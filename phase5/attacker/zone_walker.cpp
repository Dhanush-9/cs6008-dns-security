#define _DEFAULT_SOURCE 1

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>

namespace {

constexpr uint16_t DNS_PORT = 53;
constexpr uint16_t TYPE_NSEC = 47;
constexpr uint16_t TYPE_NSEC3 = 50;
constexpr uint16_t TYPE_OPT = 41;
constexpr size_t DNS_HEADER_SIZE = 12;

struct Config {
    std::string iface = "eth0";
    std::string server = "172.16.3.30";
    std::string zone = "example.com.";
    uint8_t next_hop_mac[6]{};
    bool have_next_hop_mac = false;
};

struct InterfaceInfo {
    uint8_t mac[6]{};
    in_addr address{};
};

struct QueryResult {
    bool has_nsec3 = false;
    std::optional<std::string> next_name;
    uint8_t rcode = 0;
};

uint16_t read_u16(const uint8_t *data) {
    uint16_t value;
    std::memcpy(&value, data, sizeof(value));
    return ntohs(value);
}

void append_u16(std::vector<uint8_t> &buffer, uint16_t value) {
    uint16_t network_value = htons(value);
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&network_value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(network_value));
}

void append_u32(std::vector<uint8_t> &buffer, uint32_t value) {
    uint32_t network_value = htonl(value);
    const uint8_t *bytes = reinterpret_cast<const uint8_t *>(&network_value);
    buffer.insert(buffer.end(), bytes, bytes + sizeof(network_value));
}

std::string normalize_name(std::string name) {
    std::transform(name.begin(), name.end(), name.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (name.empty()) return ".";
    if (name.back() != '.') name.push_back('.');
    return name;
}

bool parse_mac(const std::string &text, uint8_t mac[6]) {
    unsigned int values[6];
    if (std::sscanf(text.c_str(), "%x:%x:%x:%x:%x:%x",
                    &values[0], &values[1], &values[2],
                    &values[3], &values[4], &values[5]) != 6) {
        return false;
    }
    for (size_t i = 0; i < 6; ++i) {
        if (values[i] > 0xff) return false;
        mac[i] = static_cast<uint8_t>(values[i]);
    }
    return true;
}

bool get_interface_info(const std::string &iface, InterfaceInfo &info) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;

    ifreq request{};
    std::strncpy(request.ifr_name, iface.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &request) < 0) {
        close(fd);
        return false;
    }
    std::memcpy(info.mac, request.ifr_hwaddr.sa_data, 6);

    std::memset(&request, 0, sizeof(request));
    std::strncpy(request.ifr_name, iface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &request) < 0) {
        close(fd);
        return false;
    }
    info.address = reinterpret_cast<sockaddr_in *>(&request.ifr_addr)->sin_addr;
    close(fd);
    return true;
}

uint16_t internet_checksum(const uint8_t *data, size_t length) {
    uint32_t sum = 0;
    size_t offset = 0;

    while (offset + 1 < length) {
        sum += static_cast<uint16_t>((data[offset] << 8) | data[offset + 1]);
        offset += 2;
    }
    if (offset < length) {
        sum += static_cast<uint16_t>(data[offset] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return htons(static_cast<uint16_t>(~sum));
}

uint16_t udp_checksum(const iphdr *ip, const udphdr *udp,
                      const uint8_t *payload, size_t payload_length) {
    std::vector<uint8_t> data;
    data.reserve(12 + sizeof(udphdr) + payload_length + 1);

    const uint8_t *source = reinterpret_cast<const uint8_t *>(&ip->saddr);
    const uint8_t *destination = reinterpret_cast<const uint8_t *>(&ip->daddr);
    data.insert(data.end(), source, source + 4);
    data.insert(data.end(), destination, destination + 4);
    data.push_back(0);
    data.push_back(IPPROTO_UDP);

    const uint8_t *udp_length = reinterpret_cast<const uint8_t *>(&udp->len);
    data.insert(data.end(), udp_length, udp_length + 2);

    udphdr copy = *udp;
    copy.check = 0;
    const uint8_t *udp_bytes = reinterpret_cast<const uint8_t *>(&copy);
    data.insert(data.end(), udp_bytes, udp_bytes + sizeof(copy));
    data.insert(data.end(), payload, payload + payload_length);

    if (data.size() % 2 != 0) data.push_back(0);
    uint16_t result = internet_checksum(data.data(), data.size());
    return result == 0 ? htons(0xffff) : result;
}

bool append_dns_name(std::vector<uint8_t> &buffer, const std::string &input) {
    std::string name = input;
    if (!name.empty() && name.back() == '.') name.pop_back();
    if (name.empty()) {
        buffer.push_back(0);
        return true;
    }

    size_t start = 0;
    while (start < name.size()) {
        size_t dot = name.find('.', start);
        size_t end = dot == std::string::npos ? name.size() : dot;
        size_t length = end - start;
        if (length == 0 || length > 63) return false;
        buffer.push_back(static_cast<uint8_t>(length));
        buffer.insert(buffer.end(), name.begin() + static_cast<std::ptrdiff_t>(start),
                      name.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    buffer.push_back(0);
    return true;
}

bool decode_dns_name(const uint8_t *message, size_t message_length, size_t offset,
                     std::string &name, size_t &consumed) {
    name.clear();
    consumed = 0;
    size_t position = offset;
    bool jumped = false;

    for (size_t steps = 0; steps < message_length; ++steps) {
        if (position >= message_length) return false;
        uint8_t length = message[position];

        if (length == 0) {
            if (!jumped) consumed += 1;
            name = normalize_name(name);
            return true;
        }

        if ((length & 0xc0) == 0xc0) {
            if (position + 1 >= message_length) return false;
            uint16_t pointer = static_cast<uint16_t>(((length & 0x3f) << 8) |
                                                     message[position + 1]);
            if (pointer >= message_length) return false;
            if (!jumped) consumed += 2;
            position = pointer;
            jumped = true;
            continue;
        }

        if ((length & 0xc0) != 0 || length > 63 ||
            position + 1 + length > message_length) {
            return false;
        }

        if (!name.empty()) name.push_back('.');
        name.append(reinterpret_cast<const char *>(message + position + 1), length);
        if (!jumped) consumed += 1 + length;
        position += 1 + length;
    }
    return false;
}

std::vector<uint8_t> build_dns_query(uint16_t txid, const std::string &name) {
    std::vector<uint8_t> dns;
    append_u16(dns, txid);
    append_u16(dns, 0x0000);  // standard query, no recursion requested
    append_u16(dns, 1);       // QDCOUNT
    append_u16(dns, 0);
    append_u16(dns, 0);
    append_u16(dns, 1);       // one OPT pseudo-record

    if (!append_dns_name(dns, name)) return {};
    append_u16(dns, TYPE_NSEC);
    append_u16(dns, 1);       // IN

    dns.push_back(0);          // OPT owner: root
    append_u16(dns, TYPE_OPT);
    append_u16(dns, 1232);    // advertised UDP payload size
    append_u32(dns, 0x00008000);  // DNSSEC OK (DO) bit
    append_u16(dns, 0);
    return dns;
}

std::vector<uint8_t> build_frame(const Config &config, const InterfaceInfo &local,
                                 uint16_t source_port, uint16_t txid,
                                 uint16_t ip_id, const std::string &name) {
    std::vector<uint8_t> dns = build_dns_query(txid, name);
    if (dns.empty()) return {};

    const size_t ip_length = sizeof(iphdr) + sizeof(udphdr) + dns.size();
    std::vector<uint8_t> frame(sizeof(ether_header) + ip_length, 0);

    auto *ethernet = reinterpret_cast<ether_header *>(frame.data());
    std::memcpy(ethernet->ether_dhost, config.next_hop_mac, 6);
    std::memcpy(ethernet->ether_shost, local.mac, 6);
    ethernet->ether_type = htons(ETHERTYPE_IP);

    auto *ip = reinterpret_cast<iphdr *>(frame.data() + sizeof(ether_header));
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->tot_len = htons(static_cast<uint16_t>(ip_length));
    ip->id = htons(ip_id);
    ip->frag_off = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = local.address.s_addr;
    if (inet_pton(AF_INET, config.server.c_str(), &ip->daddr) != 1) return {};
    ip->check = 0;
    ip->check = internet_checksum(reinterpret_cast<const uint8_t *>(ip), sizeof(iphdr));

    auto *udp = reinterpret_cast<udphdr *>(frame.data() + sizeof(ether_header) +
                                          sizeof(iphdr));
    udp->source = htons(source_port);
    udp->dest = htons(DNS_PORT);
    udp->len = htons(static_cast<uint16_t>(sizeof(udphdr) + dns.size()));
    udp->check = 0;

    uint8_t *payload = frame.data() + sizeof(ether_header) + sizeof(iphdr) +
                       sizeof(udphdr);
    std::memcpy(payload, dns.data(), dns.size());
    udp->check = udp_checksum(ip, udp, payload, dns.size());
    return frame;
}

bool parse_dns_response(const uint8_t *dns, size_t length, uint16_t expected_txid,
                        QueryResult &result) {
    if (length < DNS_HEADER_SIZE || read_u16(dns) != expected_txid) return false;

    uint16_t flags = read_u16(dns + 2);
    if ((flags & 0x8000) == 0) return false;
    result.rcode = static_cast<uint8_t>(flags & 0x000f);

    uint16_t questions = read_u16(dns + 4);
    uint32_t records = static_cast<uint32_t>(read_u16(dns + 6)) +
                       read_u16(dns + 8) + read_u16(dns + 10);
    size_t offset = DNS_HEADER_SIZE;

    for (uint16_t i = 0; i < questions; ++i) {
        std::string ignored;
        size_t consumed = 0;
        if (!decode_dns_name(dns, length, offset, ignored, consumed)) return false;
        offset += consumed;
        if (offset + 4 > length) return false;
        offset += 4;
    }

    for (uint32_t i = 0; i < records; ++i) {
        std::string owner;
        size_t owner_length = 0;
        if (!decode_dns_name(dns, length, offset, owner, owner_length)) return false;
        offset += owner_length;
        if (offset + 10 > length) return false;

        uint16_t type = read_u16(dns + offset);
        uint16_t data_length = read_u16(dns + offset + 8);
        size_t data_offset = offset + 10;
        if (data_offset + data_length > length) return false;

        if (type == TYPE_NSEC) {
            std::string next;
            size_t consumed = 0;
            if (!decode_dns_name(dns, length, data_offset, next, consumed) ||
                consumed > data_length) {
                return false;
            }
            result.next_name = normalize_name(next);
        } else if (type == TYPE_NSEC3) {
            result.has_nsec3 = true;
        }
        offset = data_offset + data_length;
    }
    return true;
}

std::optional<QueryResult> send_query_and_wait(
    pcap_t *handle, const Config &config, const InterfaceInfo &local,
    uint16_t source_port, uint16_t txid, uint16_t ip_id, const std::string &name) {
    std::vector<uint8_t> frame =
        build_frame(config, local, source_port, txid, ip_id, name);
    if (frame.empty()) {
        std::cerr << "Could not build DNS query for " << name << std::endl;
        return std::nullopt;
    }

    if (pcap_inject(handle, frame.data(), frame.size()) < 0) {
        std::cerr << "pcap_inject failed: " << pcap_geterr(handle) << std::endl;
        return std::nullopt;
    }

    in_addr server_address{};
    inet_pton(AF_INET, config.server.c_str(), &server_address);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);

    while (std::chrono::steady_clock::now() < deadline) {
        pcap_pkthdr *header = nullptr;
        const u_char *packet = nullptr;
        int status = pcap_next_ex(handle, &header, &packet);
        if (status == 0) continue;
        if (status < 0) {
            std::cerr << "pcap capture failed: " << pcap_geterr(handle) << std::endl;
            return std::nullopt;
        }
        if (header->caplen < sizeof(ether_header) + sizeof(iphdr)) continue;

        const auto *ethernet = reinterpret_cast<const ether_header *>(packet);
        if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) continue;

        const auto *ip =
            reinterpret_cast<const iphdr *>(packet + sizeof(ether_header));
        size_t ip_header_length = static_cast<size_t>(ip->ihl) * 4;
        if (ip->version != 4 || ip_header_length < sizeof(iphdr) ||
            ip->protocol != IPPROTO_UDP ||
            sizeof(ether_header) + ip_header_length + sizeof(udphdr) >
                header->caplen) {
            continue;
        }
        if (ip->saddr != server_address.s_addr ||
            ip->daddr != local.address.s_addr) {
            continue;
        }

        const auto *udp = reinterpret_cast<const udphdr *>(
            packet + sizeof(ether_header) + ip_header_length);
        if (ntohs(udp->source) != DNS_PORT || ntohs(udp->dest) != source_port)
            continue;

        uint16_t udp_length = ntohs(udp->len);
        if (udp_length < sizeof(udphdr)) continue;
        size_t dns_length = udp_length - sizeof(udphdr);
        size_t dns_offset =
            sizeof(ether_header) + ip_header_length + sizeof(udphdr);
        if (dns_offset + dns_length > header->caplen) continue;

        QueryResult result;
        if (parse_dns_response(packet + dns_offset, dns_length, txid, result)) {
            return result;
        }
    }

    std::cerr << "Timed out waiting for " << name << " NSEC response." << std::endl;
    return std::nullopt;
}

void print_usage(const char *program) {
    std::cerr << "Usage: " << program
              << " --next-hop-mac MAC [--iface eth0]"
                 " [--server 172.16.3.30] [--zone example.com.]"
              << std::endl;
}

}  // namespace

int main(int argc, char **argv) {
    Config config;
    for (int i = 1; i < argc; ++i) {
        std::string argument = argv[i];
        if (argument == "--iface" && i + 1 < argc) {
            config.iface = argv[++i];
        } else if (argument == "--server" && i + 1 < argc) {
            config.server = argv[++i];
        } else if (argument == "--zone" && i + 1 < argc) {
            config.zone = normalize_name(argv[++i]);
        } else if (argument == "--next-hop-mac" && i + 1 < argc) {
            config.have_next_hop_mac =
                parse_mac(argv[++i], config.next_hop_mac);
        } else {
            print_usage(argv[0]);
            return 2;
        }
    }

    if (!config.have_next_hop_mac) {
        print_usage(argv[0]);
        return 2;
    }

    InterfaceInfo local;
    if (!get_interface_info(config.iface, local)) {
        std::cerr << "Could not read address information for " << config.iface
                  << std::endl;
        return 1;
    }

    char local_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &local.address, local_ip, sizeof(local_ip));

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle =
        pcap_open_live(config.iface.c_str(), 65535, 1, 100, error_buffer);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << error_buffer << std::endl;
        return 1;
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "The walker requires an Ethernet capture interface."
                  << std::endl;
        pcap_close(handle);
        return 1;
    }

    std::string filter = "udp and src host " + config.server +
                         " and src port 53 and dst host " + local_ip;
    bpf_program compiled_filter{};
    if (pcap_compile(handle, &compiled_filter, filter.c_str(), 1,
                     PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "Could not compile capture filter: " << pcap_geterr(handle)
                  << std::endl;
        pcap_close(handle);
        return 1;
    }
    if (pcap_setfilter(handle, &compiled_filter) < 0) {
        std::cerr << "Could not install capture filter: " << pcap_geterr(handle)
                  << std::endl;
        pcap_freecode(&compiled_filter);
        pcap_close(handle);
        return 1;
    }
    pcap_freecode(&compiled_filter);

    std::mt19937 random(std::random_device{}());
    std::uniform_int_distribution<uint16_t> transaction_ids(1, 65535);
    std::uniform_int_distribution<uint16_t> source_ports(32768, 60999);

    std::string current = normalize_name(config.zone);
    std::set<std::string> known{current};
    std::vector<std::string> recovered;
    unsigned int query_count = 0;

    std::cout << "=== Phase 5 libpcap zone walker ===" << std::endl;
    std::cout << "Known starting name: " << current << std::endl;
    std::cout << "Authoritative server: " << config.server << std::endl;
    std::cout << "Method: follow NSEC next-name links; no AXFR or wordlist"
              << std::endl;

    bool completed = false;
    for (unsigned int step = 0; step < 256; ++step) {
        uint16_t txid = transaction_ids(random);
        uint16_t port = source_ports(random);
        ++query_count;
        std::cout << "[" << query_count << "] Query NSEC for " << current
                  << std::endl;

        std::optional<QueryResult> response = send_query_and_wait(
            handle, config, local, port, txid, transaction_ids(random), current);
        if (!response) {
            pcap_close(handle);
            return 1;
        }

        if (response->has_nsec3) {
            std::cout << "    Received NSEC3: the next owner is hashed, not a"
                         " plaintext name."
                      << std::endl;
            std::cout << "Walk blocked." << std::endl;
            std::cout << "Queries sent: " << query_count << std::endl;
            std::cout << "Recovered names: 0" << std::endl;
            pcap_close(handle);
            return 0;
        }

        if (!response->next_name) {
            std::cerr << "Response contained neither NSEC nor NSEC3."
                      << " RCODE=" << static_cast<unsigned int>(response->rcode)
                      << std::endl;
            pcap_close(handle);
            return 1;
        }

        std::string next = normalize_name(*response->next_name);
        std::cout << "    Next existing name: " << next << std::endl;

        if (next == config.zone) {
            completed = true;
            break;
        }
        if (!known.insert(next).second) {
            std::cerr << "NSEC chain looped before returning to the zone apex."
                      << std::endl;
            pcap_close(handle);
            return 1;
        }
        recovered.push_back(next);
        current = next;
    }

    pcap_close(handle);
    if (!completed) {
        std::cerr << "NSEC walk exceeded the safety limit." << std::endl;
        return 1;
    }

    std::cout << std::endl;
    std::cout << "Walk complete." << std::endl;
    std::cout << "Recovered names: " << recovered.size() << std::endl;
    for (const std::string &name : recovered) {
        std::cout << "  " << name << std::endl;
    }
    std::cout << "Known apex: " << config.zone << std::endl;
    std::cout << "Complete owner-name count: " << known.size() << std::endl;
    std::cout << "Queries sent: " << query_count << std::endl;
    std::cout << "Assignment limit: " << known.size() + 2 << std::endl;
    std::cout << (query_count <= known.size() + 2 ? "Query limit: PASS"
                                                  : "Query limit: FAIL")
              << std::endl;
    return query_count <= known.size() + 2 ? 0 : 1;
}
