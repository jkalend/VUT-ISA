#ifndef VUT_ISA_DHCP_STATS_H
#define VUT_ISA_DHCP_STATS_H

#include "argparse.h"
#include <ncurses.h>
#include <pcap/pcap.h>
#include <map>
#include <cmath>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ETHERNET_HEADER_LEN 14
#define IP_HEADER_LEN(data) ((data[ETHERNET_HEADER_LEN] & 0x0F) * 4)
#define UDP_HEADER_LEN 8
#define DHCP_HEADER_LEN 236
#define DHCP_MAGIC_COOKIE 0x63825363
#define DHCP_OPTION_OFFSET(data) (data + ETHERNET_HEADER_LEN+IP_HEADER_LEN(data)+UDP_HEADER_LEN+DHCP_HEADER_LEN+sizeof(DHCP_MAGIC_COOKIE))


struct DHCPHeader {
	uint8_t op;
	uint8_t htype;
	uint8_t hlen;
	uint8_t hops;
	uint32_t xid;
	uint16_t secs;
	uint16_t flags;
	uint32_t ciaddr;
	uint32_t yiaddr;
	uint32_t siaddr;
	uint32_t giaddr;
	uint8_t chaddr[16];
	uint8_t sname[64];
	uint8_t file[128];
	uint32_t magic_cookie;
//	u_char *options;
};


class DHCPStats {
private:
	std::vector<std::map<std::string, int>> ips;


public:
	DHCPStats(int argc, char **argv);
	~DHCPStats() = default;
	std::string interface;

	std::string filename;

	/// Calculate subnet capacity
	/// \param subnet The subnet
	/// \return The capacity
	static int calculate_subnet_capacity(const std::string& subnet);

	void print_stats();

	void update_stats(uint32_t ip);

	int sniffer(const std::string dev);

	uint32_t parse_packet(const u_char *packet);

	int parse_options(const u_char *packet);
};

#endif //VUT_ISA_DHCP_STATS_H
