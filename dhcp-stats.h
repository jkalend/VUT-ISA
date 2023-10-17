#ifndef VUT_ISA_DHCP_STATS_H
#define VUT_ISA_DHCP_STATS_H

#include "argparse.h"
#include <ncurses.h>
#include <pcap/pcap.h>
#include <map>
#include <cmath>


class DHCPStats {
private:
	std::vector<std::map<std::string, int>> ips;
	std::string interface;
	std::string filename;

public:
	DHCPStats(int argc, char **argv);
	~DHCPStats() = default;

	/// Calculate subnet capacity
	/// \param subnet The subnet
	/// \return The capacity
	static int calculate_subnet_capacity(const std::string& subnet);

	void print_stats();

	int sniffer();
};

#endif //VUT_ISA_DHCP_STATS_H
