#include "dhcp-stats.h"
#include <pcap/pcap.h>

int DHCPStats::calculate_subnet_capacity(const std::string& subnet) {
	int capacity = 0;
	std::string subnet_mask = subnet.substr(subnet.find('/') + 1);
	if (int mask = std::stoi(subnet_mask); mask == 32) {
		capacity = 1;
	}
	else {
		capacity = static_cast<int>(pow(2, 32 - mask));
	}
	return capacity;
}

DHCPStats::DHCPStats(int argc, char **argv) {
	ArgParse argparse(argc, argv);
	interface = argparse.get_interface();
	filename = argparse.get_filename();
	for (auto const &ip : argparse.get_ips()) {
		std::map<std::string, int> ip_map;
		ip_map[ip] = 0;
		ip_map["used"] = 0;
		ip_map["capacity"] = calculate_subnet_capacity(ip);
		ips.emplace_back(ip_map);
	}
}

void DHCPStats::print_stats() {
	std::cout << "DHCP Stats" << std::endl;
	std::cout << "===========" << std::endl;
	std::cout << "Interface: " << interface << std::endl;
	std::cout << "Filename: " << filename << std::endl;
	std::cout << "IPs: " << std::endl;
	for (auto const &ip : ips) {
		std::cout << ip.begin()->first << "  " << "used" << ": " << ip.find("used")->second << "/" << ip.find("capacity")->second << std::endl;
	}
}

int DHCPStats::sniffer() {
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	pcap_if_t *alldevsp;
	pcap_findalldevs(&alldevsp, errbuf);
	dev = alldevsp[0].name;
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return 2;
	}
	printf("Device: %s\n", dev);
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return 2;
	}
	/* Grab a packet */
	packet = pcap_next(handle, &header);
	/* Print its length */
	std::cout << "Jacked a packet with length of [" << header.len << "]" << std::endl;
	/* And close the session */
	pcap_close(handle);
	return 0;
}
