#include "dhcp-stats.h"
#include <iomanip>
#include <thread>

void error(const std::string& error) {
	std::cerr << error << std::endl;
	closelog();
	exit(EXIT_FAILURE);
}

DHCPStats::DHCPStats(int argc, char **argv) {
	const ArgParse argparse(argc, argv);
	interface = argparse.get_interface();
	filename = argparse.get_filename();
	for (auto const &ip : argparse.get_ips()) {
		for (auto const &subnet : ips) {
			if ((std::string(inet_ntoa((in_addr)subnet.ip)) + "/" + std::to_string(subnet.prefix)) == ip) {
				std::cerr << "WARNING: IP address " << ip << " is duplicated" << std::endl;
				goto skip;
			}
		}
		ips.emplace_back(ip);
		skip:{}
	}

	lines = static_cast<int>(ips.size());
	std::ranges::sort(ips.begin(), ips.end(), [](const Subnet &a, const Subnet &b) {
		return a.capacity > b.capacity;
	});
}

DHCPStats::~DHCPStats() {
	if (handle != nullptr) pcap_close(handle);

	printf("IP-Prefix\tMax-hosts\tAllocated addresses\tUtilization\n");
	for (auto &subnet : ips) {
		char *ipaddr = inet_ntoa(static_cast<in_addr>(subnet.ip));
		printf("%s/%u\t%u\t\t%u\t\t\t%0.2f%%\n",
			   ipaddr,
			   subnet.prefix,
			   subnet.capacity,
			   subnet.get_subnet_used_count(),
			   subnet.calculate_subnet_fullness()
			   );
		subnet.changed = false;
	}
	for (const auto &ip : ips) {
		if (ip.warned == true) {
			std::cout << "prefix " << inet_ntoa((in_addr)ip.ip) << "/" << ip.prefix
				<< " exceeded 50% of allocations" << std::endl;
		}
	}
}

void DHCPStats::update_stats() {
	for (auto &subnet : ips) {
		for (auto &ip : added_ips) {
			if ((subnet.ip & subnet.subnet_mask) == (ip & subnet.subnet_mask)) {

				if (ip == subnet.first_ip || ip == subnet.last_ip) {
					continue;
				}
				if (subnet.address_map.find(ip) != subnet.address_map.end()) {
					continue;
				}
				subnet.address_map.emplace(ip, true);

				subnet.changed = true;
				if ((subnet.calculate_subnet_fullness() > 50) && (subnet.warned == false)) {
					syslog(LOG_WARNING,
						   "prefix %s/%d exceeded 50%% of allocations",
						   inet_ntoa(static_cast<in_addr>(subnet.ip)),
						   subnet.prefix
						   );

					if (!filename_is_set()) {
						move(lines+2, 0);
						refresh();
						std::cout << "prefix " << inet_ntoa(static_cast<in_addr>(subnet.ip)) << "/" << subnet.prefix << " exceeded 50% of allocations" << std::endl;
						lines++;
						refresh();
						std::this_thread::sleep_for(std::chrono::milliseconds(100));
					}
					subnet.warned = true;
				}
			}
		}
	}
}

void DHCPStats::print_stats() {
	int line = 1;
	for (auto &subnet : ips) {
		if (subnet.changed == false) {
			line++;
			continue;
		}

		if (filename_is_set()) {
			std::cout << inet_ntoa(static_cast<in_addr>(subnet.ip)) << "/" << subnet.prefix
				<< " " << subnet.capacity << " " << subnet.get_subnet_used_count()
				<< " " << std::setprecision(2) << subnet.calculate_subnet_fullness() << "%" << std::endl;
			subnet.changed = false;
			line++;
		} else {
			move(line, 0);
			clrtoeol();
			printw("%s/%u\t%u\t\t%u\t\t\t%0.2f%%\n",
				   inet_ntoa(static_cast<in_addr>(subnet.ip)),
				   subnet.prefix,
				   subnet.capacity,
				   subnet.get_subnet_used_count(),
				   subnet.calculate_subnet_fullness()
				   );
			subnet.changed = false;
			line++;
			refresh();
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
	}
}

uint32_t DHCPStats::parse_packet(const u_char *packet) {
	added_ips.clear();
	auto *ip_header = (struct ip *) (packet+ETHERNET_HEADER_LEN + VLAN_HEADER_LEN(packet));
	if (ntohs(ip_header->ip_len) < DHCP_HEADER_LEN) {
		return 0;
	}
	auto *dhcp_header = (struct DHCPHeader *) (packet+ETHERNET_HEADER_LEN+IP_HEADER_LEN(packet)+UDP_HEADER_LEN);

	if (dhcp_header->op != 2) {
		return 0;
	}
	auto *payload = DHCP_OPTION_OFFSET(packet);
	int overload = 0;
	const int option_length = static_cast<int>(ntohs(ip_header->ip_len)) - ( payload - packet ) + ETHERNET_HEADER_LEN;

	if (ntohl(dhcp_header->magic_cookie) != DHCP_MAGIC_COOKIE) {
		return 0;
	}

	int type = parse_options(payload, &overload, option_length);
	if (overload != 0) {
		if (overload == 1) {
			type = parse_options(dhcp_header->file, &overload, sizeof(dhcp_header->file));
		} else if (overload == 2) {
			type = parse_options(dhcp_header->sname, &overload, sizeof(dhcp_header->sname));
		} else if (overload == 3) {
			type = parse_options(dhcp_header->file, &overload, sizeof(dhcp_header->file));
			if (type == 0) {
				type = parse_options(dhcp_header->sname, &overload,	sizeof(dhcp_header->sname));
			}
		}
	}
	if(type == 5) {
		added_ips.push_back(dhcp_header->yiaddr);
		return dhcp_header->yiaddr;
	}
	if (type == 3) {
		return type;
	}
	return 0;
}

int DHCPStats::parse_options(const u_char *packet, int *overload, int length) {
	int return_code = 0;
	int i = 0;
	while (packet[i] != 0xff && i < length) {
		if (packet[i] == 0x35) {
			return_code = static_cast<int>(packet[i + 2]);
			i += static_cast<int>(packet[++i]);
		} else if (packet[i] == 0x34) {
			*overload = static_cast<int>(packet[i + 2]);
			i += static_cast<int>(packet[++i]);
		} else if (packet[i] == 0x06 || packet[i] == 0x03 || packet[i] == 0x36) {
			u_char length = packet[i + 1];
			i += 2;
			for (uint32_t j = i; j < i + length; j += 4) {
				uint32_t ip = *((uint32_t*) (packet + j));
				added_ips.push_back(ip);
			}
			i += length;
			continue;
		} else if (packet[i] != 0x00) {
			i += static_cast<int>(packet[++i]);
		}
		i++;
	}
	return return_code;
}

int DHCPStats::sniffer() {
	struct bpf_program fp;
	char filter_exp[] = "port 68 or port 67";
	bpf_u_int32 mask, net;
	struct pcap_pkthdr header;

	pcap_if_t *alldevsp;
	pcap_findalldevs(&alldevsp, errbuff);
	bool found = false;
	for (const auto *device = alldevsp; device != nullptr; device = device->next) {
		if (strcmp(device->name, interface.c_str()) == 0) {
			found = true;
			break;
		}
	}
	if (!found) {
		error("Couldn't find device " + interface + ": " + std::string(errbuff));
	}
	if (interface.empty()) {
		error("Couldn't find default device: " + std::string(errbuff));
	}
	if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuff) == -1) {
		std::cerr << "Couldn't get netmask for device " << interface << ": " << std::string(errbuff) << std::endl;
		net = 0; mask = 0;
	}
	if (geteuid() != 0) {
		error("You must be root to sniff the packets");
	}
	handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuff);
	if (handle == nullptr) {
		error("Couldn't open device " + interface + ": " + std::string(errbuff));
	}
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		error("Couldn't parse filter " + std::string(filter_exp) + ": " + std::string(pcap_geterr(handle)));
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		error("Couldn't install filter " + std::string(filter_exp) + ": " + std::string(pcap_geterr(handle)));
	}
	pcap_freecode(&fp);
	pcap_freealldevs(alldevsp);

	initscr();
	printw("IP-Prefix\tMax-hosts\tAllocated addresses\tUtilization\n");
	print_stats();

	while (true) {
		const u_char *packet = pcap_next(handle, &header);
		if (const auto result = parse_packet(packet); result == 0) {
			print_stats();
		} else {
			update_stats();
			print_stats();
		}
	}
}

int DHCPStats::read_file() {
    handle = pcap_open_offline(filename.c_str(), errbuff);
	if (handle == nullptr) {
		error("Couldn't open file " + filename + ": " + std::string(errbuff));
	}

    struct pcap_pkthdr *header;
    const u_char *data;

	int returnValue = 0;
    while ((returnValue = pcap_next_ex(handle, &header, &data)) >= 0) {
		if (parse_packet(data) == 0) {
			continue;
		}
    	//parse_packet(data);
		update_stats();
    }
	if (returnValue == -1) {
		error("Error reading the packets: " + std::string(pcap_geterr(handle)));
	}
	return 0;
}

[[nodiscard]]
bool DHCPStats::filename_is_set() const {
	return !filename.empty();
}
