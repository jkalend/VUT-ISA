#include "argparse.h"

ArgParse::ArgParse(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		if (std::regex_match(argv[i], std::regex("^-h$"))) {
			help();
			exit(EXIT_SUCCESS);
		}
	}
	for (int i = 1; i < argc; i++) {
		if (std::regex_match(argv[i], std::regex("^-i$"))) {
			if (!interface.empty()) {
				std::cerr << "ERROR: interface already specified" << std::endl;
				help();
				exit(EXIT_FAILURE);
			}
			interface = argv[++i];
		}
		else if (std::regex_match(argv[i], std::regex("^-r$"))) {
			if (!filename.empty()) {
				std::cerr << "ERROR: filename already specified" << std::endl;
				help();
				exit(EXIT_FAILURE);
			}
			filename = argv[++i];
		}
		else if (std::regex_match(argv[i], std::regex("^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\/([0-9]|[12][0-9]|3[0-2])$"))) {
			ips.emplace_back(argv[i]);
		}
		else {
			std::cerr << "ERROR: invalid arguments" << std::endl;
			help();
			exit(EXIT_FAILURE);
		}
	}
	if (ips.empty()) {
		std::cerr << "ERROR: no IP address specified" << std::endl;
		help();
		exit(EXIT_FAILURE);
	}
	if (interface.empty() && filename.empty()) {
		std::cerr << "ERROR: no interface or filename specified" << std::endl;
		help();
		exit(EXIT_FAILURE);
	}
	if (!interface.empty() && !filename.empty()) {
		std::cerr << "ERROR: no interface or filename specified" << std::endl;
		help();
		exit(EXIT_FAILURE);
	}
}

void ArgParse::help() {
	std::cout << "Usage: ./dhcp-stats [-i interface] [-r filename] IP/MASK [IP/MASK ...]" << std::endl;
	std::cout << "  - i interface to listen on" << std::endl;
	std::cout << "  - r filename to read from" << std::endl;
	std::cout << "  IP/MASK IP address and subnet mask" << std::endl;
}

std::string ArgParse::get_interface() const {
	return interface;
}

std::string ArgParse::get_filename() const {
	return filename;
}

std::vector<std::string> ArgParse::get_ips() const {
	return ips;
}
