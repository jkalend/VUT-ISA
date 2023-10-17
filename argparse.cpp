#include "argparse.h"

ArgParse::ArgParse(int argc, char **argv) {
	for (int i = 1; i < argc; i++) {
		if (std::regex_match(argv[i], std::regex("^-i$"))) {
			interface = argv[++i];
		}
		else if (std::regex_match(argv[i], std::regex("^-r$"))) {
			filename = argv[++i];
		}
		else if (std::regex_match(argv[i], std::regex("^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\\/([1-9]|[12][0-9]|3[0-2])$"))) {
			ips.emplace_back(argv[i]);
		}
		else {
			std::cerr << "ERROR: invalid arguments" << std::endl;
			exit(EXIT_FAILURE);
		}
	}
	if (ips.empty()) {
		std::cerr << "ERROR: no IP address specified" << std::endl;
		exit(EXIT_FAILURE);
	}
	if (interface.empty() && filename.empty()) {
		std::cerr << "ERROR: no interface or filename specified" << std::endl;
		exit(EXIT_FAILURE);
	}
}

std::string ArgParse::get_interface() {
	return interface;
}

std::string ArgParse::get_filename() {
	return filename;
}

std::vector<std::string> ArgParse::get_ips() {
	return ips;
}
