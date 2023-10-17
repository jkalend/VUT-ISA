#ifndef VUT_ISA_ARGPARSE_H
#define VUT_ISA_ARGPARSE_H

#include <string>
#include <vector>
#include <getopt.h>
#include <regex>
#include <iostream>
#include <syslog.h>

class ArgParse {
private:
	std::string interface;
	std::string filename;
	std::vector<std::string> ips;
public:
	ArgParse(int argc, char **argv);
	~ArgParse() = default;

	/// Get the interface
	/// \return The interface
	std::string get_interface();

	/// Get the filename
	/// \return The filename
	std::string get_filename();

	/// Get the IP addresses
	/// \return The IP addresses
	std::vector<std::string> get_ips();
};

#endif //VUT_ISA_ARGPARSE_H
