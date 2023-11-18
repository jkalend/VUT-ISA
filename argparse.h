#ifndef VUT_ISA_ARGPARSE_H
#define VUT_ISA_ARGPARSE_H

#include <string>
#include <vector>
#include <regex>
#include <iostream>
#include <syslog.h>

class ArgParse {
	std::string interface;
	std::string filename;
	std::vector<std::string> ips;

	static void help();
public:
	ArgParse(int argc, char **argv);
	~ArgParse() = default;

	/// Get the interface
	/// \return The interface
	[[nodiscard]] std::string get_interface() const;

	/// Get the filename
	/// \return The filename
	[[nodiscard]] std::string get_filename() const;

	/// Get the IP addresses
	/// \return The IP addresses
	[[nodiscard]] std::vector<std::string> get_ips() const;
};

#endif //VUT_ISA_ARGPARSE_H
