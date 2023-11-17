#include "dhcp-stats.h"
#include <csignal>

std::unique_ptr<DHCPStats> dhcp_stats;

void signal_handler(int) {
	closelog();
	endwin();
	exit(EXIT_SUCCESS);
}

int main(int argc , char **argv) {
	openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	std::signal(SIGINT, signal_handler);
	std::signal(SIGTERM, signal_handler);
	std::signal(SIGKILL, signal_handler);

	dhcp_stats = std::make_unique<DHCPStats> (argc, argv);
	if (dhcp_stats->filename_is_set()) {
		dhcp_stats->read_file();
	} else {
		dhcp_stats->sniffer();
	}

	return 0;
}
