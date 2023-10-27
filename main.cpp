#include "dhcp-stats.h"
#include <csignal>

void sigint_handler(int) {
	closelog();
	endwin();
	exit(EXIT_SUCCESS);
}

int main(int argc , char **argv) {
	initscr();
	openlog("dhcp-stats", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	std::signal(SIGINT, sigint_handler);

	DHCPStats dhcp_stats(argc, argv);
	printw("IP-Prefix Max-hosts Allocated addresses Utilization\n");
	if (!dhcp_stats.filename_is_set()) {
		dhcp_stats.read_file();
	} else {
		dhcp_stats.sniffer();
	}

	endwin();
	closelog();
}
