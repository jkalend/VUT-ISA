CCXFLAGS:= -O0 -std=c++20 -Wall -Wextra -pedantic -Werror -g
CCX:= g++
CC:= gcc
CCFLAGS:= -std=c11
LIBS:= -lcurses -lpcap

.PHONY: all clean dhcp-stats run

default: dhcp-stats

dhcp-stats: dhcp-stats.o argparse.o main.o subnet.o
	$(CCX) $(CCXFLAGS) -o $@ $^ $(LIBS)
clean:
	rm -f *.o dhcp-stats

%.o: %.cpp %.h
	$(CCX) $(CCXFLAGS) -c $<

pack:
	zip xkalen07.zip *.cpp *.h Makefile README.md manual.pdf dhcp-stats.1

run: dhcp-stats
	./dhcp-stats $(ARGS) 192.168.1.0/24 172.16.32.0/24 192.168.0.0/22 192.168.1.0/26 192.168.1.0/27

lo: dhcp-stats
	sudo ./dhcp-stats -i lo 192.168.1.0/24 172.16.32.0/24 192.168.0.0/22 192.168.1.0/26 192.168.1.0/27 192.168.1.0/27

example: dhcp-stats
	./dhcp-stats -r dhcp.pcap 192.168.1.0/24 172.16.32.0/24 192.168.0.0/22
