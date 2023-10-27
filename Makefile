CCXFLAGS:= -O0 -std=c++20
CCX:= g++-10
CC:= gcc
CCFLAGS:= -std=c11
LIBS:= -lcurses -lpcap

.PHONY: all clean dhcp-stats run

default: dhcp-stats

dhcp-stats: dhcp-stats.o argparse.o main.o
	$(CCX) $(CCXFLAGS) -o $@ $^ $(LIBS)
clean:
	rm -f *.o dhcp-stats

%.o: %.cpp %.h
	$(CCX) $(CCXFLAGS) -c $<

run: dhcp-stats
	./dhcp-stats -r /mnt/e/Downloads/dhcp-ack-random-vlan.pcapng 192.168.1.0/24 172.16.32.0/24 192.168.0.0/22 192.168.1.0/26 192.168.1.0/27
