.PHONY: clean cleanall cooked normal all

all: cooked normal

CSRCS = net_speeder.c
CFLAGS = -O2 -Wall -W -Wformat=2 -Werror
LDFLAGS = -lpcap -lnet 

cooked: net_speeder_cooked

normal: net_speeder

net_speeder_cooked: $(CSRCS)
	$(CC) $(CFLAGS) -DCOOKED -o $@ $^ $(LDFLAGS)

net_speeder: $(CSRCS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean: cleanall

cleanall:
	$(RM) -f net_speeder net_speeder_cooked
