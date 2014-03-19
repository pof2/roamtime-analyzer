CC ?= "gcc"

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration

OBJS = roamtime.o
LIBS = $(shell pcap-config --libs)

ALL = roamtime

test:	$(OBJS)
	$(Q)$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o roamtime
clean:
	$(Q)rm -f iw *.o *~ *.gz version.c *-stamp
