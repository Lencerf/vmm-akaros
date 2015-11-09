#recursive make considered harmful. 
#http://www.tip.net.au/~millerp/rmch/recu-make-cons-harm.html
# For a crazy complex way to do it:
#http://evbergen.home.xs4all.nl/nonrecursive-make.html
#

# Rules: keep this simple. Make sure the gcc is in your path and nobody gets hurt.

### Build flags for all targets
#
CFLAGS          = -O2 -std=gnu99 -fno-stack-protector -fgnu89-inline -Wsystem-headers -fPIC -static -fno-omit-frame-pointer -g -Iinclude
LDFLAGS          =
LDLIBS         = -lpthread -lbenchutil -lm -liplib -lndblib

### Build tools
# 
CC=x86_64-ucb-akaros-gcc
AR=x86_64-ucb-akaros-ar

all: vmm

# compilers are fast. Just rebuild it each time.
vmm: 
	$(CC) $(CFLAGS) $(LDFLAGS) -o vmm vmm.c lib/*.c $(LDLIBS)