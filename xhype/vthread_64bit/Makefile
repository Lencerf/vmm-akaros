src = $(wildcard *.[c|s])
obj = $(src:.c=.o)

CC=clang
CXX=clang++
CFLAGS=-g -Wall
CXXFLAGS=-std=c++11
LDFLAGS=-framework Hypervisor 

runkernel64: runkernel64.o utils.o vmm.o kernel_loader.o kernel_loader32.o vmexit.o vmexit_msr.o vmexit_cpuid.o
	$(CXX) -o build/$@ $^ $(CFLAGS) $(LDFLAGS) 

vmrunkernel: vmrunkernel.o utils.o
	$(CXX) -o $@ $^ $(CFLAGS) $(LDFLAGS) 

vmrunkernel64: vmrunkernel64.o utils.o
	$(CXX) -o $@ $^ $(CFLAGS) $(LDFLAGS) 

libchange.dylib: change.c
	$(CC) -o $@ -dynamiclib $(CFLAGS) $^

main: main.o vthread.o utils.o identity_map.o vthread_hlt.o libchange.dylib
	$(CXX) -o $@ $^ $(CFLAGS) $(LDFLAGS) -L. -lchange

.PHONY: clean
clean:
	rm -f *.o main *.dylib