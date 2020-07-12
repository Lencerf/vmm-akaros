#include <sys/sysctl.h>
#include <stdint.h>

uint64_t get_bus_frequency_c() {
    size_t length = sizeof(uint64_t);
    uint64_t bus_freq;
    sysctlbyname("hw.busfrequency", &bus_freq, &length, NULL, 0);
    return bus_freq;
}

uint64_t get_tsc_frequency_c() {
    size_t length = sizeof(uint64_t);
    uint64_t tsc_freq;
    sysctlbyname("machdep.tsc.frequency", &tsc_freq, &length, NULL, 0);
    return tsc_freq;
}