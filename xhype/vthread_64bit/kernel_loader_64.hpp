#include "vmm.hpp"

int load_linux64(struct guest_thread* gth, char const* kernel_path,
                 char const* initrd_path, char const* cmd_line,
                 uint64_t highmem_size);