#include "pci_device.hpp"

#include <cstring>

int PCIDevice::write_cfg(int offset, int size, const uint32_t* val) {
  memcpy(&config_data[offset], val, size);
}
int PCIDevice::read_cfg(int offset, int size, uint32_t* val) {
  memcpy(val, &config_data[offset], size);
}