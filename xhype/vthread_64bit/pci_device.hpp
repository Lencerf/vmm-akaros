#ifndef __PCI_DEVICE_HPP__
#define __PCI_DEVICE_HPP__

#include <cstdint>
#include <cstring>

#include "pcireg.h"

struct pci_cfg {
  uint16_t vendor;
  uint16_t device_id;
  uint16_t command;
  uint16_t status;
  uint8_t revision;
  uint8_t prog_if;
  uint8_t subclass;
  uint8_t class_code;
  uint8_t cache_line_size;
  uint8_t latency_timer;
  uint8_t header_type;
  uint8_t bist;
  uint32_t base_address[6];
};

class PCIDevice {
 protected:
  uint8_t config_data[256];
  PCIDevice() { bzero(config_data, 256); };

 public:
  virtual ~PCIDevice(){};

  virtual int write_cfg(int offset, int size, const uint32_t* val);
  virtual int read_cfg(int offset, int size, uint32_t* val);
};

#endif