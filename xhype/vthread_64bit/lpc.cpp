#include "lpc.hpp"

// FIX ME
#define LPC_DEV 0x7000
#define LPC_VENDOR 0x8086

LPC::LPC() {
  struct pci_cfg* cfg = (struct pci_cfg*)&config_data;
  cfg->vendor = LPC_VENDOR;
  cfg->device_id = LPC_DEV;
  cfg->class_code = PCIC_BRIDGE;
  cfg->subclass = PCIS_BRIDGE_ISA;

  // FIX ME
  // initialize lpc devices, this should be done somewhere else.
}