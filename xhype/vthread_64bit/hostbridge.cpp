#include "hostbridge.hpp"

HostBridge::HostBridge() {
  struct pci_cfg* cfg = (struct pci_cfg*)&config_data;
  cfg->vendor = 0x1275;
  cfg->device_id = 0x1275;
  cfg->header_type = PCIM_HDRTYPE_NORMAL;
  cfg->class_code = PCIC_BRIDGE;
  cfg->subclass = PCIS_BRIDGE_HOST;

  // FIXME: from xhyve, I do not understand
  // pci_emul_add_pciecap(pi, PCIEM_TYPE_ROOT_PORT);
}