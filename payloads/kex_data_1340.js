// kex_data_1340.js — kernel data offsets for 13.40 (user-provided, kex stage).
// Not used by webkit bridge; consumed by kex payloads after syscalls work.
const KDATA_1340 = {
  OFFSET_KERNEL_DATA: 0x00CB0000,
  OFFSET_KERNEL_ALLPROC: 0x03589E80,
  OFFSET_KERNEL_SECURITY_FLAGS: 0x01A49064,
  OFFSET_KERNEL_ROOTVNODE: 0x03DE7510,
  OFFSET_KERNEL_BUS_DATA_DEVICES: 0x02D481E8,
};
try { globalThis.KDATA_1340 = KDATA_1340; } catch(e){}
