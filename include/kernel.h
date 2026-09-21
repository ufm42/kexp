#ifndef KERNEL_H
#define KERNEL_H

#include "types.h"

#define KERNEL_PID 0
#define PAGE_SIZE 0x4000
#define FILEDESCENT_SIZE 0x30

#define CPU_PDE_PRESENT_SHIFT 0
#define CPU_PDE_PRESENT_MASK 1
#define CPU_PDE_PS_SHIFT 7
#define CPU_PDE_PS_MASK 1
#define CPU_PG_PHYS_FRAME 0x000ffffffffff000
#define CPU_PG_PS_FRAME 0x000fffffffe00000
#define CPU_PDE_FIELD(pde, field)                                              \
  ((pde >> CPU_PDE_##field##_SHIFT) & CPU_PDE_##field##_MASK)

typedef struct {
  int master_pipe[2];
  int victim_pipe[2];
  pipebuf_t pipebuf;
} karw_ctx_t;

typedef struct {
  uintptr_t cb3;
  uintptr_t cr3;
  uintptr_t mmio;
  uintptr_t dmap;
  uintptr_t kmdp;
  uintptr_t ktext;
  uintptr_t ksize;
  uintptr_t kdata;
  uintptr_t kaslr;
  uintptr_t softc;
  uintptr_t krodata;
  uintptr_t allproc;
  uintptr_t fdt_ofiles;
} kaddrs_t;

kaddrs_t kaddrs;
karw_ctx_t karw_ctx;

void init_karw(kexp_args_t *args);
void init_kaddrs(uintptr_t allproc);
void find_dyn_segment();
void find_hash_table();
void find_kmdp();
int flush();
ssize_t kread(void *dst, void *src, uint32_t sz);
ssize_t kwrite(void *dst, void *src, uint32_t sz);
uintptr_t pfind(pid_t pid);
uintptr_t fget(int fd);
void fhold(uintptr_t fp);
void remove_pktinfo_from_so(int fd);
uintptr_t get_in6p_outputopts(int fd);
uintptr_t get_dmap(uintptr_t paddr);
uintptr_t get_paddr(uintptr_t vaddr);
uintptr_t find_vm_pmap_ptr(uintptr_t vmspace);
uintptr_t find_openpsid_ptr();
uint32_t get_fw_version();
uintptr_t get_kernel_data_base();
uintptr_t get_vm_map_pmap(uintptr_t p);
uintptr_t get_vm_map_root(uintptr_t p);
int vm_map_set_protection(uintptr_t vaddr, size_t sz, uint8_t prot);
uintptr_t find_vm_map_entry(uintptr_t vaddr);
int patch_qa_flags();
#endif