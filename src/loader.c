#include "loader.h"
#include "api.h"
#include "kernel.h"
#include "utils.h"
#include <elf.h>

DATA loader_ctx_t loader_ctx;

int init_loader(char *elfldr_ptr, size_t size) {
  if (elfldr_ptr == 0) {
    notify("Empty elfldr !!");
    return -1;
  }

  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)elfldr_ptr;
  Elf64_Phdr *phdr = (Elf64_Phdr *)(elfldr_ptr + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr *)(elfldr_ptr + ehdr->e_shoff);

  if (size < sizeof(Elf64_Ehdr) || size < sizeof(Elf64_Phdr) + ehdr->e_phoff ||
      size < sizeof(Elf64_Shdr) + ehdr->e_shoff) {
    notify("truncated ELF !!");
    return -1;
  }

  if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    notify("ELF signature mismatch !!");
    return -1;
  }

  for (int i = 0; i < ehdr->e_phnum; i++)
    if (phdr[i].p_offset + phdr[i].p_filesz > size) {
      notify("truncated ELF !!");
      return -1;
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
    notify("unsupported ELF type !!");
    return -1;
  }

  loader_ctx.base = mmap(loader_ctx.base, loader_ctx.size, prot, flags, -1, 0);
  if (loader_ctx.base == UINTPTR_MAX) {
    notify("failed to map memory with size %#x prot: %#x flags: %#x !!",
           loader_ctx.size, prot, flags);
    return -1;
  }

  // Parse program headers.
  for (int i = 0; i < ehdr->e_phnum; i++) {
    if (phdr[i].p_type == PT_LOAD) {
      if (!phdr[i].p_memsz || !phdr[i].p_filesz)
        continue;

      if (phdr[i].p_vaddr + phdr[i].p_filesz > loader_ctx.size) {
        notify("ELF segment out of bounds !!");
        munmap(loader_ctx.base, loader_ctx.size);
        return -1;
      }
      memcpy(loader_ctx.base + phdr[i].p_vaddr, elfldr_ptr + phdr[i].p_offset,
             phdr[i].p_filesz);
    }
  }

  // Apply relocations.
  for (int i = 0; i < ehdr->e_shnum; i++) {
    if (shdr[i].sh_type != SHT_RELA)
      continue;

    Elf64_Rela *rela = (Elf64_Rela *)(elfldr_ptr + shdr[i].sh_offset);
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
        notify("unable to set protection to %#x for mapped memory %#lx with "
               "size %#lx",
               prot, segment_addr, segment_size);
        munmap(loader_ctx.base, loader_ctx.size);
      }
    } else {
      if (mprotect(segment_addr, segment_size, prot) == -1) {
        notify("unable to set protection to %#x for mapped memory %#lx with "
               "size %#lx",
               prot, segment_addr, segment_size);
        munmap(loader_ctx.base, loader_ctx.size);
      }
    }
  }

  loader_ctx.entry = loader_ctx.base + ehdr->e_entry;
  return 0;
}

int init_loader_args() {
  uint8_t prot = PROT_READ | PROT_WRITE;
  int flags = MAP_ANONYMOUS | MAP_PRIVATE;

  loader_ctx.args_map = mmap(0, PAGE_SIZE, prot, flags, -1, 0);
  if (loader_ctx.args_map == UINTPTR_MAX) {
    notify("failed to map memory with size %#x prot: %#x flags: %#x !!",
           PAGE_SIZE, prot, flags);
    return -1;
  }

  int master_sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (master_sock == -1) {
    notify("failed to create master socket !!");
    return -1;
  }

  int victim_sock = socket(AF_INET6, SOCK_DGRAM, 0);
  if (victim_sock == -1) {
    notify("failed to create victim socket !!");
    return -1;
  }

  *(uint32_t *)(loader_ctx.args_map + 0x00) = 0x14;
  *(uint32_t *)(loader_ctx.args_map + 0x04) = IPPROTO_IPV6;
  *(uint32_t *)(loader_ctx.args_map + 0x08) = IPV6_TCLASS;

  if (setsockopt(master_sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS,
                 loader_ctx.args_map, 0x18) == -1) {
    notify("failed to set socket option IPV6_2292PKTOPTIONS !!");
    return -1;
  }

  memset(loader_ctx.args_map, 0, 0x14);

  if (setsockopt(victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, loader_ctx.args_map,
                 0x14) == -1) {
    notify("failed to set socket option IPV6_PKTINFO !!");
    return -1;
  }

  fhold(fget(master_sock));
  fhold(fget(victim_sock));

  uintptr_t master_in6p_outputopts = get_in6p_outputopts(master_sock);
  uintptr_t slave_in6p_outputopts = get_in6p_outputopts(victim_sock);

  uintptr_t slave_ip6po_pktinfo = slave_in6p_outputopts + 0x10;

  // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
  kwrite(master_in6p_outputopts + 0x10, &slave_ip6po_pktinfo,
         sizeof(slave_ip6po_pktinfo));

  uint32_t tclass = 0x13370000;

  // pktopts.ip6po_tclass = 0x13370000
  kwrite(master_in6p_outputopts + 0xc0, &tclass, sizeof(tclass));

  int pipe_fd[2];

  if (pipe2(pipe_fd, 0) == -1) {
    notify("unable to pipe2 !!");
    return -1;
  }

  int *rwpipe = loader_ctx.args_map + 0x100;
  int *rwpair = loader_ctx.args_map + 0x200;
  uint64_t *ret_addr = loader_ctx.args_map + 0x300;

  rwpipe[0] = pipe_fd[0];
  rwpipe[1] = pipe_fd[1];

  rwpair[0] = master_sock;
  rwpair[1] = victim_sock;

  uintptr_t rpipe_fp = fget(pipe_fd[0]);
  uintptr_t rpipe_f_data;

  kread(&rpipe_f_data, rpipe_fp, sizeof(rpipe_f_data));

  void *kernel_getpid;
  if (dlsym(LIBKERNEL_HANDLE, "getpid", &kernel_getpid) == -1) {
    notify("failed to dlsym getpid !!");
    return -1;
  }

  loader_ctx.args.syscall_wrapper = kernel_getpid;
  loader_ctx.args.rwpipe = rwpipe;
  loader_ctx.args.rwpair = rwpair;
  loader_ctx.args.pipe_f_data = rpipe_f_data;
  loader_ctx.args.kernel_text_base = kaddrs.ktext;
  loader_ctx.args.ret = ret_addr;
  loader_ctx.args.flag = 0x54455854; // 'T','E','X','T'

  notify("syscall_wrapper: %#lx\nrwpipe: [%i, %i]\nrwpair: [%i, "
         "%i]\npipe_f_data: %#lx\nkernel_text_base: %#lx\nret: %lx",
         loader_ctx.args.syscall_wrapper, rwpipe[0], rwpipe[1], rwpair[0],
         rwpair[1], loader_ctx.args.pipe_f_data,
         loader_ctx.args.kernel_text_base, loader_ctx.args.ret);
  return 0;
}

int run_loader() {
  uintptr_t pthread;
  uint32_t pthread_id;

  if (pthread_create(&pthread, 0, loader_ctx.entry, (void *)&loader_ctx.args)) {
    notify("failed to create thread !!");
    return -1;
  }

  pthread_id = *(uint32_t *)pthread;

  notify("Created elfldr thread with id %i !!", pthread_id);

  if (pthread_join(pthread, 0)) {
    notify("failed to join thread !!");
    return -1;
  }

  notify("elfldr returned %#lx !!", *(uint64_t *)loader_ctx.args.ret);

  munmap(loader_ctx.base, loader_ctx.size);

  remove_pktinfo_from_so(loader_ctx.args.rwpair[0]);

  close(loader_ctx.args.rwpair[0]);
  close(loader_ctx.args.rwpair[1]);
  close(loader_ctx.args.rwpipe[0]);
  close(loader_ctx.args.rwpipe[1]);

  munmap(loader_ctx.args_map, PAGE_SIZE);
  return 0;
}