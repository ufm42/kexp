#ifndef LOADER_H
#define LOADER_H

#include "types.h"

#define PF_X 1
#define PF_W 2
#define PF_R 4
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define ET_EXEC 2
#define ET_DYN 3
#define MAP_PRIVATE 2
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x1000
#define PT_LOAD 1
#define SHT_RELA 4
#define MADV_DONTNEED 5
#define R_X86_64_RELATIVE 8

#define PFLAGS(x)                                                              \
  (((x & PF_R) ? PROT_READ : 0) | ((x & PF_W) ? PROT_WRITE : 0) |              \
   ((x & PF_X) ? PROT_EXEC : 0))

typedef struct {
  uintptr_t syscall_wrapper;
  int *rwpipe;
  int *rwpair;
  uintptr_t pipe_f_data;
  uintptr_t kernel_data_base;
  int* payloadout;
} elfldr_args_t;

typedef int entry_t(elfldr_args_t *args);

typedef struct {
  size_t size;
  uintptr_t base;
  entry_t *entry;
} loader_ctx_t;

loader_ctx_t loader_ctx;

int init_loader(char *elfldr_ptr, size_t size);
int run_loader();

#endif