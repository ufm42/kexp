#include "api.h"
#include "iommu.h"
#include "kernel.h"
#include "loader.h"
#include "logger.h"

__attribute__((section(".entry"))) int main(kexp_args_t *args) {
  if (args == 0)
    return -1;

  init_libkernel_api();
  init_libc_api();

  if (logger_init() != 0) {
    notify("unable to init logger !!");
    return -1;
  }

  log("payload_args { master_pipe: [%i, %i] victim_pipe: [%i, %i] allproc: "
      "%#lx elfldr { ptr: "
      "%#lx size: %#lx } }",
      args->master_pipe[0], args->master_pipe[1], args->victim_pipe[0],
      args->victim_pipe[1], args->allproc, args->elfldr_ptr, args->elfldr_size);

  init_karw(args);
  init_kaddrs(args->allproc);

  if (patch_qa_flags() != 0) {
    notify("unable to patch qa flags !!");
    return -1;
  }

  if (init_loader(args->elfldr_ptr, args->elfldr_size) != 0) {
    notify("unable to init elfldr !!");
    return -1;
  }

  if (run_loader() != 0) {
    notify("unable to run elfldr !!");
    return -1;
  }

  return 0;
}
