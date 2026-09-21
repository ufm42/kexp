#include "api.h"

#define API(ret, name, args) ret(*name) args = 0;
#include "libc-imports.h"
#include "libkernel-imports.h"
#undef API

static inline void resolve_symbol(SceKernelModule handle, const char *name,
                                  void **addr) {
  if (dlsym(handle, name, addr)) {
    __builtin_trap();
  }
}

void init_libkernel_api() {
#define API(ret, name, args)                                                   \
  resolve_symbol(LIBKERNEL_HANDLE, #name, (void **)&name);

#include "libkernel-imports.h"

#undef API
}

void init_libc_api() {
#define API(ret, name, args) resolve_symbol(LIBC_HANDLE, #name, (void **)&name);

#include "libc-imports.h"

#undef API
}