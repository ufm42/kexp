.intel_syntax noprefix

.text
.global syscall
syscall:
  mov r10, rcx
  syscall
  jb fail
  ret

fail:
  mov rax, -1
  mov rdx, -1
  ret

#define API(id, ret, name, args) \
.global name;                    \
name:;                           \
    mov rax, id;                 \
    jmp syscall;

#include "syscalls-imports.h"

#undef API