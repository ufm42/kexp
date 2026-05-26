#ifndef TYPES_H
#define TYPES_H

#include <stdarg.h>
#include <stdint.h>
#include <sys/types.h>

#define PACKED __attribute__((packed))
#define COMMON __attribute__((common))
#define DATA __attribute__((section(".data")))
#define ENTRY __attribute__((section(".entry")))
#define ALIGN_UP(addr, align) (addr + (align - 1)) & ~(align - 1)
#define ALIGN_DOWN(addr, align) addr & ~(align - 1)

#define O_WRONLY 1

#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 28
#define SOCK_STREAM 1
#define SOCK_DGRAM 2

#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_IPV6 41

#define IPV6_2292PKTOPTIONS 25
#define IPV6_PKTINFO 46
#define IPV6_NEXTHOP 48
#define IPV6_RTHDR 51
#define IPV6_TCLASS 61

typedef int32_t SceKernelModule;
typedef int32_t socklen_t;

typedef struct {
  int32_t type;
  int32_t reqId;
  int32_t priority;
  int32_t msg_id;
  int32_t target_id;
  int32_t user_id;
  int32_t unk1;
  int32_t unk2;
  int32_t app_id;
  int32_t error_num;
  int32_t unk3;
  unsigned char use_icon_image_uri;
  char message[0x400];
  char icon_uri[0x400];
  char unk[0x400];
} NotificationRequest;

typedef struct {
  int master_pipe[2];
  int victim_pipe[2];
  uintptr_t allproc;
  const char *elfldr_ptr;
  size_t elfldr_size;
} payload_args_t;

typedef struct {
  uint32_t cnt;
  uint32_t in;
  uint32_t out;
  uint32_t size;
  char *buffer;
} pipebuf_t;

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
} kaddrs_t;

#endif