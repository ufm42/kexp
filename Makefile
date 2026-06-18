CC := clang-18
BIN := kexp.bin
SRC_DIR := src
BUILD_DIR := build

KEXP_NO_PTHREADS ?= 0
CFLAGS := -O3 -Iinclude \
		-fPIE -fcommon -fno-omit-frame-pointer -fno-zero-initialized-in-bss \
		-ffreestanding -nostdlib -nostartfiles \
	    -Wall -Wextra -Werror -Wno-int-conversion \
		-DKEXP_NO_PTHREADS=$(KEXP_NO_PTHREADS)

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS)) $(BUILD_DIR)/syscalls.o

.PHONY: all clean

all: $(BUILD_DIR)/$(BIN)

_ := $(shell mkdir -p $(BUILD_DIR))

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.S
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/$(BIN): $(OBJS) script.ld
	$(CC) $(CFLAGS) -Tscript.ld $(OBJS) -o $@

clean:
	rm -rf $(BUILD_DIR)