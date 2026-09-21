CC := clang-18
BIN := kexp.bin
SRC_DIR := src
BUILD_DIR := build

CFLAGS := -O3 -Iinclude \
		-fPIE -fcommon -fno-omit-frame-pointer -fno-zero-initialized-in-bss \
		-ffreestanding -nostdlib -nostartfiles \
	    -Wall -Wextra -Werror -Wno-int-conversion

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS)) $(BUILD_DIR)/syscalls.o

.PHONY: all clean

all: $(BUILD_DIR)/$(BIN)

$(BUILD_DIR):
	mkdir -p $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.S | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@
	
$(BUILD_DIR)/$(BIN): $(OBJS) script.ld
	$(CC) $(CFLAGS) -Tscript.ld $(OBJS) -o $@

clean:
	rm -rf $(BUILD_DIR)