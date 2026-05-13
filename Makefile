# =============================================================================
# HDD-EAPDumper — PS4 payload built with ps4-payload-sdk
# =============================================================================
#
# Build requirements:
#   - ps4-payload-sdk checked out in ./ps4-payload-sdk, or
#   - PS4_PAYLOAD_SDK pointing to an installed copy.
#   - llvm-config available via PATH or the LLVM_CONFIG variable.
#
# Usage:
#   make        — build the GoldHEN payload ELF
#   make raw    — optionally export a raw binary image
#   make clean  — remove build artefacts
#
# Output:
#   HDD-EAPDumper.elf
# =============================================================================

PS4_PAYLOAD_SDK ?= $(CURDIR)/ps4-payload-sdk
LLVM_CONFIG ?= $(shell command -v llvm-config 2>/dev/null)

ifeq ($(strip $(LLVM_CONFIG)),)
$(error llvm-config is required by the ps4-payload-sdk wrappers; set LLVM_CONFIG to your LLVM bin/llvm-config)
endif

export LLVM_CONFIG

include $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk

TARGET := $(notdir $(CURDIR))
ELF    := $(TARGET).elf
BIN    := $(TARGET).bin
SRC    := main.c

CFLAGS += -std=c11 -Wall -Wextra -O2

.PHONY: all clean raw

all: $(ELF)

$(ELF): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

raw: $(BIN)

$(BIN): $(ELF)
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f $(ELF) $(BIN)