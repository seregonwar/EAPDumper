# Copyright (C) 2026
#
# HDD-EAPDumper - Makefile
#
# Compile for PS4 (default):
#   make
#   make ps4
#
# Build extra artefacts:
#   make raw
#
# Test on console:
#   export PS4_HOST=<console-ip>
#   export PS4_PORT=9020
#   make test-ps4
#
# This file is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING. If not see
# <http://www.gnu.org/licenses/>.

# Base directory
MAKEFILE_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# ---------- SDK Paths ----------
PS4_PAYLOAD_SDK ?= $(MAKEFILE_DIR)ps4-payload-sdk
LLVM_CONFIG ?= $(shell command -v llvm-config 2>/dev/null)

ifeq ($(strip $(LLVM_CONFIG)),)
$(error llvm-config is required by the ps4-payload-sdk wrappers; set LLVM_CONFIG to your LLVM bin/llvm-config)
endif

export LLVM_CONFIG

include $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk

# ---------- Console configuration ----------
PS4_HOST ?= ps4
PS4_PORT ?= 9020

# ---------- Output ----------
TARGET := HDD-EAPDumper
ELF_PS4 := $(TARGET).elf
BIN_PS4 := $(TARGET).bin
RAW_BIN_PS4 := $(TARGET)-raw.bin

# ---------- Sources ----------
SRC := main.c

# ---------- Compilation flags ----------
CFLAGS += -std=c11 -Wall -Wextra -O2

# ---------- Main targets ----------
.PHONY: all ps4 raw clean test-ps4

all: ps4

ps4: $(ELF_PS4) $(BIN_PS4)

$(ELF_PS4): $(SRC)
	$(CC) $(CFLAGS) -o $@ $<

$(BIN_PS4): $(ELF_PS4)
	cp $< $@
	$(STRIP) $@

raw: $(RAW_BIN_PS4)

$(RAW_BIN_PS4): $(ELF_PS4)
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f $(ELF_PS4) $(BIN_PS4) $(RAW_BIN_PS4)

# ---------- Deploy & Test ----------
test-ps4: $(ELF_PS4)
	$(PS4_DEPLOY) -h $(PS4_HOST) -p $(PS4_PORT) $^
