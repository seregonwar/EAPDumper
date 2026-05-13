# HDD-EAPDumper
[![Github All Releases](https://img.shields.io/github/downloads/seregonwar/EAPDumper/total.svg)]()
[![Repository views](https://hits.sh/github.com/seregonwar/EAPDumper.svg?label=views)](https://hits.sh/github.com/seregonwar/EAPDumper/)

PS4 payload that backs up the HDD EAP key from kernel memory.

## Output

The payload writes:

- `/data/hddeap/eap_hdd_key.bin`
- `/data/hddeap/eap_hdd_key.hex`
- `/data/hddeap/eap_hdd_key.txt`
- `/mnt/usb0/eap_hdd_key.bin`
- `/mnt/usb0/eap_hdd_key.hex`
- `/mnt/usb0/eap_hdd_key.txt`

USB output is best-effort. The internal `/data/hddeap` backup is mandatory.

## Supported firmware offsets

- 5.03, 5.05, 5.07
- 6.70, 6.71, 6.72
- 7.00, 7.01, 7.02
- 7.50, 7.51, 7.55
- 9.00, 9.03, 9.04
- 9.50, 9.51, 9.60
- 10.00, 10.01
- 10.50, 10.70, 10.71
- 11.00, 11.02
- 11.50, 11.52
- 12.00, 12.02

Firmware 12.50, 12.52, 13.00, 13.02, 13.04 and 13.50 are not listed until
a public `kern_off_eap_hdd_key` value is available.

## Build

```sh
LLVM_CONFIG=/path/to/llvm-config make
```

This builds:

- `HDD-EAPDumper.elf`
- `HDD-EAPDumper.bin`

The `.bin` is the stripped release payload and keeps the ELF payload format
expected by GoldHEN payloader.

To also generate the optional raw BIN:

```sh
LLVM_CONFIG=/path/to/llvm-config make raw
```

This also adds `HDD-EAPDumper-raw.bin`.
