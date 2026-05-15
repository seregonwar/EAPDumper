#  EAPDumper
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
- 12.50, 12.52,
- 13.00, 13.02, 13.04 13.50 

## Please note 
Make sure you have a recent version of GoldHEN; I recommend GoldHEN v2.4b18.8 or later

## Build

```sh
LLVM_CONFIG=/path/to/llvm-config make
```

This builds:

- `EAPDumper.elf`
- `EAPDumper.bin`
- `EAP-Scanner.elf`
- `EAP-Scanner.bin`

To build only the scanner payload:

```sh
LLVM_CONFIG=/path/to/llvm-config make scanner
```

The `.bin` is the stripped release payload and keeps the ELF payload format
expected by GoldHEN payloader.

