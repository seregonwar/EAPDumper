/*
 * PS4 HDD EAP key dumper.
 *
 * Saves:
 *   /data/hddeap/eap_hdd_key.{bin,hex,txt}
 *   /mnt/usb0/eap_hdd_key.{bin,hex,txt}
 */

#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <ps4/kernel.h>

#define FW_VERSION_MASK 0xFFFF0000U

#define EAP_KEY_SRC_PATH     "/system_data/priv/eap/eap_hdd_key.bin"
#define EAP_KEY_SRC_ALT_PATH "/eap_user/eap_hdd_key.bin"

#define DEST_DIR_DATA     "/data/hddeap"
#define DEST_PATH_DATA    "/data/hddeap/eap_hdd_key.bin"
#define DEST_PATH_HEX     "/data/hddeap/eap_hdd_key.hex"
#define DEST_PATH_TXT     "/data/hddeap/eap_hdd_key.txt"
#define DEST_PATH_USB     "/mnt/usb0/eap_hdd_key.bin"
#define DEST_PATH_USB_HEX "/mnt/usb0/eap_hdd_key.hex"
#define DEST_PATH_USB_TXT "/mnt/usb0/eap_hdd_key.txt"

#define EAP_KEY_SIZE 32U
#define KEY_BUF_SIZE 64U
#define HEX_BUF_SIZE 1024U
#define TXT_BUF_SIZE 256U

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

typedef struct eap_offset {
    uint32_t firmware;
    intptr_t offset;
} eap_offset_t;

__attribute__((weak)) int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

static const eap_offset_t EAP_OFFSETS[] = {
    { 0x05030000U, (intptr_t)0x2790C90 },
    { 0x05050000U, (intptr_t)0x2790C90 },
    { 0x05070000U, (intptr_t)0x2790C90 },

    { 0x06700000U, (intptr_t)0x26DCCD0 },
    { 0x06710000U, (intptr_t)0x26DCCD0 },
    { 0x06720000U, (intptr_t)0x26DCCD0 },

    { 0x07000000U, (intptr_t)0x26E0CD0 },
    { 0x07010000U, (intptr_t)0x26E0CD0 },
    { 0x07020000U, (intptr_t)0x26E0CD0 },

    { 0x07500000U, (intptr_t)0x26D4C90 },
    { 0x07510000U, (intptr_t)0x26D4C90 },
    { 0x07550000U, (intptr_t)0x26D4C90 },

    { 0x09000000U, (intptr_t)0x26C4C90 },

    { 0x09030000U, (intptr_t)0x26C0C90 },
    { 0x09040000U, (intptr_t)0x26C0C90 },

    { 0x09500000U, (intptr_t)0x26B4C60 },
    { 0x09510000U, (intptr_t)0x26B4C60 },
    { 0x09600000U, (intptr_t)0x26B4C60 },

    { 0x10000000U, (intptr_t)0x26C4D00 },
    { 0x10010000U, (intptr_t)0x26C4D00 },

    { 0x10500000U, (intptr_t)0x26C4D00 },
    { 0x10700000U, (intptr_t)0x26C4D00 },
    { 0x10710000U, (intptr_t)0x26C4D00 },

    { 0x11000000U, (intptr_t)0x26C4CD0 },
    { 0x11020000U, (intptr_t)0x26C4CD0 },

    { 0x11500000U, (intptr_t)0x26C4CF0 },
    { 0x11520000U, (intptr_t)0x26C4CF0 },

    { 0x12000000U, (intptr_t)0x26C4CF0 },
    { 0x12020000U, (intptr_t)0x26C4CF0 },
};

static void notify(const char *message)
{
    notify_request_t request;

    if (message == NULL) {
        return;
    }

    if (sceKernelSendNotificationRequest != NULL) {
        memset(&request, 0, sizeof(request));
        strncpy(request.message, message, sizeof(request.message) - 1U);

        if (sceKernelSendNotificationRequest(0, &request, sizeof(request), 0) == 0) {
            return;
        }
    }

    fprintf(stdout, "%s\n", message);
    fflush(stdout);
}

static void notify_unknown_eap_offset(uint32_t firmware)
{
    char message[96];

    snprintf(message, sizeof(message),
             "EAP Backup: ERROR - EAP offset unknown for FW 0x%08X",
             (unsigned int)(firmware & FW_VERSION_MASK));
    notify(message);
}

static int write_file(const char *path, const void *data, size_t len)
{
    const uint8_t *p;
    int fd;

    if ((path == NULL) || (data == NULL) || (len == 0U)) {
        return -1;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        return -1;
    }

    p = (const uint8_t *)data;
    while (len > 0U) {
        ssize_t written = write(fd, p, len);
        if (written <= 0) {
            close(fd);
            return -2;
        }
        p += (size_t)written;
        len -= (size_t)written;
    }

    close(fd);
    return 0;
}

static int read_file(const char *path, void *buf, size_t max_len)
{
    int fd;
    ssize_t n;

    if ((path == NULL) || (buf == NULL) || (max_len == 0U)) {
        return -1;
    }

    fd = open(path, O_RDONLY, 0);
    if (fd < 0) {
        return -1;
    }

    n = read(fd, buf, max_len);
    close(fd);

    return (n > 0) ? (int)n : -2;
}

static bool all_bytes_equal(const uint8_t *data, size_t len)
{
    size_t i;

    if ((data == NULL) || (len == 0U)) {
        return true;
    }

    for (i = 1U; i < len; i++) {
        if (data[i] != data[0]) {
            return false;
        }
    }

    return true;
}

static void reverse_16_byte_blocks(const uint8_t *src, uint8_t *dst, size_t len)
{
    size_t block;
    size_t i;

    for (block = 0U; block < len; block += 16U) {
        size_t block_len = len - block;
        if (block_len > 16U) {
            block_len = 16U;
        }

        for (i = 0U; i < block_len; i++) {
            dst[block + i] = src[block + block_len - 1U - i];
        }
    }
}

static int get_kernel_eap_key_offset(uint32_t firmware, intptr_t *offset)
{
    uint32_t fw = firmware & FW_VERSION_MASK;
    size_t i;

    if (offset == NULL) {
        return -1;
    }

    for (i = 0U; i < (sizeof(EAP_OFFSETS) / sizeof(EAP_OFFSETS[0])); i++) {
        if (EAP_OFFSETS[i].firmware == fw) {
            *offset = EAP_OFFSETS[i].offset;
            return 0;
        }
    }

    return -2;
}

static int read_kernel_eap_key(uint8_t *key, size_t key_max, uint32_t *firmware_out)
{
    uint8_t raw_key[EAP_KEY_SIZE];
    uint32_t firmware;
    intptr_t offset;

    if ((key == NULL) || (key_max < EAP_KEY_SIZE)) {
        return -1;
    }

    firmware = kernel_get_fw_version();
    if (firmware_out != NULL) {
        *firmware_out = firmware;
    }

    if ((KERNEL_ADDRESS_IMAGE_BASE == 0) ||
        (get_kernel_eap_key_offset(firmware, &offset) != 0)) {
        return -2;
    }

    if (kernel_copyout(KERNEL_ADDRESS_IMAGE_BASE + offset,
                       raw_key, sizeof(raw_key)) != 0) {
        return -3;
    }

    if (all_bytes_equal(raw_key, sizeof(raw_key))) {
        return -4;
    }

    reverse_16_byte_blocks(raw_key, key, sizeof(raw_key));
    return all_bytes_equal(key, EAP_KEY_SIZE) ? -5 : (int)EAP_KEY_SIZE;
}

static int hex_dump(const uint8_t *data, size_t len, char *out, size_t out_max)
{
    static const char HEX[] = "0123456789ABCDEF";
    size_t i;
    size_t pos = 0U;

    if ((data == NULL) || (out == NULL) || (out_max == 0U)) {
        return -1;
    }

    for (i = 0U; i < len; i++) {
        if ((i % 16U) == 0U) {
            uint32_t offset = (uint32_t)i;
            if ((pos + 10U) >= out_max) {
                return -1;
            }
            out[pos++] = HEX[(offset >> 28U) & 0xFU];
            out[pos++] = HEX[(offset >> 24U) & 0xFU];
            out[pos++] = HEX[(offset >> 20U) & 0xFU];
            out[pos++] = HEX[(offset >> 16U) & 0xFU];
            out[pos++] = HEX[(offset >> 12U) & 0xFU];
            out[pos++] = HEX[(offset >> 8U) & 0xFU];
            out[pos++] = HEX[(offset >> 4U) & 0xFU];
            out[pos++] = HEX[offset & 0xFU];
            out[pos++] = ':';
            out[pos++] = ' ';
        }

        if ((pos + 4U) >= out_max) {
            return -1;
        }
        out[pos++] = HEX[(data[i] >> 4U) & 0xFU];
        out[pos++] = HEX[data[i] & 0xFU];
        out[pos++] = ' ';

        if (((i % 16U) == 7U) && ((pos + 1U) < out_max)) {
            out[pos++] = ' ';
        }

        if (((i % 16U) == 15U) || ((i + 1U) == len)) {
            out[pos++] = '\n';
        }
    }

    out[pos] = '\0';
    return (int)pos;
}

static int build_dmsetup_txt(const uint8_t *key, size_t key_len,
                             char *out, size_t out_max)
{
    static const char HEX[] = "0123456789abcdef";
    static const char PREFIX[] = "0 1857806336 crypt aes-xts-plain64 ";
    static const char SUFFIX[] = " 0 259:3 0\n";
    size_t pos = 0U;
    size_t i;

    if ((key == NULL) || (key_len != EAP_KEY_SIZE) ||
        (out == NULL) || (out_max < TXT_BUF_SIZE)) {
        return -1;
    }

    for (i = 0U; PREFIX[i] != '\0'; i++) {
        out[pos++] = PREFIX[i];
    }

    for (i = 0U; i < key_len; i++) {
        out[pos++] = HEX[(key[i] >> 4U) & 0xFU];
        out[pos++] = HEX[key[i] & 0xFU];
    }

    for (i = 0U; SUFFIX[i] != '\0'; i++) {
        out[pos++] = SUFFIX[i];
    }

    out[pos] = '\0';
    return (int)pos;
}

static int ensure_dir(const char *path)
{
    struct stat st;

    if (path == NULL) {
        return -1;
    }

    if (mkdir(path, 0755) == 0) {
        return 0;
    }

    return ((stat(path, &st) == 0) && S_ISDIR(st.st_mode)) ? 0 : -1;
}

int main(void)
{
    static uint8_t key_buf[KEY_BUF_SIZE];
    static char hex_buf[HEX_BUF_SIZE];
    static char txt_buf[TXT_BUF_SIZE];

    int key_len;
    int kernel_key_ret;
    int hex_len;
    int txt_len;
    uint32_t firmware = 0U;
    bool usb_ok = true;

    kernel_key_ret = read_kernel_eap_key(key_buf, KEY_BUF_SIZE, &firmware);
    key_len = kernel_key_ret;

    if (key_len <= 0) {
        key_len = read_file(EAP_KEY_SRC_PATH, key_buf, KEY_BUF_SIZE);
    }
    if (key_len <= 0) {
        key_len = read_file(EAP_KEY_SRC_ALT_PATH, key_buf, KEY_BUF_SIZE);
    }
    if (key_len <= 0) {
        if (kernel_key_ret == -2) {
            notify_unknown_eap_offset(firmware);
        }
        notify("EAP Backup: ERROR - Key source not found");
        return -1;
    }

    if ((size_t)key_len != EAP_KEY_SIZE) {
        notify("EAP Backup: ERROR - Unexpected key size");
        return -2;
    }

    hex_len = hex_dump(key_buf, (size_t)key_len, hex_buf, sizeof(hex_buf));
    if (hex_len <= 0) {
        notify("EAP Backup: ERROR - Hex conversion failed");
        return -3;
    }

    txt_len = build_dmsetup_txt(key_buf, (size_t)key_len, txt_buf, sizeof(txt_buf));
    if (txt_len <= 0) {
        notify("EAP Backup: WARN - TXT conversion failed");
    }

    if (ensure_dir(DEST_DIR_DATA) != 0) {
        notify("EAP Backup: ERROR - Cannot create /data/hddeap");
        return -4;
    }

    if (write_file(DEST_PATH_DATA, key_buf, (size_t)key_len) != 0) {
        notify("EAP Backup: ERROR - Write to /data failed");
        return -5;
    }

    if (write_file(DEST_PATH_HEX, hex_buf, (size_t)hex_len) != 0) {
        notify("EAP Backup: WARN - Hex write to /data failed");
    }

    if ((txt_len > 0) && (write_file(DEST_PATH_TXT, txt_buf, (size_t)txt_len) != 0)) {
        notify("EAP Backup: WARN - TXT write to /data failed");
    }

    if (write_file(DEST_PATH_USB, key_buf, (size_t)key_len) != 0) {
        usb_ok = false;
        notify("EAP Backup: WARN - USB write failed (USB inserted?)");
    } else {
        if (write_file(DEST_PATH_USB_HEX, hex_buf, (size_t)hex_len) != 0) {
            notify("EAP Backup: WARN - Hex write to USB failed");
        }
        if ((txt_len > 0) &&
            (write_file(DEST_PATH_USB_TXT, txt_buf, (size_t)txt_len) != 0)) {
            notify("EAP Backup: WARN - TXT write to USB failed");
        }
    }

    notify(usb_ok ? "EAP Backup: SUCCESS - Saved to /data and USB"
                  : "EAP Backup: SUCCESS - Saved to /data only (no USB)");
    return 0;
}
