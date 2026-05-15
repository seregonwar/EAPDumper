/*
MIT License

Copyright (c) 2026 Seregon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
/*
 * EAP HDD key dumper with blind offset discovery for PS4.
 *
 * For known firmware versions, the EAP key offset is looked up from a
 * built-in table.  For unknown firmware versions, a blind entropy-based
 * sniper scan discovers the offset automatically.
 *
 * Design rules:
 *   - Discovery never uses known firmware offsets to select a result.
 *   - The offset table is used only for known firmwares (fast path).
 *   - No candidate key bytes are printed or written to disk.
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
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ps4/kernel.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

#define FW_VERSION_MASK             0xFFFF0000U

#define EAP_KEY_SIZE                32U

/*
 * Empirical entropy over a 32-byte sample is capped at log2(32)=5.0 bits.
 * 4.5 bits is a permissive gate; final ordering comes from score penalties.
 */
#define ENTROPY_THRESHOLD_Q8        1152U       /* 4.5 * 256 */
#define ENTROPY_MAX_Q8              1280U       /* 5.0 * 256 */

/* Search window. */
#define SCAN_START                  0x2600000U
#define SCAN_END                    0x2900000U
#define SCAN_STEP                   16U

#define SCAN_SLOTS                  ((SCAN_END - SCAN_START) / SCAN_STEP)
#define BITSET_SIZE                 ((SCAN_SLOTS + 7U) / 8U)

/* Dense entropy islands are the main false-positive source. */
#define CLUSTER_RADIUS_STEPS        8U          /* +/- 0x80 bytes */

/*
 * Neighborhood entropy contrast: real EAP keys sit in structured kernel
 * data surrounded by lower-entropy bytes.  Random high-entropy chunks
 * have similarly-high entropy in adjacent windows.
 */
#define NEIGHBOR_WINDOW             32U         /* bytes on each side */

/*
 * Post-key entropy drop: the 32 bytes immediately after a real EAP key
 * belong to the enclosing kernel structure and have lower entropy.
 * False positives from compressed regions show flat entropy across
 * adjacent windows.
 */
#define POST_KEY_WINDOW             32U

#define TOP_CANDIDATES              16U

#define DEST_DIR                    "/data/hddeap"
#define DEST_PATH_SCAN              "/data/hddeap/eap_offset_scan.txt"
#define DEST_PATH_USB_SCAN          "/mnt/usb0/eap_offset_scan.txt"

#define OUT_BUF_SIZE                32768U

/* Key-dumper constants */
#define EAP_KEY_SRC_PATH            "/system_data/priv/eap/eap_hdd_key.bin"
#define EAP_KEY_SRC_ALT_PATH        "/eap_user/eap_hdd_key.bin"

#define DEST_DIR_DATA               "/data/hddeap"
#define DEST_PATH_DATA              "/data/hddeap/eap_hdd_key.bin"
#define DEST_PATH_HEX               "/data/hddeap/eap_hdd_key.hex"
#define DEST_PATH_TXT               "/data/hddeap/eap_hdd_key.txt"
#define DEST_PATH_USB_BIN           "/mnt/usb0/eap_hdd_key.bin"
#define DEST_PATH_USB_HEX           "/mnt/usb0/eap_hdd_key.hex"
#define DEST_PATH_USB_TXT           "/mnt/usb0/eap_hdd_key.txt"

#define KEY_BUF_SIZE                64U
#define HEX_BUF_SIZE                1024U
#define TXT_BUF_SIZE                256U

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

typedef struct scan_stats {
    uint32_t total_slots;
    uint32_t read_ok;
    uint32_t read_fail;
    uint32_t rejected_all_equal;
    uint32_t rejected_entropy;
    uint32_t raw_candidates;
    uint32_t max_entropy_q8;
} scan_stats_t;

typedef struct candidate_score {
    uint32_t offset;
    uint32_t entropy_q8;
    uint32_t neighbor_entropy_q8;
    uint32_t post_entropy_q8;
    uint32_t cluster_count;
    uint32_t run_length;
    int32_t  score;
    bool     valid;
} candidate_score_t;

typedef struct eap_offset {
    uint32_t fw;
    intptr_t offset;
} eap_offset_t;

/*
 * Production offset table — used as fast path for known firmware versions.
 * For unknown firmware, the blind sniper scan takes over.
 */
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

__attribute__((weak))
int sceKernelSendNotificationRequest(int, notify_request_t *, size_t, int);

/* Candidate bitmap lives in BSS to avoid stack pressure. */
static uint8_t g_candidate_bits[BITSET_SIZE];

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void notify(const char *msg)
{
    notify_request_t req;

    if (msg == NULL) {
        return;
    }

    if (sceKernelSendNotificationRequest != NULL) {
        memset(&req, 0, sizeof(req));
        strncpy(req.message, msg, sizeof(req.message) - 1U);
        if (sceKernelSendNotificationRequest(0, &req, sizeof(req), 0) == 0) {
            return;
        }
    }

    fprintf(stdout, "%s\n", msg);
    fflush(stdout);
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
        p   += (size_t)written;
        len -= (size_t)written;
    }

    close(fd);
    return 0;
}

static int appendf(char *out_buf, size_t out_buf_max, size_t *pos,
                   const char *fmt, ...)
{
    va_list ap;
    int written;

    if ((out_buf == NULL) || (pos == NULL) || (*pos >= out_buf_max)) {
        return -1;
    }

    va_start(ap, fmt);
    written = vsnprintf(out_buf + *pos, out_buf_max - *pos, fmt, ap);
    va_end(ap);

    if (written < 0) {
        return -1;
    }

    if ((size_t)written >= out_buf_max - *pos) {
        *pos = out_buf_max - 1U;
        out_buf[*pos] = '\0';
        return 1;
    }

    *pos += (size_t)written;
    return 0;
}

static uint32_t q8_frac_to_percent(uint32_t q8)
{
    return ((q8 % 256U) * 100U + 128U) / 256U;
}

static uintptr_t slot_to_offset(uint32_t slot)
{
    return (uintptr_t)SCAN_START + ((uintptr_t)slot * (uintptr_t)SCAN_STEP);
}

static void bitset_clear_all(void)
{
    memset(g_candidate_bits, 0, sizeof(g_candidate_bits));
}

static void bitset_set(uint32_t slot)
{
    if (slot < SCAN_SLOTS) {
        g_candidate_bits[slot / 8U] |= (uint8_t)(1U << (slot % 8U));
    }
}

static bool bitset_get(uint32_t slot)
{
    if (slot >= SCAN_SLOTS) {
        return false;
    }

    return (g_candidate_bits[slot / 8U] & (uint8_t)(1U << (slot % 8U))) != 0U;
}

/* ------------------------------------------------------------------ */
/* Candidate quality checks                                            */
/* ------------------------------------------------------------------ */

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

static uint32_t entropy_q8(const uint8_t *data)
{
    uint32_t freq[256];
    uint32_t result_q8 = 0U;
    size_t i;

    static const uint16_t log2_tbl[33] = {
        0,
        0, 256, 406, 512, 595, 662, 720, 768,
        811, 851, 887, 918, 947, 974, 999, 1024,
        1047, 1068, 1088, 1107, 1126, 1143, 1159, 1174,
        1189, 1203, 1216, 1229, 1241, 1253, 1264, 1280
    };

    if (data == NULL) {
        return 0U;
    }

    memset(freq, 0, sizeof(freq));

    for (i = 0U; i < EAP_KEY_SIZE; i++) {
        freq[data[i]]++;
    }

    for (i = 0U; i < 256U; i++) {
        uint32_t f = freq[i];
        if ((f > 0U) && (f <= EAP_KEY_SIZE)) {
            result_q8 += (f * (ENTROPY_MAX_Q8 - log2_tbl[f])) / EAP_KEY_SIZE;
        }
    }

    return result_q8;
}

static bool candidate_gate(const uint8_t *candidate, uint32_t *entropy_out)
{
    uint32_t entropy;

    if (entropy_out != NULL) {
        *entropy_out = 0U;
    }

    if (candidate == NULL) {
        return false;
    }

    if (all_bytes_equal(candidate, EAP_KEY_SIZE)) {
        return false;
    }

    entropy = entropy_q8(candidate);
    if (entropy_out != NULL) {
        *entropy_out = entropy;
    }

    return entropy >= ENTROPY_THRESHOLD_Q8;
}

/* ------------------------------------------------------------------ */
/* Table lookup (fast path for known firmware)                          */
/* ------------------------------------------------------------------ */

static int get_kernel_eap_key_offset(uint32_t firmware, intptr_t *offset)
{
    uint32_t fw = firmware & FW_VERSION_MASK;
    size_t i;

    if (offset == NULL) {
        return -1;
    }

    for (i = 0U;
         i < (sizeof(EAP_OFFSETS) / sizeof(EAP_OFFSETS[0]));
         i++) {
        if (EAP_OFFSETS[i].fw == fw) {
            *offset = EAP_OFFSETS[i].offset;
            return 0;
        }
    }

    return -2;
}

/* ------------------------------------------------------------------ */
/* Scoring                                                             */
/* ------------------------------------------------------------------ */

/*
 * Compute the average entropy of the two 32-byte windows immediately
 * before and after a candidate offset.
 * A real EAP key shows a sharp entropy spike; false positives from
 * compressed/encrypted regions show similar entropy in neighbors.
 */
static bool compute_neighbor_entropy(uintptr_t candidate_offset,
                                     uint32_t *neighbor_out)
{
    uint8_t buf[NEIGHBOR_WINDOW];
    uintptr_t base;
    uint32_t before_q8;
    uint32_t after_q8;

    if (neighbor_out == NULL) {
        return false;
    }

    *neighbor_out = 0U;

    if (KERNEL_ADDRESS_IMAGE_BASE == 0) {
        return false;
    }

    base = KERNEL_ADDRESS_IMAGE_BASE + candidate_offset;

    if (candidate_offset < (uintptr_t)NEIGHBOR_WINDOW) {
        return false;
    }

    memset(buf, 0, sizeof(buf));
    if (kernel_copyout(base - NEIGHBOR_WINDOW, buf, NEIGHBOR_WINDOW) != 0) {
        return false;
    }
    before_q8 = entropy_q8(buf);

    memset(buf, 0, sizeof(buf));
    if (kernel_copyout(base + EAP_KEY_SIZE, buf, NEIGHBOR_WINDOW) != 0) {
        return false;
    }
    after_q8 = entropy_q8(buf);

    *neighbor_out = (before_q8 + after_q8) / 2U;
    return true;
}

/*
 * Compute entropy of the 32-byte window immediately after the candidate.
 * A real EAP key is followed by lower-entropy kernel structure bytes,
 * while a false positive in a compressed region is followed by similarly
 * high-entropy data.
 */
static bool compute_post_entropy(uintptr_t candidate_offset,
                                 uint32_t *post_out)
{
    uint8_t buf[POST_KEY_WINDOW];
    uintptr_t base;

    if (post_out == NULL) {
        return false;
    }

    *post_out = 0U;

    if (KERNEL_ADDRESS_IMAGE_BASE == 0) {
        return false;
    }

    base = KERNEL_ADDRESS_IMAGE_BASE + candidate_offset + EAP_KEY_SIZE;

    memset(buf, 0, sizeof(buf));
    if (kernel_copyout(base, buf, POST_KEY_WINDOW) != 0) {
        return false;
    }

    *post_out = entropy_q8(buf);
    return true;
}

static uint32_t count_cluster(uint32_t slot)
{
    uint32_t first;
    uint32_t last;
    uint32_t i;
    uint32_t count = 0U;

    first = (slot > CLUSTER_RADIUS_STEPS) ?
            (slot - CLUSTER_RADIUS_STEPS) : 0U;
    last = ((slot + CLUSTER_RADIUS_STEPS) < (SCAN_SLOTS - 1U)) ?
           (slot + CLUSTER_RADIUS_STEPS) : (SCAN_SLOTS - 1U);

    for (i = first; i <= last; i++) {
        if (bitset_get(i)) {
            count++;
        }
    }

    return count;
}

static uint32_t count_run_length(uint32_t slot)
{
    uint32_t count = 1U;
    uint32_t i;

    i = slot;
    while ((i > 0U) && bitset_get(i - 1U)) {
        count++;
        i--;
    }

    i = slot;
    while (((i + 1U) < SCAN_SLOTS) && bitset_get(i + 1U)) {
        count++;
        i++;
    }

    return count;
}

/*
 * Structure likelihood factor for neighbor/post entropy.
 * Returns Q8 fixed-point (0-256, where 256 = 1.0).
 *
 * Real EAP keys sit in kernel data structures with moderate entropy
 * (typically 1.5-4.0 bits).  Extremely low entropy (< 0.5 bits)
 * indicates zero-padding, while extremely high entropy indicates
 * compressed/encrypted regions — neither resembles a kernel struct.
 */
static uint32_t structure_factor(uint32_t entropy_q8)
{
    if (entropy_q8 <= 128U) {
        return 0U;
    }
    if (entropy_q8 <= 384U) {
        return entropy_q8 - 128U;
    }
    if (entropy_q8 <= 1024U) {
        return 256U;
    }
    if (entropy_q8 < ENTROPY_MAX_Q8) {
        return ENTROPY_MAX_Q8 - entropy_q8;
    }
    return 0U;
}

static int32_t compute_score(uint32_t entropy_q8,
                             uint32_t neighbor_entropy_q8,
                             uint32_t post_entropy_q8,
                             uint32_t cluster_count,
                             uint32_t run_length)
{
    uint32_t entropy_span;
    uint32_t entropy_over;
    int32_t entropy_score;
    int32_t contrast_bonus;
    int32_t post_drop_bonus;
    int32_t isolated_bonus;
    int32_t cluster_penalty;
    int32_t run_penalty;

    entropy_span = ENTROPY_MAX_Q8 - ENTROPY_THRESHOLD_Q8;
    entropy_over = (entropy_q8 > ENTROPY_THRESHOLD_Q8) ?
                   (entropy_q8 - ENTROPY_THRESHOLD_Q8) : 0U;

    entropy_score = (int32_t)((entropy_over * 1000U) / entropy_span);

    /*
     * Contrast bonus: rewards candidates where surrounding bytes
     * resemble kernel structure (moderate entropy, 1.5-4.0 bits).
     * Zero-padding and compressed regions both get zero bonus.
     */
    if (neighbor_entropy_q8 < entropy_q8) {
        uint32_t contrast_q8 = entropy_q8 - neighbor_entropy_q8;
        uint32_t factor = structure_factor(neighbor_entropy_q8);
        contrast_bonus = (int32_t)((contrast_q8 * 300U * factor)
                                   / (ENTROPY_MAX_Q8 * 256U));
    } else {
        contrast_bonus = 0;
    }

    /*
     * Post-key drop bonus: the strongest structural signal.
     * The 32 bytes immediately after a real EAP key belong to the
     * enclosing kernel structure and should have moderate entropy.
     */
    if (post_entropy_q8 < entropy_q8) {
        uint32_t drop_q8 = entropy_q8 - post_entropy_q8;
        uint32_t factor = structure_factor(post_entropy_q8);
        post_drop_bonus = (int32_t)((drop_q8 * 500U * factor)
                                    / (ENTROPY_MAX_Q8 * 256U));
    } else {
        post_drop_bonus = 0;
    }

    isolated_bonus = (cluster_count == 1U) ? 200 : 0;
    cluster_penalty = (cluster_count > 1U) ?
                      (int32_t)((cluster_count - 1U) * 60U) : 0;
    run_penalty = (run_length > 1U) ?
                  (int32_t)((run_length - 1U) * 80U) : 0;

    return entropy_score + contrast_bonus + post_drop_bonus + isolated_bonus
           - cluster_penalty - run_penalty;
}

static bool score_slot(uint32_t slot, candidate_score_t *out)
{
    uint8_t chunk[EAP_KEY_SIZE];
    uintptr_t offset;
    uint32_t entropy;
    uint32_t neighbor_entropy = 0U;
    uint32_t post_entropy = 0U;
    uint32_t cluster_count;
    uint32_t run_length;

    if ((out == NULL) || (slot >= SCAN_SLOTS) || !bitset_get(slot)) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    offset = slot_to_offset(slot);

    memset(chunk, 0, sizeof(chunk));
    if (kernel_copyout(KERNEL_ADDRESS_IMAGE_BASE + offset, chunk, EAP_KEY_SIZE) != 0) {
        return false;
    }

    if (!candidate_gate(chunk, &entropy)) {
        return false;
    }

    if (!compute_neighbor_entropy(offset, &neighbor_entropy)) {
        neighbor_entropy = entropy;
    }

    if (!compute_post_entropy(offset, &post_entropy)) {
        post_entropy = entropy;
    }

    cluster_count = count_cluster(slot);
    run_length = count_run_length(slot);

    out->offset = (uint32_t)offset;
    out->entropy_q8 = entropy;
    out->neighbor_entropy_q8 = neighbor_entropy;
    out->post_entropy_q8 = post_entropy;
    out->cluster_count = cluster_count;
    out->run_length = run_length;
    out->score = compute_score(entropy, neighbor_entropy, post_entropy,
                               cluster_count, run_length);
    out->valid = true;
    return true;
}

static bool candidate_is_better(const candidate_score_t *a,
                                const candidate_score_t *b)
{
    if ((a == NULL) || !a->valid) {
        return false;
    }
    if ((b == NULL) || !b->valid) {
        return true;
    }

    if (a->score != b->score) {
        return a->score > b->score;
    }
    if (a->cluster_count != b->cluster_count) {
        return a->cluster_count < b->cluster_count;
    }
    if (a->run_length != b->run_length) {
        return a->run_length < b->run_length;
    }
    if (a->entropy_q8 != b->entropy_q8) {
        return a->entropy_q8 > b->entropy_q8;
    }
    if (a->neighbor_entropy_q8 != b->neighbor_entropy_q8) {
        return a->neighbor_entropy_q8 < b->neighbor_entropy_q8;
    }
    if (a->post_entropy_q8 != b->post_entropy_q8) {
        return a->post_entropy_q8 < b->post_entropy_q8;
    }

    return a->offset < b->offset;
}

static void top_insert(candidate_score_t top[TOP_CANDIDATES],
                       const candidate_score_t *candidate)
{
    size_t i;
    size_t j;

    if ((top == NULL) || (candidate == NULL) || !candidate->valid) {
        return;
    }

    for (i = 0U; i < TOP_CANDIDATES; i++) {
        if (candidate_is_better(candidate, &top[i])) {
            for (j = TOP_CANDIDATES - 1U; j > i; j--) {
                top[j] = top[j - 1U];
            }
            top[i] = *candidate;
            return;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Scanner                                                             */
/* ------------------------------------------------------------------ */

static int build_candidate_bitmap(scan_stats_t *stats)
{
    uint8_t chunk[EAP_KEY_SIZE];
    uint32_t slot;
    uint32_t entropy;

    if (stats == NULL) {
        return -1;
    }

    memset(stats, 0, sizeof(*stats));
    bitset_clear_all();

    if (KERNEL_ADDRESS_IMAGE_BASE == 0) {
        return -1;
    }

    stats->total_slots = SCAN_SLOTS;

    for (slot = 0U; slot < SCAN_SLOTS; slot++) {
        uintptr_t offset = slot_to_offset(slot);

        memset(chunk, 0, sizeof(chunk));
        if (kernel_copyout(KERNEL_ADDRESS_IMAGE_BASE + offset, chunk, EAP_KEY_SIZE) != 0) {
            stats->read_fail++;
            continue;
        }

        stats->read_ok++;

        if (all_bytes_equal(chunk, EAP_KEY_SIZE)) {
            stats->rejected_all_equal++;
            continue;
        }

        entropy = entropy_q8(chunk);
        if (entropy > stats->max_entropy_q8) {
            stats->max_entropy_q8 = entropy;
        }

        if (entropy < ENTROPY_THRESHOLD_Q8) {
            stats->rejected_entropy++;
            continue;
        }

        bitset_set(slot);
        stats->raw_candidates++;
    }

    return 0;
}

static void rank_candidates(candidate_score_t top[TOP_CANDIDATES],
                            const candidate_score_t *known_score,
                            uint32_t *known_rank_out,
                            uint32_t *known_better_out)
{
    uint32_t slot;
    candidate_score_t cur;
    uint32_t better_than_known = 0U;

    if (top != NULL) {
        memset(top, 0, sizeof(candidate_score_t) * TOP_CANDIDATES);
    }

    for (slot = 0U; slot < SCAN_SLOTS; slot++) {
        if (!bitset_get(slot)) {
            continue;
        }

        if (!score_slot(slot, &cur)) {
            continue;
        }

        if (top != NULL) {
            top_insert(top, &cur);
        }

        if ((known_score != NULL) && known_score->valid) {
            if (candidate_is_better(&cur, known_score) &&
                (cur.offset != known_score->offset)) {
                better_than_known++;
            }
        }
    }

    if (known_better_out != NULL) {
        *known_better_out = better_than_known;
    }
    if (known_rank_out != NULL) {
        *known_rank_out = ((known_score != NULL) && known_score->valid) ?
                          (better_than_known + 1U) : 0U;
    }
}

/*
 * Blind sniper discovery — scans kernel memory and returns the
 * top-ranked EAP key offset, or 0 on failure.
 * Also writes the detailed scan report as a side effect.
 */
static uintptr_t discover_eap_offset(void)
{
    static char out_buf[OUT_BUF_SIZE];
    scan_stats_t stats;
    candidate_score_t top[TOP_CANDIDATES];
    size_t pos = 0U;
    size_t i;

    if (KERNEL_ADDRESS_IMAGE_BASE == 0) {
        return 0U;
    }

    if (build_candidate_bitmap(&stats) != 0) {
        return 0U;
    }

    rank_candidates(top, NULL, NULL, NULL);

    (void)appendf(out_buf, sizeof(out_buf), &pos,
                  "EAP Offset Discovery\n"
                  "FW raw:          0x%08X\n"
                  "Kbase:           0x%016llX\n"
                  "Range:           [0x%X, 0x%X) step=0x%X\n"
                  "---\n",
                  (unsigned int)kernel_get_fw_version(),
                  (unsigned long long)KERNEL_ADDRESS_IMAGE_BASE,
                  SCAN_START, SCAN_END, SCAN_STEP);

    (void)appendf(out_buf, sizeof(out_buf), &pos,
                  "Stats: slots=%u read_ok=%u raw_candidates=%u\n"
                  "---\nTop candidates:\n",
                  (unsigned int)stats.total_slots,
                  (unsigned int)stats.read_ok,
                  (unsigned int)stats.raw_candidates);

    for (i = 0U; i < TOP_CANDIDATES; i++) {
        if (!top[i].valid) {
            continue;
        }

        (void)appendf(out_buf, sizeof(out_buf), &pos,
                      "#%u offset=0x%08X score=%ld entropy=%u.%02u "
                      "nbr=%u.%02u post=%u.%02u cluster=%u run=%u\n",
                      (unsigned int)(i + 1U),
                      (unsigned int)top[i].offset,
                      (long)top[i].score,
                      (unsigned int)(top[i].entropy_q8 / 256U),
                      (unsigned int)q8_frac_to_percent(top[i].entropy_q8),
                      (unsigned int)(top[i].neighbor_entropy_q8 / 256U),
                      (unsigned int)q8_frac_to_percent(top[i].neighbor_entropy_q8),
                      (unsigned int)(top[i].post_entropy_q8 / 256U),
                      (unsigned int)q8_frac_to_percent(top[i].post_entropy_q8),
                      (unsigned int)top[i].cluster_count,
                      (unsigned int)top[i].run_length);
    }

    out_buf[(pos < sizeof(out_buf)) ? pos : (sizeof(out_buf) - 1U)] = '\0';

    (void)ensure_dir(DEST_DIR);
    (void)write_file(DEST_PATH_SCAN, out_buf, (size_t)pos);
    (void)write_file(DEST_PATH_USB_SCAN, out_buf, (size_t)pos);

    if (top[0].valid) {
        return (uintptr_t)top[0].offset;
    }

    return 0U;
}

/* ------------------------------------------------------------------ */
/* Key dumper helpers                                                   */
/* ------------------------------------------------------------------ */

static void reverse_16_byte_blocks(const uint8_t *src, uint8_t *dst,
                                   size_t len)
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

static int read_kernel_eap_key(uint8_t *key, size_t key_max,
                               uint32_t *firmware_out)
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

    if (KERNEL_ADDRESS_IMAGE_BASE == 0) {
        return -2;
    }

    if (get_kernel_eap_key_offset(firmware, &offset) != 0) {
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

/* ------------------------------------------------------------------ */
/* Entry point                                                         */
/* ------------------------------------------------------------------ */

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
    char notify_msg[128];

    notify("EAP Dumper: Starting...");

    kernel_key_ret = read_kernel_eap_key(key_buf, KEY_BUF_SIZE, &firmware);
    key_len = kernel_key_ret;

    /*
     * If the table lookup failed (unknown firmware), run the blind
     * sniper scan to discover the offset, then read the key from it.
     */
    if (key_len == -2) {
        uint32_t fw_norm = firmware & FW_VERSION_MASK;
        snprintf(notify_msg, sizeof(notify_msg),
                 "EAP Dumper: FW 0x%08X unknown, sniper scan running...",
                 (unsigned int)fw_norm);
        notify(notify_msg);

        uintptr_t discovered = discover_eap_offset();
        if (discovered != 0U) {
            uint8_t raw_key[EAP_KEY_SIZE];

            snprintf(notify_msg, sizeof(notify_msg),
                     "EAP Dumper: Discovered offset 0x%08lX, reading key...",
                     (unsigned long)discovered);
            notify(notify_msg);

            if (kernel_copyout(KERNEL_ADDRESS_IMAGE_BASE + discovered,
                               raw_key, sizeof(raw_key)) == 0) {
                if (!all_bytes_equal(raw_key, sizeof(raw_key))) {
                    reverse_16_byte_blocks(raw_key, key_buf,
                                          sizeof(raw_key));
                    if (!all_bytes_equal(key_buf, EAP_KEY_SIZE)) {
                        key_len = (int)EAP_KEY_SIZE;
                    }
                }
            }
        }
    }

    if (key_len <= 0) {
        key_len = read_file(EAP_KEY_SRC_PATH, key_buf, KEY_BUF_SIZE);
    }
    if (key_len <= 0) {
        key_len = read_file(EAP_KEY_SRC_ALT_PATH, key_buf, KEY_BUF_SIZE);
    }
    if (key_len <= 0) {
        notify("EAP Dumper: ERROR - No key source found");
        return -1;
    }

    if ((size_t)key_len != EAP_KEY_SIZE) {
        notify("EAP Dumper: ERROR - Unexpected key size");
        return -2;
    }

    hex_len = hex_dump(key_buf, (size_t)key_len, hex_buf, sizeof(hex_buf));
    if (hex_len <= 0) {
        notify("EAP Dumper: ERROR - Hex conversion failed");
        return -3;
    }

    txt_len = build_dmsetup_txt(key_buf, (size_t)key_len,
                                txt_buf, sizeof(txt_buf));
    if (txt_len <= 0) {
        notify("EAP Dumper: WARN - TXT conversion failed");
    }

    if (ensure_dir(DEST_DIR_DATA) != 0) {
        notify("EAP Dumper: ERROR - Cannot create /data/hddeap");
        return -4;
    }

    if (write_file(DEST_PATH_DATA, key_buf, (size_t)key_len) != 0) {
        notify("EAP Dumper: ERROR - Write to /data failed");
        return -5;
    }

    if (write_file(DEST_PATH_HEX, hex_buf, (size_t)hex_len) != 0) {
        notify("EAP Dumper: WARN - Hex write to /data failed");
    }

    if ((txt_len > 0) &&
        (write_file(DEST_PATH_TXT, txt_buf, (size_t)txt_len) != 0)) {
        notify("EAP Dumper: WARN - TXT write to /data failed");
    }

    if (write_file(DEST_PATH_USB_BIN, key_buf, (size_t)key_len) != 0) {
        usb_ok = false;
        notify("EAP Dumper: WARN - USB write failed (USB inserted?)");
    } else {
        if (write_file(DEST_PATH_USB_HEX, hex_buf, (size_t)hex_len) != 0) {
            notify("EAP Dumper: WARN - Hex write to USB failed");
        }
        if ((txt_len > 0) &&
            (write_file(DEST_PATH_USB_TXT, txt_buf, (size_t)txt_len) != 0)) {
            notify("EAP Dumper: WARN - TXT write to USB failed");
        }
    }

    notify(usb_ok ? "EAP Dumper: SUCCESS - Saved to /data and USB"
                  : "EAP Dumper: SUCCESS - Saved to /data only (no USB)");
    return 0;
}
