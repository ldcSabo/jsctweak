/* Tweak_readbit.m - the device-side capture probe (the layout-independent
 * three-block form). One hook (JSObject::putByIndex) with two filters:
 * (a) the value in the marker set -> the first ring (the readybit)
 * (b) the index in the 36 named slots -> the second ring (the wj)
 * Each shared block carries its OWN magic + a nonzero initializer, so
 * every block is one contiguous __data allocation - the reader anchors
 * each block independently, no cross-block offsets. */
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <libkern/OSCacheControl.h>
#import <stdint.h>
#import <stdio.h>
#import <string.h>
#import <unistd.h>

#define MAGIC_HDR 0x5245574A504F4252ULL
#define MAGIC_RB  0x5245574A50524252ULL
#define MAGIC_WJ  0x5245574A50574A4AULL
#define MAGIC_PUSH 0x5245574A50555348ULL
#define MAGIC_API  0x5245574A50415049ULL
#define MAGIC_STR  0x5245574A50535452ULL

#define RB_RING 65536
#define WJ_RING 4096
#define PUSH_RING 32768
#define API_RING 32768
#define STR_RING 4096
#define STR_BUF 128

typedef struct {
    uint64_t slot_id;
    uint64_t raw_value;
    uint64_t seq;
} RBEntry;

typedef struct {
    uint64_t magic;      /* offset 0 */
    uint64_t armed;      /* offset 8 */
    uint64_t total_puts; /* offset 16 */
    uint64_t syms_mask;  /* offset 24 - the bitmask of the candidate symbols found */
    uint64_t syms_count; /* offset 32 - the count */
    uint64_t push_status;/* offset 40 - 0 not found / 1 reloc / 2 tramp / 3 rw / 4 ok */
    uint64_t vt_attempted; /* offset 48 */
    uint64_t vt_ok;        /* offset 56 */
    uint64_t vt_sid;       /* offset 64 - the structureID from the cell */
    uint64_t vt_classinfo; /* offset 72 */
    uint64_t vt_mt;        /* offset 80 - the methodTable pointer */
    uint64_t vt_gos;       /* offset 88 - the getOwnPropertySlot slot value */
    uint64_t vt_gosbi;     /* offset 96 - the getOwnPropertySlotByIndex slot value */
    uint64_t dbg8[8];      /* offset 104 - the install status of the 8 stubborn hooks:
                               0 not-found / 1 thunk-follow / 2 tramp-NULL /
                               3 make_rw-fail / 4 ok */
} HdrBlock;

typedef struct {
    uint64_t magic;      /* offset 0 */
    uint64_t capacity;   /* offset 8 */
    uint64_t entry_size; /* offset 16 */
    uint64_t head;       /* offset 24 */
    RBEntry  entries[RB_RING]; /* offset 32 */
} RBBlock;

typedef struct {
    uint64_t magic;      /* offset 0 */
    uint64_t capacity;   /* offset 8 */
    uint64_t entry_size; /* offset 16 */
    uint64_t head;       /* offset 24 */
    struct { uint64_t array; uint64_t value; uint64_t seq; } entries[PUSH_RING];
} PushBlock;

/* the C-API ring: the indexed property get/set via the public embedding layer */
typedef struct {
    uint64_t magic;      /* offset 0 */
    uint64_t capacity;   /* offset 8 */
    uint64_t entry_size; /* offset 16 */
    uint64_t head;       /* offset 24 */
    struct { uint64_t obj; uint64_t index; uint64_t value; uint64_t kind; uint64_t seq; } entries[API_RING];
} APIBlock;

/* the string-text ring: the JSValueToStringCopy results (the UTF-16 text) */
typedef struct {
    uint64_t magic;      /* offset 0 */
    uint64_t capacity;   /* offset 8 */
    uint64_t entry_size; /* offset 16 */
    uint64_t head;       /* offset 24 */
    struct { uint64_t len; uint64_t seq; uint16_t chars[STR_BUF]; } entries[STR_RING];
} StrBlock;

typedef struct {
    uint64_t magic;      /* offset 0 */
    uint64_t capacity;   /* offset 8 */
    uint64_t slot_size;  /* offset 16 */
    uint64_t val_size;   /* offset 24 */
    uint64_t head;       /* offset 32 */
    uint64_t slots[WJ_RING]; /* offset 40 */
    uint64_t vals[WJ_RING];  /* offset 40 + WJ_RING*8 */
    uint64_t seqs[WJ_RING];  /* offset 40 + WJ_RING*16 - the op stamp */
} WJBlock;

__attribute__((visibility("default"))) HdrBlock g_hdr = {
    MAGIC_HDR, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, {0}
};
__attribute__((visibility("default"))) RBBlock g_rb = {
    MAGIC_RB, RB_RING, sizeof(RBEntry), 0, {{0}}
};
__attribute__((visibility("default"))) WJBlock g_wj = {
    MAGIC_WJ, WJ_RING, sizeof(uint64_t), sizeof(uint64_t), 0, {0}, {0}
};
__attribute__((visibility("default"))) PushBlock g_push = {
    MAGIC_PUSH, PUSH_RING, 24, 0, {{0}}
};
__attribute__((visibility("default"))) APIBlock g_api = {
    MAGIC_API, API_RING, 40, 0, {{0}}
};
__attribute__((visibility("default"))) StrBlock g_str = {
    MAGIC_STR, STR_RING, 16 + STR_BUF * 2, 0, {{0}}
};

/* the 42 named slots (the 30 engine-side + the 6 reference-side +
   the 6 keysched seed-chain: the 47/51/339/405/498/510) */
static const uint32_t named36[] = {
    2, 3, 7, 9, 34, 37, 38, 68, 69, 82, 87, 93, 94, 130, 154, 168,
    188, 217, 222, 235, 321, 340, 346, 371, 374, 447, 449, 452, 493, 506,
    17, 41, 62, 172, 191, 281,
    47, 51, 339, 405, 498, 510
};

/* the 8 record-head cells (the per-byte attribution targets) */
static const uint32_t rechead8[] = {
    112, 245, 360, 386, 90, 331, 177, 137
};

static int is_named(uint64_t idx) {
    /* the low 32 = the true index; the upper half of the register is stale
       (the caller only sets w2), so never compare the full 64-bit value. */
    uint32_t v = (uint32_t)idx;
    for (int i = 0; i < 42; i++)
        if (named36[i] == v) return 1;
    for (int i = 0; i < 8; i++)
        if (rechead8[i] == v) return 1;
    return 0;
}

static int is_marker(uint64_t v) {
    /* the marker values: -1 (tombstone), 0x800 (ready bit), 0x5E25, 0x20800.
       The value register may carry the tagged upper half, so compare the low 32. */
    uint32_t lo = (uint32_t)v;
    return lo == 0xFFFFFFFFu || lo == 0x800u || lo == 0x5E25u || lo == 0x20800u;
}

static void *g_orig_put = NULL;
static uint64_t g_putby_addr = 0;
static void probe_vtable_chain(uint64_t cell, uint64_t global);

/* a fault-safe 64-bit read: the kernel validates the mapping, so a bad
   speculative address returns an error instead of killing the process. */
static int safe_read64(uint64_t addr, uint64_t *out) {
    vm_size_t got = 0;
    return vm_read_overwrite(mach_task_self(), (vm_address_t)addr, 8,
                             (vm_address_t)out, &got) == KERN_SUCCESS && got == 8;
}

static void put_hook(uint64_t cell, uint64_t global, uint64_t index,
                     uint64_t value, uint64_t strict) {
    uint64_t n = __atomic_add_fetch(&g_hdr.total_puts, 1, __ATOMIC_SEQ_CST);
    if (!g_hdr.vt_attempted && cell > 0x100000000ULL)
        probe_vtable_chain(cell, global);
    if (is_named(index)) {
        uint64_t h = __atomic_fetch_add(&g_wj.head, 1, __ATOMIC_SEQ_CST) % WJ_RING;
        g_wj.slots[h] = index;
        g_wj.vals[h] = value;
        g_wj.seqs[h] = n;   /* the op stamp (the monotonic put counter) */
    }
    /* the early-setup window (the first 1024 puts) unconditionally, so the
       setup context is captured; plus every marker-valued put (including the
       zero append-trigger) at any time. */
    if (n <= 1024 || is_marker(value) || (uint32_t)value == 0) {
        uint64_t h = __atomic_fetch_add(&g_rb.head, 1, __ATOMIC_SEQ_CST) % RB_RING;
        g_rb.entries[h].slot_id = index;
        g_rb.entries[h].raw_value = value;
        g_rb.entries[h].seq = n;
    }
    /* THE ORIGINAL MUST RUN - the trampoline call (the true ABI:
       the unsigned index in x2, the JSValue in x3) */
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))g_orig_put)(
        cell, global, index, value, strict);
}

/* ---- the array-literal store path (the keysched keystream blocks) ----
   JSObject::initializeIndex(JSGlobalObject*, unsigned, JSValue) = the
   put-by-index path the interpreter's array literals take (the putByIndex
   is the dynamic arr[idx]=v; the literals initialize via this one, so the
   nw output blocks never hit putByIndex). The x0 = this, x1 = the global,
   x2 = the index, x3 = the value. */
static void *g_orig_initidx = NULL;
static void initidx_hook(uint64_t self, uint64_t global, uint64_t index, uint64_t value) {
    uint64_t n = __atomic_add_fetch(&g_hdr.total_puts, 1, __ATOMIC_SEQ_CST);
    if (is_named(index)) {
        uint64_t h = __atomic_fetch_add(&g_wj.head, 1, __ATOMIC_SEQ_CST) % WJ_RING;
        g_wj.slots[h] = index;
        g_wj.vals[h] = value;
        g_wj.seqs[h] = n;
    }
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t))g_orig_initidx)(
        self, global, index, value);
}

/* ---- the named-put capture (the t.X re-key write) ----
   JSObject::put(JSCell*, JSGlobalObject*, PropertyName, JSValue, PutPropertySlot*)
   = the x0 cell, x1 global, x2 the PropertyName (the numeric = the odd-encoded
   u (the (u-1)>>1 = the index); the string = the WTF::StringImpl ptr), x3 the
   value, x4 the slot. The string names are read at capture time: the
   (ptr+8) = the u32 m_length, the (ptr+16) = the latin1 data. The short
   single-letter names (the "X" the re-key field) are logged. */
static void *g_orig_put_named = NULL;
static void put_named_hook(uint64_t cell, uint64_t global, uint64_t pname,
                           uint64_t value, uint64_t slot) {
    uint64_t n = __atomic_add_fetch(&g_hdr.total_puts, 1, __ATOMIC_SEQ_CST);
    if (pname > 0x100000000ULL && pname < 0x800000000ULL) {
        if (pname & 1) {
            /* the numeric PropertyName = the odd-encoded index */
            uint64_t idx = (pname - 1) >> 1;
            if (is_named(idx)) {
                uint64_t h = __atomic_fetch_add(&g_wj.head, 1, __ATOMIC_SEQ_CST) % WJ_RING;
                g_wj.slots[h] = idx;
                g_wj.vals[h] = value;
                g_wj.seqs[h] = n;
            }
        } else {
            /* the string name: the read the StringImpl (the len @+8, the data @+16) */
            uint64_t lenq = 0;
            if (safe_read64(pname + 8, &lenq)) {
                uint32_t len = (uint32_t)lenq;
                if (len > 0 && len < 16) {
                    char nbuf[16] = {0};
                    if (safe_read64(pname + 16, (uint64_t *)nbuf) &&
                        safe_read64(pname + 24, (uint64_t *)(nbuf + 8))) {
                        int printable = 1;
                        for (uint32_t i = 0; i < len; i++) {
                            char ch = nbuf[i];
                            if (ch < 0x20 || ch > 0x7e) { printable = 0; break; }
                        }
                        if (printable && len <= 2) {
                            FILE *f = fopen("/tmp/jsc_namedputs.log", "a");
                            if (f) {
                                fprintf(f, "[%d] put name='%.*s' len=%u value=%llx cell=%llx\n",
                                        getpid(), (int)len, nbuf, len,
                                        (unsigned long long)value,
                                        (unsigned long long)cell);
                                fclose(f);
                            }
                        }
                    }
                }
            }
        }
    }
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))g_orig_put_named)(
        cell, global, pname, value, slot);
}

/* ---- the vtable chain probe (the MethodTable slot walk, runtime-validated) ----
   The cell -> the structureID -> the VM's structureIDTable -> the Structure ->
   the m_classInfo -> the MethodTable; the slots 7/8 (the getOwnPropertySlot /
   getOwnPropertySlotByIndex) are raw function pointers on this arm64 build.
   Every hop is validated (the pointer ranges + the printable className), so a
   wrong candidate offset fails safely instead of crashing. */
/* the method-table discovery: the scan the readable regions for the 8-byte
   putByIndex pointer (the MethodTable slot 4); the slots 7/8 = the
   getOwnPropertySlot / getOwnPropertySlotByIndex addresses. This derives the
   vtable entry points from the one symbol we already hook - no layout guess. */
static void discover_mt(uint64_t pv) {
    vm_address_t addr = 0;
    vm_size_t size = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t ic = VM_REGION_BASIC_INFO_COUNT_64;
    mach_port_t obj;
    int regions = 0;
    while (vm_region_64(mach_task_self(), &addr, &size, VM_REGION_BASIC_INFO_64,
                        (vm_region_info_t)&info, &ic, &obj) == KERN_SUCCESS && !g_hdr.vt_ok) {
        regions++;
        if ((info.protection & VM_PROT_READ) && size >= 0x1000 && size < 0x8000000) {
            uint8_t *buf = malloc(size);
            if (!buf) { addr += size; size = 0; continue; }
            vm_size_t got = 0;
            if (vm_read_overwrite(mach_task_self(), addr, size, (vm_address_t)buf, &got) == KERN_SUCCESS) {
                for (vm_size_t off = 0; off + 8 <= got; off += 8) {
                    uint64_t v = 0;
                    memcpy(&v, buf + off, 8);
                    if (v == pv) {
                        uint64_t mt = addr + off - 4 * 8;
                        uint64_t gos = 0, gosbi = 0;
                        if (safe_read64(mt + 7 * 8, &gos) && safe_read64(mt + 8 * 8, &gosbi) &&
                            gos >= 0x180000000ULL && gos < 0x190000000ULL &&
                            gosbi >= 0x180000000ULL && gosbi < 0x190000000ULL) {
                            g_hdr.vt_ok = 1;
                            g_hdr.vt_mt = mt;
                            g_hdr.vt_gos = gos;
                            g_hdr.vt_gosbi = gosbi;
                        }
                    }
                }
            }
            free(buf);
        }
        addr += size;
        size = 0;
        if (regions > 4000) break;
    }
}

static void probe_vtable_chain(uint64_t cell, uint64_t global) {
    if (g_hdr.vt_attempted) return;
    g_hdr.vt_attempted = 1;
    if (g_hdr.vt_ok) return;
    /* the method-table route first (the pointer scan); the cell-walk as the fallback */
    discover_mt(g_putby_addr);

    uint32_t sid = 0;
    if (!safe_read64(cell, (uint64_t *)&sid)) { g_hdr.vt_sid = 0; return; }
    g_hdr.vt_sid = sid;

    for (uint64_t vmOff = 0x20; vmOff < 0x800 && !g_hdr.vt_ok; vmOff += 8) {
        uint64_t p = 0;
        if (!safe_read64(global + vmOff, &p)) continue;
        if (p < 0x100000000ULL || p > 0x800000000ULL) continue;
        uint64_t s = 0;
        if (!safe_read64(p + (uint64_t)(sid & 0x7FFF) * 8, &s)) continue;
        if (s < 0x100000000ULL || s > 0x800000000ULL) continue;
        for (uint64_t ciOff = 0x48; ciOff <= 0x80 && !g_hdr.vt_ok; ciOff += 8) {
            uint64_t ci = 0;
            if (!safe_read64(s + ciOff, &ci)) continue;
            if (ci < 0x100000000ULL || ci > 0x800000000ULL) continue;
            uint64_t namep = 0;
            if (!safe_read64(ci, &namep)) continue;
            if (namep < 0x100000000ULL || namep > 0x800000000ULL) continue;
            char nbuf[24] = {0};
            if (!safe_read64(namep, (uint64_t *)nbuf) || !safe_read64(namep + 8, (uint64_t *)(nbuf + 8))
                || !safe_read64(namep + 16, (uint64_t *)(nbuf + 16))) continue;
            int printable = 1;
            for (int i = 0; i < 16; i++) {
                char ch = nbuf[i];
                if (!ch) break;
                if (ch < 0x20 || ch > 0x7e) { printable = 0; break; }
            }
            if (!printable) continue;
            for (uint64_t mtOff = 0x20; mtOff <= 0x50 && !g_hdr.vt_ok; mtOff += 8) {
                uint64_t mt = ci + mtOff;
                uint64_t gos = 0, gosbi = 0;
                if (!safe_read64(mt + 56, &gos) || !safe_read64(mt + 64, &gosbi)) continue;
                if (gos >= 0x180000000ULL && gos < 0x190000000ULL &&
                    gosbi >= 0x180000000ULL && gosbi < 0x190000000ULL) {
                    g_hdr.vt_ok = 1;
                    g_hdr.vt_classinfo = ci;
                    g_hdr.vt_mt = mt;
                    g_hdr.vt_gos = gos;
                    g_hdr.vt_gosbi = gosbi;
                }
            }
        }
    }
}

static void *g_orig_push = NULL;
/* the member overload: JSArray::push(JSGlobalObject*, JSValue) -> x0 = this
   (the JSArray), x1 = the global, x2 = the value. */
static void push_hook(uint64_t self, uint64_t global, uint64_t value) {
    uint64_t n = __atomic_add_fetch(&g_push.head, 1, __ATOMIC_SEQ_CST);
    uint64_t h = (n - 1) % PUSH_RING;
    g_push.entries[h].array = self;
    g_push.entries[h].value = value;
    g_push.entries[h].seq = n;
    ((void (*)(uint64_t, uint64_t, uint64_t))g_orig_push)(self, global, value);
}

/* the C-API indexed property get/set (the public embedding layer) */
static void *g_orig_apiget = NULL;
static void *g_orig_apiset = NULL;
static void apiget_hook(uint64_t ctx, uint64_t obj, uint64_t index, uint64_t exc) {
    uint64_t n = __atomic_add_fetch(&g_api.head, 1, __ATOMIC_SEQ_CST);
    uint64_t h = (n - 1) % API_RING;
    g_api.entries[h].obj = obj;
    g_api.entries[h].index = index;
    g_api.entries[h].value = 0;
    g_api.entries[h].kind = 1;  /* 1 = get */
    g_api.entries[h].seq = n;
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t))g_orig_apiget)(ctx, obj, index, exc);
}
static void apiset_hook(uint64_t ctx, uint64_t obj, uint64_t index, uint64_t value, uint64_t exc) {
    uint64_t n = __atomic_add_fetch(&g_api.head, 1, __ATOMIC_SEQ_CST);
    uint64_t h = (n - 1) % API_RING;
    g_api.entries[h].obj = obj;
    g_api.entries[h].index = index;
    g_api.entries[h].value = value;
    g_api.entries[h].kind = 2;  /* 2 = set */
    g_api.entries[h].seq = n;
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))g_orig_apiset)(ctx, obj, index, value, exc);
}

/* the call layer: JSObjectCallAsFunction - the callee identity (the n2/O layer) */
static void *g_orig_callfn = NULL;
static void callfn_hook(uint64_t ctx, uint64_t obj, uint64_t thisObj, uint64_t argc, uint64_t argv, uint64_t exc) {
    uint64_t n = __atomic_add_fetch(&g_api.head, 1, __ATOMIC_SEQ_CST);
    uint64_t h = (n - 1) % API_RING;
    g_api.entries[h].obj = obj;
    g_api.entries[h].index = argc;
    g_api.entries[h].value = thisObj;
    g_api.entries[h].kind = 3;  /* 3 = call */
    g_api.entries[h].seq = n;
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))g_orig_callfn)(
        ctx, obj, thisObj, argc, argv, exc);
}

/* the eval layer: JSEvaluateScript */
static void *g_orig_eval = NULL;
static void eval_hook(uint64_t ctx, uint64_t script, uint64_t thisObj, uint64_t srcURL, uint64_t line, uint64_t exc) {
    uint64_t n = __atomic_add_fetch(&g_api.head, 1, __ATOMIC_SEQ_CST);
    uint64_t h = (n - 1) % API_RING;
    g_api.entries[h].obj = script;
    g_api.entries[h].index = line;
    g_api.entries[h].value = thisObj;
    g_api.entries[h].kind = 4;  /* 4 = eval */
    g_api.entries[h].seq = n;
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t))g_orig_eval)(
        ctx, script, thisObj, srcURL, line, exc);
}

/* the string-text capture: JSValueToStringCopy wraps the result, copies the
   UTF-16 text (the first 128 chars) into the str ring */
static void *g_orig_tostr = NULL;
static void *g_orig_strchars = NULL;
static void *g_orig_strlen = NULL;
static uint64_t tostr_hook(uint64_t ctx, uint64_t value, uint64_t exc) {
    uint64_t result = ((uint64_t (*)(uint64_t, uint64_t, uint64_t))g_orig_tostr)(ctx, value, exc);
    if (result > 0x100000000ULL && result < 0x800000000ULL && g_orig_strchars) {
        const uint16_t *chars = ((const uint16_t *(*)(uint64_t))g_orig_strchars)(result);
        if ((uintptr_t)chars > 0x100000000ULL) {
            uint64_t len = ((uint64_t (*)(uint64_t))g_orig_strlen)(result);
            uint64_t n = __atomic_add_fetch(&g_str.head, 1, __ATOMIC_SEQ_CST);
            uint64_t h = (n - 1) % STR_RING;
            uint64_t cp = len < STR_BUF ? len : STR_BUF;
            g_str.entries[h].len = len;
            g_str.entries[h].seq = n;
            for (uint64_t i = 0; i < cp; i++) g_str.entries[h].chars[i] = chars[i];
        }
    }
    return result;
}

/* the string length: JSStringGetLength - the payload byte-count layer */
static void strlen_hook(uint64_t s) {
    uint64_t n = __atomic_add_fetch(&g_api.head, 1, __ATOMIC_SEQ_CST);
    uint64_t h = (n - 1) % API_RING;
    g_api.entries[h].obj = s;
    g_api.entries[h].index = 0;
    g_api.entries[h].value = 0;
    g_api.entries[h].kind = 5;  /* 5 = strlen */
    g_api.entries[h].seq = n;
    ((void (*)(uint64_t))g_orig_strlen)(s);
}

/* the interpreter entry: llint_entry - the bytecode-dispatch tick counter */
static void *g_orig_llint = NULL;
static void llint_hook(void) {
    uint64_t n = __atomic_add_fetch(&g_api.head, 1, __ATOMIC_SEQ_CST);
    uint64_t h = (n - 1) % API_RING;
    g_api.entries[h].obj = 0;
    g_api.entries[h].index = 0;
    g_api.entries[h].value = 0;
    g_api.entries[h].kind = 6;  /* 6 = llint tick */
    g_api.entries[h].seq = n;
    ((void (*)(void))g_orig_llint)();
}

/* the seven found C++ entry points - the generic pass-through hooks that
   record the first argument registers with their kind tags */
static void *g_orig_cpp[7];
static uint64_t cpp_n = 0;
static void cpp_record(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t kind) {
    cpp_n = __atomic_add_fetch(&g_api.head, 1, __ATOMIC_SEQ_CST);
    uint64_t h = (cpp_n - 1) % API_RING;
    g_api.entries[h].obj = a0;
    g_api.entries[h].index = a1;
    g_api.entries[h].value = a2;
    g_api.entries[h].kind = kind;
    g_api.entries[h].seq = cpp_n;
}
static void cpp_hook0(uint64_t a0, uint64_t a1, uint64_t a2) {
    cpp_record(a0, a1, a2, 0, 7);   /* deleteProperty */
    ((void (*)(uint64_t, uint64_t, uint64_t))g_orig_cpp[0])(a0, a1, a2);
}
static void cpp_hook1(uint64_t a0, uint64_t a1, uint64_t a2, uint64_t a3) {
    cpp_record(a0, a1, a2, a3, 8);  /* getOwnProperty */
    ((void (*)(uint64_t, uint64_t, uint64_t, uint64_t))g_orig_cpp[1])(a0, a1, a2, a3);
}
static void cpp_hook2(uint64_t a0, uint64_t a1) {
    cpp_record(a0, a1, 0, 0, 9);    /* getByIndex */
    ((void (*)(uint64_t, uint64_t))g_orig_cpp[2])(a0, a1);
}
static void cpp_hook3(uint64_t a0, uint64_t a1) {
    cpp_record(a0, a1, 0, 0, 10);   /* getProperty */
    ((void (*)(uint64_t, uint64_t))g_orig_cpp[3])(a0, a1);
}
static void cpp_hook4(uint64_t a0) {
    cpp_record(a0, 0, 0, 0, 11);    /* toObject */
    ((void (*)(uint64_t))g_orig_cpp[4])(a0);
}
static void cpp_hook5(uint64_t a0, uint64_t a1) {
    cpp_record(a0, a1, 0, 0, 12);   /* JSString::create */
    ((void (*)(uint64_t, uint64_t))g_orig_cpp[5])(a0, a1);
}
static void cpp_hook6(uint64_t a0, uint64_t a1) {
    cpp_record(a0, a1, 0, 0, 13);   /* JSGlobalObject::get */
    ((void (*)(uint64_t, uint64_t))g_orig_cpp[6])(a0, a1);
}

/* ---- the proven hook machinery ---- */
static int make_rw(void *addr, size_t len) {
    vm_address_t page = (vm_address_t)((uintptr_t)addr & ~0x3FFFULL);
    vm_size_t size = (((uintptr_t)addr + len - page + 0x3FFF) & ~0x3FFFULL);
    return vm_protect(mach_task_self(), page, size, 0,
                      VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY) == KERN_SUCCESS;
}

static void *build_trampoline(void *src) {
    /* the relocation-aware trampoline: copies up to 6 instructions, relocating
       the PC-relative forms (the adrp, b/bl, cbz/tbz, the literal ldr), then
       the absolute jump to the remainder. */
    void *mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (mem == MAP_FAILED) return NULL;
    uint32_t *p = (uint32_t *)src;
    uint64_t src_addr = (uint64_t)(uintptr_t)src;
    uint64_t dst_addr = (uint64_t)(uintptr_t)mem;
    uint32_t *t = (uint32_t *)mem;
    int n = 0;
    for (int i = 0; i < 6; i++) {
        uint32_t insn = p[i];
        uint32_t out = insn;
        if ((insn & 0x9F000000u) == 0x90000000u) {
            /* adrp */
            int64_t immlo = (insn >> 29) & 0x3;
            int64_t immhi = (insn >> 5) & 0x7FFFF;
            int64_t imm = (immhi << 2) | immlo;
            if (imm & 0x100000) imm -= 0x200000;
            uint64_t target_page = (src_addr & ~0xFFFULL) + ((uint64_t)imm << 12);
            uint64_t dst_page = (dst_addr + (uint64_t)i * 4) & ~0xFFFULL;
            int64_t new_imm = ((int64_t)target_page - (int64_t)dst_page) >> 12;
            out = 0x90000000u | (((uint32_t)new_imm & 0x3) << 29) |
                  ((((uint32_t)new_imm >> 2) & 0x7FFFF) << 5) | (insn & 0x1Fu);
        } else if ((insn & 0xFC000000u) == 0x14000000u ||
                   (insn & 0xFC000000u) == 0x94000000u) {
            /* b / bl */
            int64_t imm = (int64_t)(insn << 6) >> 4;
            uint64_t target = src_addr + (uint64_t)i * 4 + (uint64_t)imm;
            int64_t new_imm = ((int64_t)target - (int64_t)(dst_addr + (uint64_t)i * 4)) >> 2;
            out = (insn & 0xFC000000u) | ((uint32_t)new_imm & 0x03FFFFFFu);
        } else if ((insn & 0x7E000000u) == 0x34000000u ||
                   (insn & 0x7E000000u) == 0x36000000u) {
            /* cbz/cbnz/tbz/tbnz */
            int64_t imm = (int64_t)((insn >> 5) & 0x7FFFF) << 2;
            uint64_t target = src_addr + (uint64_t)i * 4 + (uint64_t)imm;
            int64_t new_imm = ((int64_t)target - (int64_t)(dst_addr + (uint64_t)i * 4)) >> 2;
            out = (insn & 0xFF00001Fu) | (((uint32_t)new_imm & 0x7FFFF) << 5);
        } else if ((insn & 0x3B000000u) == 0x18000000u) {
            /* ldr (literal): the relocate; the out-of-18-bit-range becomes the
               adrp + the ldr pair (the two-slot rewrite) */
            int64_t imm = (int64_t)((insn >> 5) & 0x7FFFF) << 2;
            uint64_t lit_base = (src_addr + (uint64_t)i * 4) & ~0x3ULL;
            uint64_t target = lit_base + (uint64_t)imm;
            int64_t new_imm = ((int64_t)target - (int64_t)((dst_addr + (uint64_t)i * 4) & ~0x3ULL)) >> 2;
            if (new_imm < -(1 << 18) || new_imm >= (1 << 18)) {
                uint32_t rd = insn & 0x1Fu;
                uint64_t lit_page = target & ~0xFFFULL;
                int64_t page_delta = ((int64_t)lit_page - (int64_t)((dst_addr + (uint64_t)i * 4) & ~0xFFFULL)) >> 12;
                t[i] = 0x90000000u | (((uint32_t)page_delta & 0x3) << 29) |
                       ((((uint32_t)page_delta >> 2) & 0x7FFFF) << 5) | rd;
                i++;
                if (i >= 6) { munmap(mem, 4096); return NULL; }
                uint32_t ldr_imm = (uint32_t)((target - lit_page) >> 2);
                t[i] = (insn & 0xFF00001Fu) | ((ldr_imm & 0x7FFFF) << 5);
                n = i + 1;
                continue;
            }
            out = (insn & 0xFF00001Fu) | (((uint32_t)new_imm & 0x7FFFF) << 5);
        }
        t[i] = out;
        n = i + 1;
        if ((insn & 0xFC000000u) == 0x14000000u || (insn & 0xFC000000u) == 0x94000000u) break;
        if (i >= 3) break;
    }
    t[n] = 0x58000050;
    t[n + 1] = 0xD61F0200;
    *(uint64_t *)((char *)mem + (uint64_t)n * 4 + 8) = (uint64_t)((char *)src + n * 4);
    mprotect(mem, 4096, PROT_READ | PROT_EXEC);
    sys_icache_invalidate(mem, 4096);
    return mem;
}

static int needs_relocation(uint32_t insn) {
    if ((insn & 0x1f000000u) == 0x10000000u) return 1;
    if ((insn & 0x3b000000u) == 0x18000000u) return 1;
    if ((insn & 0x7c000000u) == 0x14000000u) return 1;
    if ((insn & 0xff000010u) == 0x54000000u) return 1;
    if ((insn & 0x7e000000u) == 0x34000000u) return 1;
    if ((insn & 0x7e000000u) == 0x36000000u) return 1;
    return 0;
}

static void *follow_thunk(void *fn) {
    /* the arm64 GOT veneer: adrp x16, page; ldr x16, [x16, #imm]; br x16
       (the standard exported-symbol stub). Returns the real body pointer. */
    uint32_t *p = (uint32_t *)fn;
    if ((p[0] & 0x9F000000u) == 0x90000000u &&
        (p[1] & 0xFFC00000u) == 0xF9400000u &&
        (p[2] & 0xFFFFFC1Fu) == 0xD61F0000u) {
        int64_t immlo = (int64_t)((p[0] >> 29) & 0x3);
        int64_t immhi = (int64_t)((p[0] >> 5) & 0x7FFFF);
        int64_t imm = (immhi << 2) | immlo;
        if (imm & 0x100000) imm -= 0x200000;   /* sign-extend 21 bits */
        uint64_t base = ((uint64_t)(uintptr_t)p & ~0xFFFULL) + ((uint64_t)imm << 12);
        uint64_t off = (uint64_t)((p[1] >> 10) & 0xFFF) << 3;
        void *target = *(void **)(uintptr_t)(base + off);
        return target ? target : fn;
    }
    return fn;
}

__attribute__((constructor)) static void init(void) {
    /* the symbol probe: which write-path entries exist on this JSC build.
       The found names are written to /tmp/jsc_syms.txt for the outside
       reader; the header keeps the count. */
    static const char *cands[] = {
        "_ZN3JSC8JSObject10putByIndexEPNS_6JSCellEPNS_14JSGlobalObjectEjNS_7JSValueEb",
        "_ZN3JSC8JSObject11putByIndexEPNS_14JSGlobalObjectEjNS_7JSValueEb",
        "_ZN3JSC8JSObject3putEPNS_6JSCellEPNS_14JSGlobalObjectENS_10PropertyNameENS_7JSValueERNS_15PutPropertySlotE",
        "_ZN3JSC8JSObject3putEPNS_6JSCellEPNS_14JSGlobalObjectENS_10IdentifierENS_7JSValueERNS_15PutPropertySlotE",
        "_ZN3JSC7JSArray4pushEPNS_14JSGlobalObjectEPS0_NS_7JSValueE",
        "_ZN3JSC7JSArray4pushEPNS_14JSGlobalObjectENS_7JSValueE",
        "_ZN3JSC17JSArrayBufferView10putByIndexEPNS_6JSCellEPNS_14JSGlobalObjectEjNS_7JSValueEb",
        "_ZN3JSC8JSObject12putDirectOffsetEPNS_14JSGlobalObjectEiNS_7JSValueE",
        "_ZN3JSC8JSObject15putDirectInternalILNS_15PutDirectModeEKNS_14JSGlobalObjectEEEbPS0_NS_10PropertyNameENS_7JSValuEjPNS_20PutPropertySlotE",
        "_ZN3JSC8JSObject15initializeIndexEPNS_14JSGlobalObjectEjNS_7JSValueE",
        "_ZN3JSC8JSObject15initializeIndexEPNS_14JSGlobalObjectEjNS_7JSValueEb",
        "_ZN3JSC8JSObject14defineOwnPropertyEPNS_14JSGlobalObjectENS_10PropertyNameENS_7JSValueERNS_18PropertyDescriptorEb",
        "_ZN3JSC8JSObject19getOwnPropertySlotEPNS_6JSCellEPNS_14JSGlobalObjectENS_10PropertyNameERNS_12PropertySlotE",
        "_ZN3JSC8JSObject26getOwnPropertySlotByIndexEPS0_PNS_14JSGlobalObjectEjRNS_12PropertySlotE",
        "_ZN3JSC8JSObject3getEPNS_14JSGlobalObjectENS_10PropertyNameE",
        "_ZN3JSC8JSObject4callEPNS_14JSGlobalObjectERKNS_8CallDataENS_7JSValueERKNS_7ArgListE",
        "_ZN3JSC10JSFunction4callEPNS_14JSGlobalObjectERKNS_8CallDataENS_7JSValueERKNS_7ArgListE",
        "_ZN3JSC12Interpreter7executeEPNS_14JSGlobalObjectEPNS_14ProgramExecutableEPNS_8JSObjectEPNS_7JSValueE",
        "llint_entry",
        "_ZN3JSC8JSObject13deletePropertyEPNS_6JSCellEPNS_14JSGlobalObjectENS_10PropertyNameE",
        "_ZN3JSC8JSObject14getOwnPropertyEPNS_6JSCellEPNS_14JSGlobalObjectENS_10PropertyNameERNS_18PropertyDescriptorE",
        "_ZN3JSC8JSObject11getByIndexEPNS_14JSGlobalObjectEj",
        "_ZN3JSC8JSObject11getPropertyEPNS_14JSGlobalObjectERKNS_10IdentifierE",
        "_ZN3JSC7JSValue11toObjectEPNS_14JSGlobalObjectE",
        "_ZN3JSC8JSString6createEPNS_14JSGlobalObjectERKN3WTF6StringE",
        "_ZN3JSC14JSGlobalObject3getEPNS_14JSGlobalObjectERKNS_10IdentifierE",
        /* the public C API (the plain C exports - the embedding layer) */
        "JSObjectGetPropertyAtIndex",
        "JSObjectSetPropertyAtIndex",
        "JSObjectGetProperty",
        "JSObjectSetProperty",
        "JSEvaluateScript",
        "JSObjectCallAsFunction",
        "JSValueGetType",
        "JSObjectMakeArray",
        "JSContextGetGlobalObject",
        "JSObjectGetPrivate",
        "JSObjectMake",
        "JSValueMakeString",
        "JSValueToStringCopy",
        "JSStringGetLength",
        "JSStringGetCharactersPtr",
        "JSGlobalContextCreate",
        "JSObjectGetArrayBufferBackingStore",
    };
    FILE *sf = NULL;
    {
        char spath[64];
        snprintf(spath, sizeof(spath), "/tmp/jsc_syms_%d.txt", getpid());
        sf = fopen(spath, "w");
    }
    int found = 0;
    uint64_t mask = 0;
    for (unsigned i = 0; i < sizeof(cands) / sizeof(cands[0]); i++) {
        void *a = dlsym(RTLD_DEFAULT, cands[i]);
        if (sf) { fprintf(sf, "%s %s\n", cands[i], a ? "FOUND" : "-"); fflush(sf); }
        if (a) { found++; mask |= (1ULL << i); }
    }
    if (sf) fclose(sf);
    g_hdr.syms_mask = mask;
    g_hdr.syms_count = (uint64_t)found;

    void *pb = dlsym(RTLD_DEFAULT,
        "_ZN3JSC8JSObject10putByIndexEPNS_6JSCellEPNS_14JSGlobalObjectEjNS_7JSValueEb");
    if (!pb) pb = dlsym(RTLD_DEFAULT,
        "_ZN3JSC8JSObject11putByIndexEPNS_14JSGlobalObjectEjNS_7JSValueEb");
    if (!pb) { g_hdr.armed = 0; return; }
    g_putby_addr = (uint64_t)(uintptr_t)pb;
    uint32_t *p = (uint32_t *)pb;
    for (int i = 0; i < 4; i++)
        if (needs_relocation(p[i])) { g_hdr.armed = 2; return; }
    void *tramp = build_trampoline(pb);
    if (!tramp) { g_hdr.armed = 3; return; }
    g_orig_put = tramp;
    if (!make_rw(pb, 16)) { g_hdr.armed = 4; return; }
    p[0] = 0x58000050;
    p[1] = 0xD61F0200;
    *(uint64_t *)((char *)pb + 8) = (uint64_t)(uintptr_t)&put_hook;
    sys_icache_invalidate(pb, 16);
    vm_address_t page = (vm_address_t)((uintptr_t)pb & ~0x3FFFULL);
    vm_protect(mach_task_self(), page, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
    g_hdr.armed = 1;

    /* the second entry: JSArray::push - the append path (the 7 negative
       record-head cells are array appends, not indexed puts). */
    void *pp = dlsym(RTLD_DEFAULT,
        "_ZN3JSC7JSArray4pushEPNS_14JSGlobalObjectENS_7JSValueE");
    if (!pp)
        pp = dlsym(RTLD_DEFAULT,
            "_ZN3JSC7JSArray4pushEPNS_14JSGlobalObjectEPS0_NS_7JSValueE");
    if (pp) {
        g_hdr.push_status = 1;
        pp = follow_thunk(pp);
        uint32_t *q = (uint32_t *)pp;
        if (1) {
            g_hdr.push_status = 2;
            void *t2 = build_trampoline(pp);
            if (t2) {
                g_hdr.push_status = 3;
                if (make_rw(pp, 16)) {
                    g_orig_push = t2;
                    q[0] = 0x58000050;
                    q[1] = 0xD61F0200;
                    *(uint64_t *)((char *)pp + 8) = (uint64_t)(uintptr_t)&push_hook;
                    sys_icache_invalidate(pp, 16);
                    vm_address_t pg2 = (vm_address_t)((uintptr_t)pp & ~0x3FFFULL);
                    vm_protect(mach_task_self(), pg2, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
                    g_hdr.push_status = 4;
                    g_hdr.armed |= (1ULL << 40);
                }
            }
        }
    }

    /* the C-API indexed get (the 4-arg) + the set (the 5-arg) */
    {
        static const char *gsym = "JSObjectGetPropertyAtIndex";
        static const char *ssym = "JSObjectSetPropertyAtIndex";
        void *gp = dlsym(RTLD_DEFAULT, gsym);
        void *sp = dlsym(RTLD_DEFAULT, ssym);
        if (gp) {
            uint32_t *q = (uint32_t *)gp;
            if (1) {
                void *t = build_trampoline(gp);
                if (t && make_rw(gp, 16)) {
                    g_orig_apiget = t;
                    q[0] = 0x58000050;
                    q[1] = 0xD61F0200;
                    *(uint64_t *)((char *)gp + 8) = (uint64_t)(uintptr_t)&apiget_hook;
                    sys_icache_invalidate(gp, 16);
                    vm_address_t pg = (vm_address_t)((uintptr_t)gp & ~0x3FFFULL);
                    vm_protect(mach_task_self(), pg, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
                    g_hdr.armed |= (1ULL << 41);
                }
            }
        }
        if (sp) {
            uint32_t *q = (uint32_t *)sp;
            if (1) {
                void *t = build_trampoline(sp);
                if (t && make_rw(sp, 16)) {
                    g_orig_apiset = t;
                    q[0] = 0x58000050;
                    q[1] = 0xD61F0200;
                    *(uint64_t *)((char *)sp + 8) = (uint64_t)(uintptr_t)&apiset_hook;
                    sys_icache_invalidate(sp, 16);
                    vm_address_t pg = (vm_address_t)((uintptr_t)sp & ~0x3FFFULL);
                    vm_protect(mach_task_self(), pg, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
                    g_hdr.armed |= (1ULL << 42);
                }
            }
        }

        /* the array-literal store path (the keysched keystream blocks) */
        {
            static const char *iisyms[2] = {
                "_ZN3JSC8JSObject15initializeIndexEPNS_14JSGlobalObjectEjNS_7JSValueE",
                "_ZN3JSC8JSObject15initializeIndexEPNS_14JSGlobalObjectEjNS_7JSValueEb"
            };
            void *ii = NULL;
            for (int i = 0; i < 2 && !ii; i++) ii = dlsym(RTLD_DEFAULT, iisyms[i]);
            if (ii) {
                void *t = build_trampoline(ii);
                if (t && make_rw(ii, 16)) {
                    g_orig_initidx = t;
                    uint32_t *q = (uint32_t *)ii;
                    q[0] = 0x58000050;
                    q[1] = 0xD61F0200;
                    *(uint64_t *)((char *)ii + 8) = (uint64_t)(uintptr_t)&initidx_hook;
                    sys_icache_invalidate(ii, 16);
                    vm_address_t pg = (vm_address_t)((uintptr_t)ii & ~0x3FFFULL);
                    vm_protect(mach_task_self(), pg, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
                    g_hdr.armed |= (1ULL << 47);
                }
            }
        }

        /* the named-put capture (the t.X re-key write) */
        {
            static const char *pnsyms[2] = {
                "_ZN3JSC8JSObject3putEPNS_6JSCellEPNS_14JSGlobalObjectENS_10PropertyNameENS_7JSValueERNS_15PutPropertySlotE",
                "_ZN3JSC8JSObject3putEPNS_6JSCellEPNS_14JSGlobalObjectENS_10IdentifierENS_7JSValueERNS_15PutPropertySlotE"
            };
            void *pn = NULL;
            for (int i = 0; i < 2 && !pn; i++) pn = dlsym(RTLD_DEFAULT, pnsyms[i]);
            if (pn) {
                void *t = build_trampoline(pn);
                if (t && make_rw(pn, 16)) {
                    g_orig_put_named = t;
                    uint32_t *q = (uint32_t *)pn;
                    q[0] = 0x58000050;
                    q[1] = 0xD61F0200;
                    *(uint64_t *)((char *)pn + 8) = (uint64_t)(uintptr_t)&put_named_hook;
                    sys_icache_invalidate(pn, 16);
                    vm_address_t pg = (vm_address_t)((uintptr_t)pn & ~0x3FFFULL);
                    vm_protect(mach_task_self(), pg, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
                    g_hdr.armed |= (1ULL << 48);
                }
            }
        }

        /* the four deeper hooks: the call, the eval, the strlen, the llint */
        static const char *cnames[4] = {
            "JSObjectCallAsFunction", "JSEvaluateScript", "JSStringGetLength", "llint_entry"
        };
        void *caddrs[4] = { NULL, NULL, NULL, NULL };
        uint64_t cbits[4] = { (1ULL << 43), (1ULL << 44), (1ULL << 45), (1ULL << 46) };
        void *chooks[4] = {
            (void *)&callfn_hook, (void *)&eval_hook, (void *)&strlen_hook, (void *)&llint_hook
        };
        void **corigs[4] = { &g_orig_callfn, &g_orig_eval, &g_orig_strlen, &g_orig_llint };
        for (int i = 0; i < 4; i++) {
            caddrs[i] = dlsym(RTLD_DEFAULT, cnames[i]);
            if (caddrs[i]) caddrs[i] = follow_thunk(caddrs[i]);
            if (!caddrs[i]) continue;
            uint32_t *q = (uint32_t *)caddrs[i];
                        void *t = build_trampoline(caddrs[i]);
            if (!t || !make_rw(caddrs[i], 16)) continue;
            *corigs[i] = t;
            q[0] = 0x58000050;
            q[1] = 0xD61F0200;
            *(uint64_t *)((char *)caddrs[i] + 8) = (uint64_t)(uintptr_t)chooks[i];
            sys_icache_invalidate(caddrs[i], 16);
            vm_address_t pg = (vm_address_t)((uintptr_t)caddrs[i] & ~0x3FFFULL);
            vm_protect(mach_task_self(), pg, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
            g_hdr.armed |= cbits[i];
        }

        /* the seven C++ entry hooks */
        static const char *cppnames[7] = {
            "_ZN3JSC8JSObject13deletePropertyEPNS_6JSCellEPNS_14JSGlobalObjectENS_10PropertyNameE",
            "_ZN3JSC8JSObject14getOwnPropertyEPNS_6JSCellEPNS_14JSGlobalObjectENS_10PropertyNameERNS_18PropertyDescriptorE",
            "_ZN3JSC8JSObject11getByIndexEPNS_14JSGlobalObjectEj",
            "_ZN3JSC8JSObject11getPropertyEPNS_14JSGlobalObjectERKNS_10IdentifierE",
            "_ZN3JSC7JSValue11toObjectEPNS_14JSGlobalObjectE",
            "_ZN3JSC8JSString6createEPNS_14JSGlobalObjectERKN3WTF6StringE",
            "_ZN3JSC14JSGlobalObject3getEPNS_14JSGlobalObjectERKNS_10IdentifierE",
        };
        /* the resolution: the RTLD_DEFAULT misses some (the dependent-image
           ordering); the explicit handle resolves them */
        void *jsc_handle = dlopen(
            "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore",
            RTLD_NOLOAD | RTLD_GLOBAL);
        void *cpphooks[7] = {
            (void *)&cpp_hook0, (void *)&cpp_hook1, (void *)&cpp_hook2,
            (void *)&cpp_hook3, (void *)&cpp_hook4, (void *)&cpp_hook5,
            (void *)&cpp_hook6
        };
        uint64_t cppbits[7] = { (1ULL << 47), (1ULL << 48), (1ULL << 49), (1ULL << 50),
                                (1ULL << 51), (1ULL << 52), (1ULL << 53) };
        for (int i = 0; i < 7; i++) {
            void *a = dlsym(RTLD_DEFAULT, cppnames[i]);
            if (!a && jsc_handle) a = dlsym(jsc_handle, cppnames[i]);
            uint64_t st = 0;
            if (a) {
                a = follow_thunk(a);
                st = 1;
                void *t = build_trampoline(a);
                if (!t) st = 2;
                else if (!make_rw(a, 16)) st = 3;
                else {
                    st = 4;
                    g_orig_cpp[i] = t;
                    uint32_t *q = (uint32_t *)a;
                    q[0] = 0x58000050;
                    q[1] = 0xD61F0200;
                    *(uint64_t *)((char *)a + 8) = (uint64_t)(uintptr_t)cpphooks[i];
                    sys_icache_invalidate(a, 16);
                    vm_address_t pg2 = (vm_address_t)((uintptr_t)a & ~0x3FFFULL);
                    vm_protect(mach_task_self(), pg2, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
                    g_hdr.armed |= cppbits[i];
                }
            }
            g_hdr.dbg8[i] = st;
        }
        /* the llint status = the dbg8[7] */
        {
            void *a = dlsym(RTLD_DEFAULT, "llint_entry");
            if (!a && jsc_handle) a = dlsym(jsc_handle, "llint_entry");
            uint64_t st = 0;
            if (a) {
                a = follow_thunk(a);
                st = 1;
                void *t = build_trampoline(a);
                if (!t) st = 2;
                else if (!make_rw(a, 16)) st = 3;
                else {
                    st = 4;
                    g_orig_llint = t;
                    uint32_t *q = (uint32_t *)a;
                    q[0] = 0x58000050;
                    q[1] = 0xD61F0200;
                    *(uint64_t *)((char *)a + 8) = (uint64_t)(uintptr_t)&llint_hook;
                    sys_icache_invalidate(a, 16);
                    vm_address_t pg2 = (vm_address_t)((uintptr_t)a & ~0x3FFFULL);
                    vm_protect(mach_task_self(), pg2, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
                    g_hdr.armed |= (1ULL << 46);
                }
            }
            g_hdr.dbg8[7] = st;
        }

        /* the string-text capture: JSValueToStringCopy + JSStringGetCharactersPtr */
        {
            void *a = dlsym(RTLD_DEFAULT, "JSValueToStringCopy");
            void *b = dlsym(RTLD_DEFAULT, "JSStringGetCharactersPtr");
            if (a && b) {
                void *t = build_trampoline(a);
                if (t && make_rw(a, 16)) {
                    g_orig_tostr = t;
                    g_orig_strchars = b;
                    uint32_t *q = (uint32_t *)a;
                    q[0] = 0x58000050;
                    q[1] = 0xD61F0200;
                    *(uint64_t *)((char *)a + 8) = (uint64_t)(uintptr_t)&tostr_hook;
                    sys_icache_invalidate(a, 16);
                    vm_address_t pg = (vm_address_t)((uintptr_t)a & ~0x3FFFULL);
                    vm_protect(mach_task_self(), pg, 0x4000, 0, VM_PROT_READ | VM_PROT_EXECUTE);
                    g_hdr.armed |= (1ULL << 54);
                }
            }
        }
    }
}
