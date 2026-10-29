// HwbpHelper.dll — in-process HWBP capture for R6 external cheat.
//
// Purpose:
//   R6's post-2026-08-04 anti-tamper self-terminates when the external
//   pokes .text with a code-cave JMP.  This DLL runs INSIDE R6 (loaded
//   via manual map from the external / injector), uses a hardware
//   breakpoint (DR0) at actor_update entry to capture the per-actor
//   pointer in RCX with ZERO byte modifications.  Captured pointers are
//   written to a named shared-memory ring buffer that the external
//   process reads back.
//
// Load-time init:
//   1. Locate R6.exe base + verify actor_update prologue at RVA
//      0x53F9850 (fallback: scan .text for the prologue bytes).
//   2. Create / open shared memory:  Global\OmnisActorRing
//   3. Install VEH for EXCEPTION_SINGLE_STEP.
//   4. Snapshot all R6 threads, SetThreadContext to set DR0 = actor_fn.
//   5. Spawn refresh thread — re-applies DR0 to newly spawned R6 threads
//      every 2 s.  Cheap: <100 threads * 1 SetThreadContext each.
//
// VEH callback:
//   * Check EXCEPTION_SINGLE_STEP + DR6.B0 + RIP == actor_fn (own DR0).
//   * Read RCX (Windows fastcall 1st arg = Actor*).
//   * InterlockedIncrement head, store RCX at ring->data[head % SLOTS].
//   * Clear DR6, set EFlags.RF (so the same instruction doesn't re-fire
//     on resume — RF auto-clears after one instruction), return
//     EXCEPTION_CONTINUE_EXECUTION.
//
// Detection surface:
//   Zero R6 .text bytes modified.  Debug registers per-thread only.
//   R6 could enumerate its own thread contexts and see non-zero DR0
//   but that's a much less common check than byte scanning, and not
//   what's currently killing the external.

#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <atomic>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <intrin.h>
#include <unordered_set>
#include <vector>

// ── Config ────────────────────────────────────────────────────────────
// We set DR0 at fn+0xB0 (the LOCK INC after `alloc → test rax → mov rbp,rax`).
// The AI's re-derive confirmed the actor pointer is in RAX at that moment.
// Setting DR0 at function ENTRY captures RCX, which is the caller's `this`
// (manager pointer, constant across all calls) — useless as an actor
// pointer.
// Post-2026-08-XX patch: actor_update moved + entire fn body restructured.
// No more LOCK INC on r13/r14/r15 in the fn body — the closest analog is
// LOCK INC [rax+8] at fn+0xF71 where RAX holds the actor pointer.
static constexpr uint64_t kActorFnRVA        = 0x24DF41CULL;   // new fn start
static constexpr uint64_t kBpSiteRVA         = 0x24E038DULL;   // fn+0xF71 = LOCK INC [rax+8]
static constexpr size_t   kRingSlots         = 4096;
// SAFE-MODE: skip HWBP, poll a static global that R6 writes the current
// actor into (from MOV [rip+G], r8 at fn+0x2C6).  Zero DR usage, zero
// VEH — pure read every 8 ms.  Set to 0 to fall back to HWBP path.
static constexpr uint64_t kActorGlobalRVA    = 0x11881168ULL;
#define HWBP_SAFE_MODE 1
static const char*        kSharedMemName     = "Local\\OmnisActorRing";
static const wchar_t*     kR6ModuleName      = L"RainbowSix.exe";
// Prologue verification skipped this build — AI-reported prologue starts with
// XMM saves + SUB RSP 0x218 but exact byte sequence not captured.  Instead
// we verify by BP site bytes only.
// Expected 5 bytes at bp site: F0 48 FF 40 08 = lock inc qword ptr [rax + 8]
static const uint8_t kBpSitePrefix[3] = { 0xF0, 0x48, 0xFF };

// ── Shared memory layout ─────────────────────────────────────────────
// SPSC ring.  Producer: this DLL (single writer thread == R6 game
// thread that calls actor_update).  Consumer: the external process.
// Consumer never writes head; producer never writes tail.
// Camera state — populated by CameraPublisherThread which scans R6's
// heap in-process (no RPM/driver, so BE-safe) for the view-block anchor,
// then reads cam_pos + world→clip matrix every 8 ms and writes here.
// External uses seq (odd during write / even after write) to detect
// torn reads: reader takes s1, reads cam, takes s2 — retry if s1 != s2
// or s1 is odd.
struct SharedCameraState {
    volatile uint32_t seq;             // increments twice per publish (pre/post)
    uint32_t          valid;           // 1 = ever populated
    float             cam_pos[3];      // 12
    float             _pad;            // 4 (align matrix on 16 B)
    float             matrix[16];      // 64 (row-major world→clip, translation baked)
    uint64_t          view_block_va;   // for diagnostics
    uint64_t          last_write_ms;
    // External→DLL: set to non-zero to trigger an immediate entity-list
    // back-trace scan (instead of waiting for 30 s periodic).  DLL clears
    // to 0 when scan completes.  Layout kept trailing so field can be
    // added without breaking older-version alignment checks.
    volatile uint32_t entlist_scan_trigger;
    uint32_t          _pad2;
};
static_assert(sizeof(SharedCameraState) == 4+4+12+4+64+8+8+4+4, "cam layout");

struct SharedActorRing {
    volatile uint32_t head;         // producer-owned, monotonic
    volatile uint32_t tail;         // consumer-owned, monotonic
    uint32_t          slot_count;   // = kRingSlots
    uint32_t          version;      // 3 = includes cam block
    uint64_t          producer_pid; // R6 PID (for consumer sanity)
    uint64_t          install_ms;   // GetTickCount64 when producer init'd
    uint64_t          total_writes; // debug counter
    uint64_t          _pad;
    // Diagnostic sample — VEH overwrites every N fires, no file I/O
    volatile uint64_t sample_seq;
    uint64_t          sample_rax;
    uint64_t          sample_rbp;
    uint64_t          sample_r13;
    uint64_t          sample_r14;
    uint64_t          sample_r15;
    uint64_t          sample_rip;
    uint64_t          _pad2;
    // BE-safe camera state — DLL scans + publishes, external reads.
    SharedCameraState cam;
    uint64_t          data[kRingSlots];  // actor pointers
};
// Header = 4*u32 (16) + 4*u64 (32) + 8*u64 sample (64) + 112 cam = 224 bytes
static_assert(sizeof(SharedActorRing) == 224 + kRingSlots * 8,
              "SharedActorRing layout drift");

// ── State ────────────────────────────────────────────────────────────
static SharedActorRing* g_ring          = nullptr;
static HANDLE           g_map           = nullptr;
static uint64_t         g_actor_fn      = 0;   // fn start (diagnostic)
static uint64_t         g_bp_site       = 0;   // VA of the LOCK INC we watch
static PVOID            g_veh           = nullptr;
static HANDLE           g_refresh_thd   = nullptr;
static std::atomic<bool> g_running{false};

// ── Simple file log for early-attach diagnostics ─────────────────────
// Runs before ring is ready; writes to C:\ProgramData\r6_hwbp.log.
static void HLog(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    FILE* f = nullptr;
    fopen_s(&f, "C:\\ProgramData\\r6_hwbp.log", "a");
    if (!f) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    fprintf(f, "[%02u:%02u:%02u.%03u T%u] %s\n",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
            GetCurrentThreadId(), buf);
    fclose(f);
}

// ── Locate actor_update entry ─────────────────────────────────────────
// Post-patch: exact prologue bytes not captured, so we verify the BP site
// bytes at kBpSiteRVA (fn+0xF71) instead — if F0 48 FF match, we're good.
static uint64_t LocateActorFn() {
    HMODULE r6 = GetModuleHandleW(kR6ModuleName);
    if (!r6) {
        HLog("[locate] R6 module not found");
        return 0;
    }
    uint64_t base = (uint64_t)r6;
    uint64_t fn_va = base + kActorFnRVA;
    uint64_t bp_va = base + kBpSiteRVA;

    __try {
        const uint8_t* bp = (const uint8_t*)bp_va;
        if (bp[0] == kBpSitePrefix[0] &&
            bp[1] == kBpSitePrefix[1] &&
            bp[2] == kBpSitePrefix[2])
        {
            HLog("[locate] actor_fn = 0x%llX  BP site = 0x%llX  "
                 "(RVAs 0x%llX / 0x%llX, BP prefix F0 48 FF verified)",
                 fn_va, bp_va, kActorFnRVA, kBpSiteRVA);
            return fn_va;
        }
        HLog("[locate] BP site prefix mismatch at 0x%llX  got %02X %02X %02X  "
             "want F0 48 FF — RVA is stale, needs re-derive",
             bp_va, bp[0], bp[1], bp[2]);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        HLog("[locate] fault reading BP site at 0x%llX", bp_va);
    }
    return 0;
}

// ── Shared memory setup ──────────────────────────────────────────────
static bool CreateSharedRing(DWORD r6_pid) {
    const size_t sz = sizeof(SharedActorRing);

    // Allow Everyone read/write so the external (any user session) can attach.
    // Using a NULL DACL security descriptor.  Fine for local IPC.
    SECURITY_DESCRIPTOR sd{};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);
    SECURITY_ATTRIBUTES sa{};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    g_map = CreateFileMappingA(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE,
                               0, (DWORD)sz, kSharedMemName);
    if (!g_map) {
        HLog("[shmem] CreateFileMapping failed err=%u", GetLastError());
        return false;
    }
    g_ring = (SharedActorRing*)MapViewOfFile(g_map, FILE_MAP_ALL_ACCESS, 0, 0, sz);
    if (!g_ring) {
        HLog("[shmem] MapViewOfFile failed err=%u", GetLastError());
        CloseHandle(g_map); g_map = nullptr;
        return false;
    }
    // Init header (zero-init the ring data too).
    memset(g_ring, 0, sz);
    g_ring->slot_count   = kRingSlots;
    g_ring->version      = 3;
    g_ring->producer_pid = r6_pid;
    g_ring->install_ms   = GetTickCount64();
    HLog("[shmem] ring @ %p  slots=%u  producer_pid=%u",
         g_ring, kRingSlots, r6_pid);
    return true;
}

// ── VEH callback ─────────────────────────────────────────────────────
static LONG WINAPI HwbpVEH(EXCEPTION_POINTERS* ep) {
    if (!ep || !ep->ExceptionRecord || !ep->ContextRecord)
        return EXCEPTION_CONTINUE_SEARCH;
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    CONTEXT* ctx = ep->ContextRecord;
    // We own only DR0.
    if (!(ctx->Dr6 & 0x1)) return EXCEPTION_CONTINUE_SEARCH;
    // Sanity: RIP should equal our watch address (LOCK INC site).
    if (ctx->Rip != g_bp_site) return EXCEPTION_CONTINUE_SEARCH;

    // Diagnostic sample into shared memory (NO file I/O — file ops from a
    // VEH callback are what killed R6 on shooting-range load; disk write
    // rate matched actor_update fire rate and Windows I/O paths deadlock
    // when interrupted mid-flight).  Update every 500th fire, atomic seq.
    static volatile LONG s_sample_ctr = 0;
    LONG c = InterlockedIncrement(&s_sample_ctr);
    if (g_ring && (c % 500) == 0) {
        g_ring->sample_rax = ctx->Rax;
        g_ring->sample_rbp = ctx->Rbp;
        g_ring->sample_r13 = ctx->R13;
        g_ring->sample_r14 = ctx->R14;
        g_ring->sample_r15 = ctx->R15;
        g_ring->sample_rip = ctx->Rip;
        InterlockedIncrement64((volatile LONG64*)&g_ring->sample_seq);
    }

    // Write RAX to ring (current best guess for actor pointer).
    uint64_t p = ctx->Rax;
    if (p > 0x10000 && (p & 0x7) == 0 && g_ring) {
        uint32_t idx = InterlockedIncrement((volatile LONG*)&g_ring->head) - 1;
        g_ring->data[idx % kRingSlots] = p;
        InterlockedIncrement64((volatile LONG64*)&g_ring->total_writes);
    }

    // Clear DR6 status + set EFlags.RF so the LOCK-prefixed instruction
    // at RIP executes once without re-firing the BP.
    ctx->Dr6 = 0;
    ctx->EFlags |= 0x10000;
    return EXCEPTION_CONTINUE_EXECUTION;
}

// ── Per-thread DR0 apply ─────────────────────────────────────────────
static bool ApplyOne(DWORD tid, uint64_t addr, bool enable) {
    HANDLE hT = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                           THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!hT) return false;
    if (SuspendThread(hT) == (DWORD)-1) { CloseHandle(hT); return false; }
    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    bool ok = false;
    if (GetThreadContext(hT, &ctx)) {
        if (enable) {
            ctx.Dr0 = addr;
            ctx.Dr7 &= ~(0xFULL << 16);  // R/W0=00 (exec), LEN0=00 (1 byte)
            ctx.Dr7 |= 0x1ULL;           // L0
        } else {
            ctx.Dr0 = 0;
            ctx.Dr7 &= ~0x1ULL;
            ctx.Dr7 &= ~(0xFULL << 16);
        }
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (SetThreadContext(hT, &ctx)) ok = true;
    }
    ResumeThread(hT);
    CloseHandle(hT);
    return ok;
}

static int ApplyToAll(uint64_t addr, bool enable) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    THREADENTRY32 te = {}; te.dwSize = sizeof(te);
    DWORD my_pid = GetCurrentProcessId();
    DWORD my_tid = GetCurrentThreadId();
    int applied = 0, seen = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != my_pid) continue;
            if (te.th32ThreadID == my_tid)       continue;
            seen++;
            if (ApplyOne(te.th32ThreadID, addr, enable)) applied++;
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    HLog("[hwbp] %s DR0=0x%llX → %d/%d threads",
         enable ? "ENABLE" : "DISABLE", addr, applied, seen);
    return applied;
}

// Periodic re-apply for threads spawned after install.
static DWORD WINAPI RefreshThread(LPVOID) {
    HLog("[refresh] thread started");
    while (g_running.load()) {
        Sleep(2000);
        if (!g_running.load()) break;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap == INVALID_HANDLE_VALUE) continue;
        THREADENTRY32 te = {}; te.dwSize = sizeof(te);
        DWORD my_pid = GetCurrentProcessId();
        DWORD my_tid = GetCurrentThreadId();
        int patched = 0;
        if (Thread32First(snap, &te)) {
            do {
                if (te.th32OwnerProcessID != my_pid) continue;
                if (te.th32ThreadID == my_tid)       continue;
                HANDLE hT = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                                       THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (!hT) continue;
                if (SuspendThread(hT) == (DWORD)-1) { CloseHandle(hT); continue; }
                CONTEXT ctx = {};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                if (GetThreadContext(hT, &ctx)) {
                    if (ctx.Dr0 != g_bp_site || !(ctx.Dr7 & 0x1)) {
                        ctx.Dr0 = g_bp_site;
                        ctx.Dr7 &= ~(0xFULL << 16);
                        ctx.Dr7 |= 0x1ULL;
                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                        if (SetThreadContext(hT, &ctx)) patched++;
                    }
                }
                ResumeThread(hT);
                CloseHandle(hT);
            } while (Thread32Next(snap, &te));
        }
        CloseHandle(snap);
        if (patched > 0)
            HLog("[refresh] patched %d new/stripped threads", patched);
    }
    HLog("[refresh] thread exiting");
    return 0;
}

// ── Init (called on DLL attach in its own thread) ────────────────────
static DWORD WINAPI InitThread(LPVOID) {
    HLog("=== HwbpHelper.dll init ===  pid=%u", GetCurrentProcessId());

    // Wait briefly for R6 to fully load if we were injected during startup.
    for (int i = 0; i < 100; i++) {
        if (GetModuleHandleW(kR6ModuleName)) break;
        Sleep(50);
    }

    g_actor_fn = LocateActorFn();
    if (g_actor_fn == 0) {
        HLog("[init] ABORT: actor_fn not located");
        return 1;
    }

    if (!CreateSharedRing(GetCurrentProcessId())) {
        HLog("[init] ABORT: shared ring create failed");
        return 1;
    }

#if HWBP_SAFE_MODE
    // MINIMAL MODE — DLL does nothing but publish camera.  No actor
    // discovery (external's fingerprint scanner handles that).  No
    // HWBP.  No entity-list scan.  If R6 STILL crashes with this
    // config, the crash is R6-side (patch instability), not ours.
    g_running.store(true);
    HLog("[init] MINIMAL MODE — camera publisher only, everything else "
         "disabled (bisection build to isolate crash cause)");
#else
    // HWBP path — arm DR0 at BP site, VEH captures RAX.
    g_bp_site = g_actor_fn + (kBpSiteRVA - kActorFnRVA);
    {
        uint8_t buf[5] = {};
        __try {
            memcpy(buf, (const void*)g_bp_site, 5);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            HLog("[init] ABORT: fault reading BP site @ 0x%llX", g_bp_site);
            return 1;
        }
        HLog("[init] BP site @ 0x%llX  bytes: %02X %02X %02X %02X %02X",
             g_bp_site, buf[0], buf[1], buf[2], buf[3], buf[4]);
        if (buf[0] != kBpSitePrefix[0] || buf[1] != kBpSitePrefix[1] ||
            buf[2] != kBpSitePrefix[2] || buf[3] != 0x40 || buf[4] != 0x08)
        {
            HLog("[init] ABORT: BP site shape mismatch — want F0 48 FF 40 08");
            return 1;
        }
        HLog("[init] BP site verified (LOCK INC qword [rax+8])");
    }
    g_veh = AddVectoredExceptionHandler(1, HwbpVEH);
    if (!g_veh) {
        HLog("[init] ABORT: AddVectoredExceptionHandler failed err=%u", GetLastError());
        return 1;
    }
    HLog("[init] VEH installed @ %p", g_veh);
    int n = ApplyToAll(g_bp_site, true);
    if (n == 0) {
        HLog("[init] ABORT: no threads patched — removing VEH");
        RemoveVectoredExceptionHandler(g_veh);
        g_veh = nullptr;
        return 1;
    }
    g_running.store(true);
    g_refresh_thd = CreateThread(nullptr, 0, RefreshThread, nullptr, 0, nullptr);
#endif
    // Camera publisher — the ONLY thread we spawn in MINIMAL MODE.
    // Reads cam_pos + view matrix every 8 ms, writes to g_ring->cam.
    // Entity list scanner + actor polling DISABLED for bisection.
    extern DWORD WINAPI CameraPublisherThread(LPVOID);
    HANDLE cam_thd = CreateThread(nullptr, 0, CameraPublisherThread, nullptr, 0, nullptr);
    if (cam_thd) CloseHandle(cam_thd);
#if HWBP_SAFE_MODE
    HLog("[init] READY — SAFE MODE (actor global poll + cam + entlist "
         "scanner threads up)");
#else
    HLog("[init] READY — DR0 armed on %d threads at 0x%llX (BP site)  "
         "capturing RAX  refresh + cam publisher + entlist scanner threads up",
         n, g_bp_site);
#endif
    return 0;
}

// ── SAFE-MODE actor poller (no HWBP, no VEH) ─────────────────────────
// R6 stores "current actor being processed" into a static global at
// base+kActorGlobalRVA (identified from `MOV [rip+G], r8` at fn+0x2C6).
// We poll it every 8 ms, dedupe against the last N unique values, and
// push into the same ring the HWBP path used.  Downstream code is
// oblivious to which path produced the pointers.
DWORD WINAPI ActorPollThread(LPVOID) {
    HLog("[poll] actor-global poller started");
    HMODULE r6 = GetModuleHandleW(kR6ModuleName);
    if (!r6) {
        HLog("[poll] ABORT: R6 module gone");
        return 1;
    }
    uint64_t global_va = (uint64_t)r6 + kActorGlobalRVA;
    // Small rolling dedupe — same actor pointer often stays valid for
    // many polls in a row; only push when it CHANGES to avoid flooding
    // the ring with dupes.
    uint64_t last_pushed = 0;
    uint64_t push_count  = 0;
    uint64_t poll_count  = 0;
    uint64_t nonzero_count = 0;
    uint64_t last_log_ms = 0;
    while (g_running.load()) {
        poll_count++;
        __try {
            uint64_t v = *(volatile uint64_t*)global_va;
            if (v != 0 && v != last_pushed) {
                nonzero_count++;
                // Basic sanity — has to look like a heap pointer.
                if (v > 0x10000 && (v & 0x7) == 0 && v < 0x00007FFFFFFFFFFFULL) {
                    last_pushed = v;
                    if (g_ring) {
                        uint32_t idx = InterlockedIncrement((volatile LONG*)&g_ring->head) - 1;
                        g_ring->data[idx % kRingSlots] = v;
                        InterlockedIncrement64((volatile LONG64*)&g_ring->total_writes);
                        push_count++;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
        // Periodic health log
        uint64_t now_ms = GetTickCount64();
        if (now_ms - last_log_ms > 10000) {
            last_log_ms = now_ms;
            HLog("[poll] health  polls=%llu  nonzero=%llu  pushed=%llu  "
                 "global_va=0x%llX  last=0x%llX",
                 poll_count, nonzero_count, push_count, global_va, last_pushed);
        }
        Sleep(8);   // ~125 Hz — same rate as HWBP would fire
    }
    HLog("[poll] thread exiting");
    return 0;
}

// ── Camera publisher (BE-safe: all reads are in-process) ─────────────
// Scans R6's heap for the 40-byte view-block anchor pattern (same one
// used by external ViewScan) then reads the 76-byte cam struct
// (+0x190 pos, +0x250 matrix) every 8 ms.  Rescans on the fly if the
// view block address goes stale.
// Post-patch view block: cam_pos + basis vectors (right/up/forward), no
// matrix.  Anchor pattern is 16 bytes (1.0, 1.0, 1.0, 0.0) at vb_pos+0xB0.
// Common pattern — validator below narrows the winner.
// Layout (relative to vb_pos = cam_pos address):
//   vb_pos - 0x30   Vec3 RIGHT
//   vb_pos - 0x20   Vec3 UP
//   vb_pos - 0x10   Vec3 FORWARD
//   vb_pos + 0x00   Vec4 CAM_POS  (world.xyz, w=1)
//   vb_pos + 0xB0   Vec4 (1,1,1,0) ← anchor
static const uint8_t kViewAnchor[16] = {
    0x00, 0x00, 0x80, 0x3F,   // 1.0
    0x00, 0x00, 0x80, 0x3F,   // 1.0
    0x00, 0x00, 0x80, 0x3F,   // 1.0
    0x00, 0x00, 0x00, 0x00,   // 0.0
};
static constexpr int64_t kViewBlockOffFromAnchor = 0xB0;  // vb_pos = anchor - 0xB0
static constexpr int64_t kCamPosOff  = 0x00;
static constexpr int64_t kRightOff   = -0x30;
static constexpr int64_t kUpOff      = -0x20;
static constexpr int64_t kFwdOff     = -0x10;

static uint64_t g_view_block_va = 0;

// Safe-read helper for the validator (used inside __try below).
static bool try_validate_view_block(uint64_t vb) {
    __try {
        // cam_pos as Vec4 — world.xyz + w=1
        float cx = *(float*)(vb + 0x00);
        float cy = *(float*)(vb + 0x04);
        float cz = *(float*)(vb + 0x08);
        float cw = *(float*)(vb + 0x0C);
        if (!(cx == cx && cy == cy && cz == cz && cw == cw)) return false;
        if (fabsf(cx) > 500.f || fabsf(cy) > 500.f || fabsf(cz) > 500.f) return false;
        if (fabsf(cx) + fabsf(cy) + fabsf(cz) < 5.f) return false;
        if (fabsf(cw - 1.0f) > 0.01f) return false;
        // Basis vectors — must be orthonormal (each unit length).
        float r[3], u[3], f[3];
        memcpy(r, (const void*)(vb - 0x30), 12);
        memcpy(u, (const void*)(vb - 0x20), 12);
        memcpy(f, (const void*)(vb - 0x10), 12);
        float rn = r[0]*r[0] + r[1]*r[1] + r[2]*r[2];
        float un = u[0]*u[0] + u[1]*u[1] + u[2]*u[2];
        float fn = f[0]*f[0] + f[1]*f[1] + f[2]*f[2];
        return (0.98f < rn && rn < 1.02f) &&
               (0.98f < un && un < 1.02f) &&
               (0.98f < fn && fn < 1.02f);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Heap scan — pattern is common (three 1.0f + 0.0f), so we need the
// basis-orthonormality validator to pick the winner.  In-process so no
// RPM/driver → BE-safe.
static uint64_t ScanViewBlock() {
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uint8_t* addr = (uint8_t*)0x10000;
    MEMORY_BASIC_INFORMATION mbi{};
    int total_hits = 0, verified_hits = 0;
    uint64_t winner = 0;
    while (addr < (uint8_t*)si.lpMaximumApplicationAddress) {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;
        if (mbi.RegionSize == 0) break;
        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        bool ok = (mbi.State == MEM_COMMIT) &&
                  ((mbi.Protect & PAGE_READWRITE) ||
                   (mbi.Protect & PAGE_EXECUTE_READWRITE)) &&
                  !(mbi.Protect & PAGE_GUARD) &&
                  (mbi.Type == MEM_PRIVATE);
        if (ok && mbi.RegionSize >= sizeof(kViewAnchor)) {
            __try {
                const uint8_t* p   = (const uint8_t*)mbi.BaseAddress;
                const uint8_t* end = p + mbi.RegionSize - sizeof(kViewAnchor);
                for (const uint8_t* q = p; q < end; q += 4) {
                    if (q[0] != kViewAnchor[0]) continue;
                    if (memcmp(q, kViewAnchor, sizeof(kViewAnchor)) != 0) continue;
                    total_hits++;
                    uint64_t va = (uint64_t)q;
                    if (va < kViewBlockOffFromAnchor) continue;
                    uint64_t vb = va - kViewBlockOffFromAnchor;
                    // Guard the validator against faults in a NEW try scope
                    // (this __try is the region-read guard).
                    if (try_validate_view_block(vb)) {
                        verified_hits++;
                        if (!winner) winner = vb;
                    }
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        addr = next;
    }
    if (winner) {
        HLog("[cam] anchor hits=%d  verified=%d  → vb_pos = 0x%llX",
             total_hits, verified_hits, winner);
    } else {
        HLog("[cam] anchor hits=%d  verified=0  (validator rejected all)",
             total_hits);
    }
    return winner;
}

// ── Entity list back-tracer (in-process, BE-safe) ──────────────────
// Given the last N HWBP-captured actor pointers as ground truth, scan
// R6's own heap for arrays that contain 3+ of those known actors as
// adjacent slots.  If we find one, that array IS the entity manager's
// internal actor list — we can iterate it directly with zero HWBP.
//
// For each candidate hit, also validate the surrounding slots: how many
// deref to something with cls==0x2C8 (a real player).  If most do, this
// list holds plaintext actor pointers → free entity discovery.  If the
// slots hold non-pointer-looking qwords that DON'T deref to actors,
// the list may be encrypted (per zoid's approach) — that becomes the
// next reverse-engineering target.
//
// Results logged only; not wired into anything yet.  Diagnostic first.
static uint64_t s_entlist_last_base   = 0;
static int      s_entlist_last_hits   = 0;
static int      s_entlist_last_count  = 0;

static bool LooksLikePlayerActor(uint64_t p) {
    if (p < 0x10000) return false;
    if ((p & 0x7) != 0) return false;
    __try {
        uint64_t fb  = *(uint64_t*)(p + 0xB8);
        uint16_t cls = (uint16_t)((fb >> 52) & 0xFFF);
        return cls == 0x2C8;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Helpers that isolate __try from C++ object unwinding.
// scan_region_for_hits: walks a region, appends any qword position whose
//   value is in known_set AND is surrounded by at least min_hits-1 other
//   known values within ±32 slots.  Returns count of clusters found.
static int scan_region_for_hits(const uint64_t* qw, size_t n,
                                const std::unordered_set<uint64_t>& known_set,
                                int min_hits,
                                uint64_t* out_bases, int* out_hits,
                                int out_cap) {
    int out_n = 0;
    __try {
        for (size_t i = 0; i < n && out_n < out_cap; i++) {
            if (!known_set.count(qw[i])) continue;
            int cnt = 1;
            size_t lo = i > 32 ? i - 32 : 0;
            size_t hi = i + 32 < n ? i + 32 : n;
            for (size_t j = lo; j < hi; j++) {
                if (j == i) continue;
                if (known_set.count(qw[j])) cnt++;
            }
            if (cnt >= min_hits) {
                size_t base_idx = i;
                for (size_t j = lo; j < i; j++) {
                    if (known_set.count(qw[j])) { base_idx = j; break; }
                }
                out_bases[out_n] = (uint64_t)&qw[base_idx];
                out_hits[out_n]  = cnt;
                out_n++;
                i = hi;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    return out_n;
}

// probe_slots: safely read up to 32 slots of a candidate array,
// count how many deref to real players + capture first N raw values.
static void probe_slots(uint64_t base,
                        int* out_slot_players, int* out_slot_derefed,
                        uint64_t* out_sample, int sample_n) {
    *out_slot_players = 0;
    *out_slot_derefed = 0;
    __try {
        const uint64_t* qw = (const uint64_t*)base;
        for (int i = 0; i < 32; i++) {
            uint64_t v = qw[i];
            if (i < sample_n) out_sample[i] = v;
            if (v < 0x10000) continue;
            (*out_slot_derefed)++;
            if (LooksLikePlayerActor(v)) (*out_slot_players)++;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
}

static void ScanForEntityList() {
    // Collect a snapshot of recent HWBP-captured actor pointers to use
    // as ground truth (only ones that STILL look like players today).
    if (!g_ring) return;
    std::vector<uint64_t> known;
    known.reserve(64);
    // Walk the last min(head, 2048) ring entries backward.  head is
    // monotonic-uint32; using modulo indexing avoids the wrap bug where
    // (i != head) never terminated when head - 512 wrapped.
    uint32_t head = g_ring->head;
    uint32_t n_check = head < 2048 ? head : 2048;
    for (uint32_t k = 0; k < n_check; k++) {
        uint32_t slot = (head - 1 - k) % kRingSlots;
        uint64_t p = g_ring->data[slot];
        if (LooksLikePlayerActor(p)) known.push_back(p);
    }
    // Dedupe.
    std::sort(known.begin(), known.end());
    known.erase(std::unique(known.begin(), known.end()), known.end());
    if (known.size() < 3) {
        HLog("[entlist] scan skipped — only %zu known-good actors "
             "(need 3+ for meaningful back-trace)", known.size());
        return;
    }
    HLog("[entlist] scan starting with %zu known-good actor pointers "
         "as ground truth", known.size());

    // Fast lookup — pack into unordered_set for O(1) test.
    std::unordered_set<uint64_t> known_set(known.begin(), known.end());

    // Collect hits across all regions.  Cap per-region + total to bound
    // memory.  Bases/hits kept in parallel arrays so scan helper can be
    // pure raw-pointer (needed for __try in a C++-object-using scope).
    constexpr int kMaxHits = 256;
    uint64_t all_bases[kMaxHits];
    int      all_hits [kMaxHits];
    int      total_hits = 0;

    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uint8_t* addr = (uint8_t*)0x10000;
    MEMORY_BASIC_INFORMATION mbi{};
    int regions = 0;

    uint64_t t0 = GetTickCount64();
    while (addr < (uint8_t*)si.lpMaximumApplicationAddress && total_hits < kMaxHits) {
        if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;
        if (mbi.RegionSize == 0) break;
        uint8_t* next = (uint8_t*)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        bool ok = (mbi.State == MEM_COMMIT) && (mbi.Type == MEM_PRIVATE) &&
                  ((mbi.Protect & PAGE_READWRITE) ||
                   (mbi.Protect & PAGE_EXECUTE_READWRITE)) &&
                  !(mbi.Protect & PAGE_GUARD);
        if (ok && mbi.RegionSize < 0x02000000) {
            int rem = kMaxHits - total_hits;
            int got = scan_region_for_hits(
                (const uint64_t*)mbi.BaseAddress,
                mbi.RegionSize / 8,
                known_set, 3,
                &all_bases[total_hits], &all_hits[total_hits], rem);
            total_hits += got;
        }
        regions++;
        addr = next;
    }
    uint64_t t1 = GetTickCount64();

    // Rank by hit count (descending).
    for (int i = 1; i < total_hits; i++) {
        for (int j = i; j > 0 && all_hits[j] > all_hits[j-1]; j--) {
            uint64_t tb = all_bases[j]; all_bases[j] = all_bases[j-1]; all_bases[j-1] = tb;
            int      th = all_hits[j];  all_hits[j]  = all_hits[j-1];  all_hits[j-1]  = th;
        }
    }

    HLog("[entlist] scan done in %llums  regions=%d  candidate clusters=%d",
         t1 - t0, regions, total_hits);

    // Log + probe top 5.  Track the one with highest slot_players (that's
    // the plaintext list if any); if slot_players stays 0 but known_hits
    // is high, entries are encrypted and we hand off to zoid's method.
    int  best_slot_players = 0;
    uint64_t best_base     = 0;
    int      best_known    = 0;
    for (int i = 0; i < total_hits && i < 5; i++) {
        int slot_players = 0, slot_derefed = 0;
        uint64_t sample[4] = { 0 };
        probe_slots(all_bases[i], &slot_players, &slot_derefed, sample, 4);
        HLog("[entlist]   cand @ 0x%llX  known_hits=%d  slot_players=%d/32  "
             "derefed=%d/32  first_slots={0x%llX, 0x%llX, 0x%llX, 0x%llX}",
             all_bases[i], all_hits[i], slot_players, slot_derefed,
             sample[0], sample[1], sample[2], sample[3]);
        if (slot_players > best_slot_players) {
            best_slot_players = slot_players;
            best_base         = all_bases[i];
            best_known        = all_hits[i];
        }
    }
    if (best_base == 0 && total_hits > 0) {
        // No candidate has plaintext players → suspect encrypted.  Pick
        // the one with most known_hits so zoid's method has a target.
        best_base  = all_bases[0];
        best_known = all_hits[0];
    }

    if (total_hits > 0) {
        s_entlist_last_base  = best_base;
        s_entlist_last_hits  = best_known;
        s_entlist_last_count = best_slot_players;
        HLog("[entlist] BEST @ 0x%llX  known_hits=%d  slot_players=%d/32  "
             "%s",
             best_base, best_known, best_slot_players,
             best_slot_players >= 3
                ? "→ PLAINTEXT list found, ready to walk directly"
                : "→ entries not deref-able; likely encrypted (zoid path)");
    } else {
        HLog("[entlist] no candidate cluster found — actor list may use "
             "non-contiguous storage (linked list, hash map, etc)");
    }
}

DWORD WINAPI EntListScannerThread(LPVOID) {
    HLog("[entlist] scanner thread started");
    Sleep(15000);   // let HWBP capture some actors first
    uint64_t next_periodic = GetTickCount64() + 30000;
    while (g_running.load()) {
        uint64_t now = GetTickCount64();
        bool trigger = g_ring && g_ring->cam.entlist_scan_trigger != 0;
        if (trigger || now >= next_periodic) {
            if (trigger) {
                HLog("[entlist] scan triggered by external (F6)");
                g_ring->cam.entlist_scan_trigger = 0;
            }
            ScanForEntityList();
            next_periodic = GetTickCount64() + 30000;
        }
        Sleep(250);  // poll trigger 4x/sec
    }
    HLog("[entlist] scanner thread exiting");
    return 0;
}

DWORD WINAPI CameraPublisherThread(LPVOID) {
    HLog("[cam] publisher thread started");
    // Wait a moment for R6 to fully initialize its renderer before scanning.
    Sleep(3000);

    uint64_t last_rescan_ms  = 0;
    uint64_t last_health_ms  = 0;
    uint64_t last_change_ms  = 0;
    int      publish_count   = 0;
    int      good_count      = 0;
    int      bad_count       = 0;
    float    last_cam_x      = 0.f;
    float    last_matrix0    = 0.f;

    while (g_running.load()) {
        uint64_t now_ms = GetTickCount64();

        // Full rescan every 30 s, or immediately if we've had bad publishes,
        // or every 3 s if the cam values have been frozen for >3 s (view
        // block probably reallocated to a different address).
        bool need_rescan = (g_view_block_va == 0) ||
                           (now_ms - last_rescan_ms > 30000) ||
                           (last_change_ms > 0 && now_ms - last_change_ms > 3000
                            && now_ms - last_rescan_ms > 2000);
        if (need_rescan) {
            uint64_t vb = ScanViewBlock();
            if (vb) {
                if (vb != g_view_block_va) {
                    HLog("[cam] view_block located @ 0x%llX (was 0x%llX)  "
                         "publish_count=%d good=%d bad=%d",
                         vb, g_view_block_va, publish_count, good_count, bad_count);
                }
                g_view_block_va = vb;
                last_rescan_ms  = now_ms;
                last_change_ms  = now_ms;   // reset staleness timer post-rescan
            } else if (g_view_block_va == 0) {
                Sleep(1000);
                continue;
            }
        }

        // Publish cam + synthesized matrix, ~125 Hz.  Post-patch layout
        // stores basis vectors (right/up/forward) instead of a baked
        // matrix — we read them + cam_pos, then build a row-major world→
        // clip matrix that the external's existing W2S (which expects
        // "feed world coords directly, translation baked in row 3") can
        // consume unchanged.
        // FOV hardcoded to R6 default (60° vertical); if user changes
        // FOV in R6 settings, ESP boxes will be off in magnitude — we
        // can fix by reading fov from the view block later.
        if (g_ring && g_view_block_va) {
            __try {
                float tmp_pos[3];
                float right[3], up[3], fwd[3];
                memcpy(tmp_pos, (const void*)(g_view_block_va + kCamPosOff), 12);
                memcpy(right,   (const void*)(g_view_block_va + kRightOff), 12);
                memcpy(up,      (const void*)(g_view_block_va + kUpOff),    12);
                memcpy(fwd,     (const void*)(g_view_block_va + kFwdOff),   12);
                // Synthesize world→clip (column-major storage, row-vector
                // math): clip.x = sx*right·(w - cam),
                //        clip.y = sy*up·(w - cam),
                //        clip.w = fwd·(w - cam)
                const float PI      = 3.14159265f;
                const float fov_y   = 60.f * PI / 180.f;
                const float aspect  = 16.f / 9.f;
                const float tan_h   = tanf(fov_y * 0.5f);
                const float sx      = 1.0f / (aspect * tan_h);
                const float sy      = 1.0f / tan_h;
                const float dp_r    = right[0]*tmp_pos[0] + right[1]*tmp_pos[1] + right[2]*tmp_pos[2];
                const float dp_u    = up[0]   *tmp_pos[0] + up[1]   *tmp_pos[1] + up[2]   *tmp_pos[2];
                const float dp_f    = fwd[0]  *tmp_pos[0] + fwd[1]  *tmp_pos[1] + fwd[2]  *tmp_pos[2];
                float tmp_mat[16] = {
                    sx*right[0], sy*up[0], 0.f, fwd[0],
                    sx*right[1], sy*up[1], 0.f, fwd[1],
                    sx*right[2], sy*up[2], 0.f, fwd[2],
                    -sx*dp_r,    -sy*dp_u, 0.f, -dp_f
                };
                // Sanity: pos + matrix must be finite AND non-zero.
                // (matrix[0] and matrix[5] are diagonal entries — they
                // should always be non-zero for a real projection.)
                // Finite AND within-map-bounds.  R6 map coords are within
                // ~1000m of origin; anything past 100000m is garbage from
                // a wrong view_block address (seen: cam=(0, 2e23, 7e26)
                // when we resolved a completely different heap struct).
                bool ok_pos = (tmp_pos[0] == tmp_pos[0]) &&
                              (tmp_pos[1] == tmp_pos[1]) &&
                              (tmp_pos[2] == tmp_pos[2]) &&
                              fabsf(tmp_pos[0]) < 100000.f &&
                              fabsf(tmp_pos[1]) < 100000.f &&
                              fabsf(tmp_pos[2]) < 100000.f;
                bool ok_mat = (tmp_mat[0] == tmp_mat[0]) &&
                              (tmp_mat[5] == tmp_mat[5]) &&
                              (tmp_mat[0] != 0.f || tmp_mat[5] != 0.f) &&
                              fabsf(tmp_mat[0]) < 1000.f &&
                              fabsf(tmp_mat[5]) < 1000.f;
                if (!ok_pos || !ok_mat) {
                    // Garbage — invalidate + force rescan.
                    g_ring->cam.valid = 0;
                    bad_count++;
                    if ((bad_count % 100) == 1) {
                        HLog("[cam] bad publish #%d — cam=(%.2f,%.2f,%.2f) "
                             "matrix[0]=%.2f — invalidating",
                             bad_count, tmp_pos[0], tmp_pos[1], tmp_pos[2],
                             tmp_mat[0]);
                    }
                    g_view_block_va = 0;
                    last_rescan_ms  = 0;
                    Sleep(100);
                    continue;
                }
                // Track whether values are actually changing (mouse turn,
                // player move) so we can detect a frozen/stale view block.
                if (tmp_pos[0] != last_cam_x || tmp_mat[0] != last_matrix0) {
                    last_change_ms = now_ms;
                    last_cam_x     = tmp_pos[0];
                    last_matrix0   = tmp_mat[0];
                }
                // Pre-increment (odd = writing).
                InterlockedIncrement(&g_ring->cam.seq);
                memcpy(g_ring->cam.cam_pos, tmp_pos, 12);
                memcpy(g_ring->cam.matrix,  tmp_mat, 64);
                g_ring->cam.view_block_va = g_view_block_va;
                g_ring->cam.last_write_ms = now_ms;
                g_ring->cam.valid = 1;
                InterlockedIncrement(&g_ring->cam.seq);
                good_count++;
                if (++publish_count == 1) {
                    HLog("[cam] first publish OK  cam=(%.1f,%.1f,%.1f)  "
                         "matrix[0]=%.4f",
                         tmp_pos[0], tmp_pos[1], tmp_pos[2], tmp_mat[0]);
                }
                // Health log every 10 s.
                if (now_ms - last_health_ms > 10000) {
                    last_health_ms = now_ms;
                    uint64_t age = now_ms - last_change_ms;
                    HLog("[cam] health  good=%d bad=%d  vb=0x%llX  "
                         "cam=(%.1f,%.1f,%.1f)  last_change=%llums ago",
                         good_count, bad_count, g_view_block_va,
                         tmp_pos[0], tmp_pos[1], tmp_pos[2], age);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                HLog("[cam] fault reading view_block 0x%llX — will rescan",
                     g_view_block_va);
                g_ring->cam.valid = 0;
                g_view_block_va = 0;
                last_rescan_ms = 0;
            }
        }
        Sleep(8);
    }
    HLog("[cam] publisher thread exiting");
    return 0;
}

// ── DLL entry ────────────────────────────────────────────────────────
BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(inst);
        HLog("[dllmain] PROCESS_ATTACH");
        // Spawn init on its own thread — DllMain is loader-locked so
        // Toolhelp32/SetThreadContext are unsafe here.
        HANDLE h = CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        HLog("[dllmain] PROCESS_DETACH");
        g_running.store(false);
        if (g_bp_site)  ApplyToAll(g_bp_site, false);
        if (g_veh)  RemoveVectoredExceptionHandler(g_veh);
        if (g_ring) UnmapViewOfFile(g_ring);
        if (g_map)  CloseHandle(g_map);
    }
    return TRUE;
}
