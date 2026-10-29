// StoreDecoder.h - minimal x86-64 decoder for "store to memory" instructions.
//
// The guard may need to skip one faulting store, so it needs the instruction's exact
// length and its memory operand (to cross-check against the fault address).
// Anything not recognised is rejected, and the guard then lets the crash proceed
// exactly as it would have without the plugin.
//
// Standard C++ only, so it can be unit-tested anywhere (tests/decoder_test.cpp).
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace guard {

struct StoreInsn {
    std::uint8_t length      = 0;      // total instruction length, bytes
    bool         ripRelative = false;  // [rip + disp]
    int          base        = -1;     // 0..15 = RAX,RCX,RDX,RBX,RSP,RBP,RSI,RDI,R8..R15; -1 = none
    int          index       = -1;     // same numbering, -1 = none
    std::uint8_t scale       = 1;
    std::int64_t disp        = 0;
};

// Recognised: 88/89 (mov r/m,r), C6/C7 /0 (mov r/m,imm), and the SSE/MMX/NT stores
// 0F 11, 13, 17, 29, 2B, 7F, D6, E7, C3, with optional 66/F2/F3 and REX prefixes.
// Rejected: register-direct forms, segment/lock/addr-size prefixes, VEX/EVEX, loads, RMW ops.
inline bool DecodeStore(const std::uint8_t* p, std::size_t avail, StoreInsn& out)
{
    std::size_t i = 0;
    auto need = [&](std::size_t n) { return i + n <= avail; };

    bool opsize16 = false;
    for (int n = 0; need(1) && (p[i] == 0x66 || p[i] == 0xF2 || p[i] == 0xF3); ++n, ++i) {
        if (n >= 3) return false;
        if (p[i] == 0x66) opsize16 = true;
    }

    std::uint8_t rex = 0;
    if (need(1) && (p[i] & 0xF0) == 0x40) rex = p[i++];

    if (!need(1)) return false;
    std::uint8_t op = p[i++];
    std::size_t immSize = 0;
    bool regMustBeZero = false;

    if (op == 0x0F) {
        if (!need(1)) return false;
        op = p[i++];
        switch (op) {
        case 0x11: case 0x13: case 0x17: case 0x29: case 0x2B:
        case 0x7F: case 0xD6: case 0xE7: case 0xC3:
            break;
        default:
            return false;
        }
    } else {
        switch (op) {
        case 0x88: case 0x89: break;
        case 0xC6: immSize = 1;                 regMustBeZero = true; break;
        case 0xC7: immSize = opsize16 ? 2 : 4;  regMustBeZero = true; break;
        default: return false;
        }
    }

    if (!need(1)) return false;
    const std::uint8_t modrm = p[i++];
    const unsigned mod = modrm >> 6;
    const unsigned reg = (modrm >> 3) & 7u;
    const unsigned rm  = modrm & 7u;
    if (mod == 3) return false;                 // register-direct: not a memory store
    if (regMustBeZero && reg != 0) return false;

    StoreInsn r;
    std::size_t dispSize = 0;

    if (rm == 4) {                              // SIB follows
        if (!need(1)) return false;
        const std::uint8_t sib = p[i++];
        const unsigned idx = ((sib >> 3) & 7u) | ((rex & 0x02) ? 8u : 0u);   // REX.X
        const unsigned bas = (sib & 7u)        | ((rex & 0x01) ? 8u : 0u);   // REX.B
        r.scale = static_cast<std::uint8_t>(1u << (sib >> 6));
        if (idx != 4) r.index = static_cast<int>(idx);                       // 4 = "no index"
        if ((sib & 7u) == 5 && mod == 0) dispSize = 4;                       // disp32, no base
        else r.base = static_cast<int>(bas);
    } else if (rm == 5 && mod == 0) {           // RIP-relative
        r.ripRelative = true;
        dispSize = 4;
    } else {
        r.base = static_cast<int>(rm | ((rex & 0x01) ? 8u : 0u));
    }
    if (mod == 1) dispSize = 1;
    else if (mod == 2) dispSize = 4;

    if (!need(dispSize)) return false;
    if (dispSize == 1) {
        r.disp = static_cast<std::int8_t>(p[i]);
    } else if (dispSize == 4) {
        std::int32_t d;
        std::memcpy(&d, p + i, 4);
        r.disp = d;
    }
    i += dispSize;

    if (!need(immSize)) return false;
    i += immSize;

    if (i > 15) return false;
    r.length = static_cast<std::uint8_t>(i);
    out = r;
    return true;
}

}  // namespace guard
