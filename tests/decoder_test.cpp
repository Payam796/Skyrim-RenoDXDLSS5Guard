#include "../src/StoreDecoder.h"

#include <cstdio>
#include <initializer_list>
#include <vector>

static int failures = 0;

struct Expect { bool ok; int len; int base; int index; int scale; long long disp; bool rip; };

static void Check(const char* name, std::initializer_list<unsigned> bytes, Expect e)
{
    std::vector<std::uint8_t> v;
    for (unsigned b : bytes) v.push_back(static_cast<std::uint8_t>(b));
    v.resize(v.size() + 16, 0x90);                                   // slack bytes must not be consumed
    guard::StoreInsn s;
    const bool ok = guard::DecodeStore(v.data(), bytes.size(), s);   // avail = exact length
    bool pass = (ok == e.ok);
    if (ok && e.ok)
        pass = s.length == e.len && s.base == e.base && s.index == e.index &&
               s.scale == e.scale && s.disp == e.disp && s.ripRelative == e.rip;
    std::printf("%-48s %s\n", name, pass ? "ok" : "FAIL");
    if (!pass) ++failures;
}

int main()
{
    // The instruction from the crash log: mov [rdi], rax
    Check("48 89 07         mov [rdi],rax  (crash site)", {0x48,0x89,0x07},              {true, 3, 7,-1,1,0,false});
    Check("89 4B 10         mov [rbx+10h],ecx",           {0x89,0x4B,0x10},              {true, 3, 3,-1,1,0x10,false});
    Check("88 01            mov [rcx],al",                {0x88,0x01},                   {true, 2, 1,-1,1,0,false});
    Check("48 89 84 C8 ...  mov [rax+rcx*8+110h],rax",    {0x48,0x89,0x84,0xC8,0x10,0x01,0,0}, {true, 8, 0, 1,8,0x110,false});
    Check("C7 00 05000000   mov dword [rax],5",           {0xC7,0x00,0x05,0,0,0},        {true, 6, 0,-1,1,0,false});
    Check("C6 00 5A         mov byte [rax],5Ah",          {0xC6,0x00,0x5A},              {true, 3, 0,-1,1,0,false});
    Check("66 C7 00 0500    mov word [rax],5",            {0x66,0xC7,0x00,0x05,0x00},    {true, 5, 0,-1,1,0,false});
    Check("0F 29 04 24      movaps [rsp],xmm0",           {0x0F,0x29,0x04,0x24},         {true, 4, 4,-1,1,0,false});
    Check("41 89 45 00      mov [r13+0],eax",             {0x41,0x89,0x45,0x00},         {true, 4,13,-1,1,0,false});
    Check("89 05 10000000   mov [rip+10h],eax",           {0x89,0x05,0x10,0,0,0},        {true, 6,-1,-1,1,0x10,true});
    Check("C6 05 F0FFFFFF 5A mov byte [rip-10h],5Ah",     {0xC6,0x05,0xF0,0xFF,0xFF,0xFF,0x5A}, {true, 7,-1,-1,1,-0x10,true});
    Check("F3 0F 7F 07      movdqu [rdi],xmm0",           {0xF3,0x0F,0x7F,0x07},         {true, 4, 7,-1,1,0,false});
    Check("4C 89 24 25 ...  mov [1000h],r12  (no base)",  {0x4C,0x89,0x24,0x25,0,0x10,0,0}, {true, 8,-1,-1,1,0x1000,false});
    Check("4A 89 04 A9      mov [rcx+r13*4],rax",         {0x4A,0x89,0x04,0xA9},         {true, 4, 1,13,4,0,false});

    // Must be rejected
    Check("48 8B 07         mov rax,[rdi]  (load)",       {0x48,0x8B,0x07},              {false,0,0,0,0,0,false});
    Check("89 C1            mov ecx,eax  (reg-direct)",   {0x89,0xC1},                   {false,0,0,0,0,0,false});
    Check("C7 08 ...        C7 /1  (not mov)",            {0xC7,0x08,1,0,0,0},           {false,0,0,0,0,0,false});
    Check("64 89 07         fs: prefix",                  {0x64,0x89,0x07},              {false,0,0,0,0,0,false});
    Check("67 89 07         addr-size prefix",            {0x67,0x89,0x07},              {false,0,0,0,0,0,false});
    Check("F0 89 07         lock prefix",                 {0xF0,0x89,0x07},              {false,0,0,0,0,0,false});
    Check("48 89            truncated",                   {0x48,0x89},                   {false,0,0,0,0,0,false});
    Check("C7 00 05         truncated imm32",             {0xC7,0x00,0x05},              {false,0,0,0,0,0,false});
    Check("(empty)",                                      {},                            {false,0,0,0,0,0,false});

    std::printf("\n%s (%d failure%s)\n", failures ? "FAILED" : "ALL PASSED", failures, failures == 1 ? "" : "s");
    return failures ? 1 : 0;
}
