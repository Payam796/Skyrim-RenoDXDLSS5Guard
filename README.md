# RenoDX DLSS Guard 1.1

SKSE plugin (Skyrim SE/AE, x64) that keeps `renodx-dlss.addon64` from crashing the game when it runs
alongside **Community Shaders' Upscaling** (DLSS via Streamline).

## What the crash actually is

From `crash-2026-10-26-03-06-37.log` + `ReShade.log`:

- Exception: `EXCEPTION_ACCESS_VIOLATION`, **write**, in ReShade's `dxgi.dll+011B5EA`, instruction `mov [rdi], rax`.
- `RAX` is the D3D11 device pointer from `ReShade.log`; `RDI` (the destination) is
  `renodx-dlss.addon64 + 0x2C21F8` - **inside the add-on's own image, on a page that is not writable**.
- Call chain: `CommunityShaders.dll Upscaling::Main_PostProcessing` -> `renodx-dlss.addon64+0x14725` -> ReShade.
- So the add-on handed ReShade an output pointer into its own non-writable memory. Community Shaders
  and ReShade are both behaving; the fault is in the add-on's code path.

The add-on is closed source (RenoDX Discord only), so the real fix has to come from its author.
This plugin is a guard until then.

## What the guard does

A vectored exception handler that reacts **only** to write-faults whose target address is inside a module
whose file name contains `renodx-dlss`. Everything else passes through untouched.

| Situation (decided from the add-on's PE section headers) | Action |
|---|---|
| **A.** Target is in a section declared *writable* (`.data`) but the page is read-only | Restore `PAGE_READWRITE`, retry. Lossless. |
| **B.** Target is in a section declared *read-only* (`.rdata`/`.text`) | `ReadOnlyWriteMode`: **`emulate`** (default, see below); `skip` drops that one store; `unprotect` lets it land; `crash` only logs. |
| Anything it can't positively identify | Not touched - same crash as without the plugin. |

Every event is logged to `RenoDXDLSSGuard.log` (registers, stack scan, section name/flags, current page
protection, bytes at the target). **The first event tells you whether it was case A or B**, which is
exactly what the add-on's author needs.

## `emulate` mode (v1.1)

Logs from a real session showed the same fault once per DLSS evaluate (~19,000 in 6 minutes). Decoded:

- the write target holds a GUID (`{E65D8F75-88FC-46F4-BF67-00F2D58937D8}`), not a variable;
- the faulting ReShade function returns `void` and stores a D3D11 device pointer: D3D11 `GetDevice(ID3D11Device**)`;
- `R8`/`R9` are two stack pointers.

That is the shape of `GetPrivateData(guid, &size, &data)`, which is vtable slot 3 on a D3D12 object but slot 4 on
a D3D11 one (slot 3 is `GetDevice`). So the add-on is treating a D3D11 object (the context Streamline hands it) as D3D12.
Plain `skip` leaves it with an uninitialised size/data and a success-looking return value, so it probably rejects the
motion/depth tags: **Render/Upscaled show no motion or depth**.

`emulate` gives it what a correct D3D11 call would have produced, in this order, and drops back to `skip` the moment a check fails:

1. what follows the store must be a plain function epilogue (so the return value can be set safely);
2. `R8`/`R9` must be pointers into the caller's stack, and the "pointer" we faulted on must be 16 readable bytes;
3. **real call:** find the object (it must have `vtable[3]` = the function we are inside, `vtable[4]` = code in the same
   module), call `GetPrivateData` on slot 4 into a private buffer inside an SEH guard, copy back honouring the caller's buffer size;
4. **otherwise synthetic:** `size = 0`, return `DXGI_ERROR_NOT_FOUND` - exactly what an object with no such data returns.

Known cost: the faulting function had already `AddRef`'d the device before the store, so each handled call leaks one
reference on it (same as `skip`). That only matters at shutdown.

**Reading the log** (first 8 events are detailed, then one summary line every 256):

```
emulate: REAL call. guid=...  this=R12=...  vtable[3]=d3d11.dll+0x...  vtable[4]=d3d11.dll+0x...
emulate: GetPrivateData(slot 4) -> HRESULT=0x887A0002  size_in=.. size_out=0 ...
```
`0x887A0002` means "no such private data": the add-on asked for something it never stored on that object.
`SYNTHETIC` means the object could not be identified, so the guard answered "not found" itself.
If you see `plain skip`, a validation failed and the line says which one.

**Does it fix Render/Upscaled?** Unknown until you try. It removes the garbage the add-on was reading, which is the most
likely reason it ignored the tags, but the add-on may have other D3D11-hosted problems behind this one.
Whatever happens, the log above is precisely the evidence the add-on's author needs.

## Upgrading from 1.0

Replace `RenoDXDLSSGuard.dll` **and** `RenoDXDLSSGuard.ini` (the old ini says `ReadOnlyWriteMode=skip`, which keeps the old behaviour).
Run `SelfTest=1` once: in `emulate` mode it also prints `SelfTest C` and `SelfTest D`.
`SelfTest C` needs a **Release** build (Debug/incremental builds route function pointers through jump stubs, which defeats the object check;
D still passes).

## Honest limits

- It makes this specific fault survivable and (in `emulate`) answers the misdirected call correctly. It cannot know what the add-on
  does next - that is why the log matters.
- Built and syntax-checked off-Windows; the instruction decoder is unit-tested (and its test vectors were
  verified against a real assembler). The handler has **not been executed on Windows or against your setup**.
  Use `SelfTest=1` once to verify it on your machine (below).

## Build

**Option 1 - no local tools:** push this folder to a GitHub repo; Actions builds it
(`.github/workflows/build.yml`) and publishes an artifact already laid out as `Data/SKSE/Plugins/...`.

**Option 2 - Visual Studio Build Tools (x64 Native Tools prompt):**

```
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release
```

Output: `build\Release\RenoDXDLSSGuard.dll`. No dependencies (static CRT, no SKSE/CommonLib headers).

## Install

Copy `RenoDXDLSSGuard.dll` and `RenoDXDLSSGuard.ini` to `Data\SKSE\Plugins\` (or as a mod in MO2/Vortex).

## Verify it works on your machine (30 seconds)

1. Set `SelfTest=1` in the ini, start the game, quit at the main menu.
2. Open `Data\SKSE\Plugins\RenoDXDLSSGuard.log` (MO2: check the *overwrite* folder). Expect:
   ```
   SelfTest A (read-only page inside a writable section -> restore + retry): PASS
   SelfTest B (write to read-only section, mode=emulate): PASS
   SelfTest C (misdirected GetPrivateData on a D3D11-style object -> real slot-4 call): PASS
   SelfTest D (same, object unidentifiable -> synthetic NOT_FOUND): PASS
   ```
3. Set `SelfTest=0` again.

If it says FAIL (or the game dies during the self-test), set `Enabled=0` and send me the log.

## Then play and read the log

Look for `---- write fault #1 into guarded module ----`:

- `target section: .data declared RW- | current page protect=0x02 (NOT writable)` -> **case A**: a page was
  flipped read-only; the guard repaired it, nothing lost.
- `target section: .rdata declared R-- ...` -> **case B**: the add-on writes to read-only data. Try
  `ReadOnlyWriteMode=unprotect` if `skip` leaves DLSS misbehaving, and send the log to the add-on's author.

No fault logged and no crash = the guard wasn't needed this session.

## Report upstream

Send the RenoDX Discord (#dlss5): your `RenoDXDLSSGuard.log`, the CrashLogger log, `ReShade.log`, and this
one-liner: *"write to `renodx-dlss.addon64+0x2C21F8` (build 0.2026.1025.409) from a ReShade D3D11 COM call
at `+0x14725`, during CS Upscaling `Main_PostProcessing`; destination page not writable."*

## Also worth trying (independent of this plugin)

Your `ReShade.log` has this line from the add-on itself: *"not listed in ADDON.LoadFromDllMain ... Loaded-module
NGX hooks will attach during ReShade Present"*. That is the add-on telling you it is running in its degraded,
late-attach mode because Streamline/NGX were already loaded by Community Shaders. Add to `ReShade.ini`:

```
[ADDON]
LoadFromDllMain=renodx-dlss.addon64
```

so it hooks before CS loads Streamline. Not guaranteed to cure this crash, but it removes the late-hook race
the log describes.

## Files

- `src/RenoDXDLSSGuard.cpp` - the plugin
- `src/StoreDecoder.h` - x86-64 store decoder (standard C++, unit-tested)
- `tests/decoder_test.cpp` - decoder tests
- `RenoDXDLSSGuard.ini` - settings
