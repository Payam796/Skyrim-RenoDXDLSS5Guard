# RenoDX DLSS Guard

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
| **B.** Target is in a section declared *read-only* (`.rdata`/`.text`) | `ReadOnlyWriteMode`: `skip` (default) drops that one store; `unprotect` lets it land; `crash` only logs. |
| Anything it can't positively identify | Not touched - same crash as without the plugin. |

Every event is logged to `RenoDXDLSSGuard.log` (registers, stack scan, section name/flags, current page
protection, bytes at the target). **The first event tells you whether it was case A or B**, which is
exactly what the add-on's author needs.

## Honest limits

- It makes this specific fault survivable. It cannot know what the add-on does next with a value it never
  received (case B/`skip`) - that is why the log matters.
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
   SelfTest B (write to read-only section, mode=skip): PASS
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
