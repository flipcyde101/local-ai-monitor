# Local AI Monitor

A tiny always-on-top Windows widget for watching what matters when running local AI models, plus a task-manager window to kill whatever is hogging your GPU.

- **~0.3% CPU, ~65 MB RAM.** One native .exe, no installer, no runtime to download.
- **Zero dependencies.** Uses only what ships with Windows and the NVIDIA driver: .NET Framework 4, NVML, Windows performance counters, DXGI and a single `NtQuerySystemInformation` process snapshot.

## What it shows

| Area | Details |
|---|---|
| CPU | Total load, effective clock, per-thread bars, history graph |
| RAM | Used / free, commit charge, disk read rate (model loading) |
| NVIDIA GPU | Load, VRAM used/free with history, temperature, power draw vs limit, core/memory clocks, P-state, memory-bus load, PCIe throughput, clock limiter (idle / power cap / thermal) |
| VRAM spill | Shared GPU memory in use, i.e. model data that overflowed VRAM into system RAM (the slow path) |
| iGPU | Load and shared memory for the integrated GPU |
| GPU processes | Top processes by VRAM and GPU load, each with a one-click end task |
| Ollama | Loaded models, size, context length, **% on GPU vs CPU**, time until unload, one-click unload |
| Alerts | VRAM nearly full, spillover, model partly on CPU, thermal throttling, high RAM / commit, GPU temperature |

## Task manager

Click **Tasks** (or Ctrl+T) for a full process list: name, PID, CPU %, memory, VRAM, GPU %, threads. Sort by any column, filter by name or PID, show only AI or GPU-using processes. **End task** / **End tree** (Delete / Shift+Delete) with confirmation; critical Windows processes are protected, and PID reuse is checked before anything is terminated. Elevated processes can be ended after **Restart as administrator** from the right-click menu.

## Settings

Right-click the widget or click ⚙: always on top, opacity, refresh rate, zoom, auto-fit height, start with Windows, which sections to show, compact mode, alert thresholds, Ollama URL, confirm-before-ending, and the keywords that mark a process as AI-related. Stored in `LocalAIMonitor.ini` next to the exe.

The widget is borderless: drag anywhere to move it, drag an edge or corner to resize it, Ctrl+mouse wheel to zoom.

## Build

Requires only Windows 10/11 (the C# compiler ships with .NET Framework 4):

```bat
build.cmd
```

Output: `bin\LocalAIMonitor.exe`. `build.cmd` then runs `sign.ps1`, which signs the exe with a local self-signed code-signing certificate (`CN=LocalAIMonitor Local Code Signing` in `CurrentUser\My`) if one exists. Signing is optional; delete those lines if you don't need it. Smart App Control may block unsigned or unknown builds on some machines.

`LocalAIMonitor.exe --diag` writes a one-shot `diag.txt` with detected adapters and a sample, for troubleshooting.

## Notes

- GPU details (temperature, power, clocks, throttling) require an NVIDIA GPU. AMD/Intel GPUs still show load and memory via Windows counters.
- CPU temperature isn't shown: Windows doesn't expose it without a kernel driver.
