// Local AI Monitor - tiny always-on-top CPU/GPU/VRAM/Ollama monitor + task killer for Windows.
// Zero dependencies: .NET Framework 4 (in-box), NVML (ships with NVIDIA driver),
// Windows performance counters, DXGI, ntdll process snapshot. Build with build.cmd.
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

// ======================================================================= native
static class Nvml
{
    const string D = "nvml.dll";
    [StructLayout(LayoutKind.Sequential)] public struct Util { public uint gpu; public uint memory; }
    [StructLayout(LayoutKind.Sequential)] public struct Mem { public ulong total; public ulong free; public ulong used; }
    [DllImport(D)] public static extern int nvmlInit_v2();
    [DllImport(D)] public static extern int nvmlDeviceGetCount_v2(out uint c);
    [DllImport(D)] public static extern int nvmlDeviceGetHandleByIndex_v2(uint i, out IntPtr h);
    [DllImport(D, CharSet = CharSet.Ansi)] public static extern int nvmlDeviceGetName(IntPtr h, StringBuilder n, uint len);
    [DllImport(D)] public static extern int nvmlDeviceGetUtilizationRates(IntPtr h, out Util u);
    [DllImport(D)] public static extern int nvmlDeviceGetMemoryInfo(IntPtr h, out Mem m);
    [DllImport(D)] public static extern int nvmlDeviceGetTemperature(IntPtr h, int sensor, out uint t);
    [DllImport(D)] public static extern int nvmlDeviceGetPowerUsage(IntPtr h, out uint mw);
    [DllImport(D)] public static extern int nvmlDeviceGetEnforcedPowerLimit(IntPtr h, out uint mw);
    [DllImport(D)] public static extern int nvmlDeviceGetClockInfo(IntPtr h, int type, out uint mhz);
    [DllImport(D)] public static extern int nvmlDeviceGetMaxClockInfo(IntPtr h, int type, out uint mhz);
    [DllImport(D)] public static extern int nvmlDeviceGetPerformanceState(IntPtr h, out int p);
    [DllImport(D)] public static extern int nvmlDeviceGetCurrentClocksThrottleReasons(IntPtr h, out ulong r);
    [DllImport(D)] public static extern int nvmlDeviceGetPcieThroughput(IntPtr h, int counter, out uint kbs);
}

[ComImport, Guid("770aae78-f26f-4dba-a829-253c83d1b387"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IDXGIFactory1
{
    void SetPrivateData(); void SetPrivateDataInterface(); void GetPrivateData(); void GetParent();
    void EnumAdapters(); void MakeWindowAssociation(); void GetWindowAssociation(); void CreateSwapChain(); void CreateSoftwareAdapter();
    [PreserveSig] int EnumAdapters1(uint i, out IDXGIAdapter1 a);
}

[ComImport, Guid("29038f61-3839-4626-91fd-086879011a05"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
interface IDXGIAdapter1
{
    void SetPrivateData(); void SetPrivateDataInterface(); void GetPrivateData(); void GetParent();
    void EnumOutputs(); void GetDesc(); void CheckInterfaceSupport();
    [PreserveSig] int GetDesc1(out DxgiDesc1 d);
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
struct DxgiDesc1
{
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)] public string Description;
    public uint VendorId, DeviceId, SubSysId, Revision;
    public UIntPtr DedicatedVideoMemory, DedicatedSystemMemory, SharedSystemMemory;
    public uint LuidLow; public int LuidHigh; public uint Flags;
}

static class Win
{
    [StructLayout(LayoutKind.Sequential)]
    public class MemStatus
    {
        public uint dwLength = 64; public uint dwMemoryLoad;
        public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }
    [DllImport("kernel32.dll")] public static extern bool GlobalMemoryStatusEx([In, Out] MemStatus m);
    [DllImport("dxgi.dll")] public static extern int CreateDXGIFactory1(ref Guid riid, [MarshalAs(UnmanagedType.Interface)] out IDXGIFactory1 f);
    [DllImport("user32.dll")] public static extern bool ReleaseCapture();
    [DllImport("user32.dll")] public static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    [DllImport("user32.dll")] public static extern bool DestroyIcon(IntPtr h);
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr h, int attr, ref int val, int size);
    [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)] public static extern int SetWindowTheme(IntPtr h, string app, string idList);

    public static void DarkTitle(Form f)
    {
        try { int on = 1; DwmSetWindowAttribute(f.Handle, 20, ref on, 4); } catch { }
    }
}

// ------------------------------------------------------------ process snapshot / kill
class SysProc { public int Pid, Parent, Threads, Handles; public string Name = ""; public long Create, CpuTicks, PrivateWs, WorkingSet, Commit; }

static class NtProc
{
    [DllImport("ntdll.dll")] static extern int NtQuerySystemInformation(int cls, IntPtr buf, int len, out int ret);
    static int bufLen = 1 << 20;

    // One syscall, no per-process handles: names, PIDs, parents, CPU times and memory for every process.
    public static List<SysProc> Snapshot()
    {
        for (int attempt = 0; attempt < 6; attempt++)
        {
            IntPtr b = Marshal.AllocHGlobal(bufLen);
            try
            {
                int ret;
                int st = NtQuerySystemInformation(5, b, bufLen, out ret);
                if (st == unchecked((int)0xC0000004)) { bufLen = Math.Max(bufLen * 2, ret + 65536); continue; }
                if (st != 0) return new List<SysProc>();
                var list = new List<SysProc>(400);
                long off = 0;
                while (true)
                {
                    IntPtr p = new IntPtr(b.ToInt64() + off);
                    var sp = new SysProc();
                    sp.Threads = Marshal.ReadInt32(p, 4);
                    sp.PrivateWs = Marshal.ReadInt64(p, 8);
                    sp.Create = Marshal.ReadInt64(p, 32);
                    sp.CpuTicks = Marshal.ReadInt64(p, 40) + Marshal.ReadInt64(p, 48);
                    int nl = Marshal.ReadInt16(p, 56) & 0xFFFF;
                    IntPtr nb = Marshal.ReadIntPtr(p, 64);
                    sp.Name = nb == IntPtr.Zero ? "" : Marshal.PtrToStringUni(nb, nl / 2);
                    sp.Pid = (int)Marshal.ReadInt64(p, 80);
                    sp.Parent = (int)Marshal.ReadInt64(p, 88);
                    sp.Handles = Marshal.ReadInt32(p, 96);
                    sp.WorkingSet = Marshal.ReadInt64(p, 144);
                    sp.Commit = Marshal.ReadInt64(p, 200);
                    if (sp.Pid == 0) sp.Name = "System Idle Process";
                    list.Add(sp);
                    int next = Marshal.ReadInt32(p, 0);
                    if (next == 0) break;
                    off += next;
                }
                return list;
            }
            finally { Marshal.FreeHGlobal(b); }
        }
        return new List<SysProc>();
    }

    public static SysProc Find(int pid)
    {
        foreach (var p in Snapshot()) if (p.Pid == pid) return p;
        return null;
    }
}

static class Killer
{
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool QueryFullProcessImageName(IntPtr h, int flags, StringBuilder name, ref int size);

    static readonly string[] Critical = {
        "system", "system idle process", "registry", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe", "services.exe",
        "lsass.exe", "lsaiso.exe", "memcompression", "memory compression", "secure system", "dwm.exe", "svchost.exe", "fontdrvhost.exe", "sihost.exe" };

    public static bool IsCritical(SysProc p)
    {
        if (p.Pid <= 4 || p.Pid == Process.GetCurrentProcess().Id) return true;
        return Array.IndexOf(Critical, p.Name.ToLowerInvariant()) >= 0;
    }

    public static List<SysProc> Children(List<SysProc> all, SysProc parent)
    {
        var outp = new List<SysProc>(); Collect(all, parent, outp, 0); return outp;
    }

    static void Collect(List<SysProc> all, SysProc parent, List<SysProc> outp, int depth)
    {
        if (depth > 32) return;
        foreach (var c in all)
            if (c.Parent == parent.Pid && c.Pid != parent.Pid && c.Create >= parent.Create)
            { Collect(all, c, outp, depth + 1); outp.Add(c); }
    }

    // Returns null on success, otherwise a readable error. createTime guards against PID reuse.
    public static string Kill(int pid, long createTime, bool tree)
    {
        var all = NtProc.Snapshot();
        SysProc target = null;
        foreach (var p in all) if (p.Pid == pid) target = p;
        if (target == null) return "The process has already exited.";
        if (createTime != 0 && target.Create != createTime) return "That PID now belongs to a different process, so nothing was ended.";
        if (IsCritical(target)) return target.Name + " is a critical Windows process and is protected from being ended here.";
        var order = tree ? Children(all, target) : new List<SysProc>();
        order.Add(target);
        var errs = new List<string>();
        foreach (var p in order)
        {
            if (IsCritical(p)) continue;
            string e = Term(p.Pid);
            if (e != null) errs.Add(p.Name + " (PID " + p.Pid + "): " + e);
        }
        return errs.Count == 0 ? null : string.Join("\n", errs.ToArray());
    }

    static string Term(int pid)
    {
        IntPtr h = OpenProcess(0x0001, false, pid);
        if (h == IntPtr.Zero)
        {
            int e = Marshal.GetLastWin32Error();
            if (e == 87) return null; // already gone
            return e == 5 ? "access denied. It runs elevated; use 'Restart as administrator' to end it." : "could not open (error " + e + ")";
        }
        try
        {
            if (TerminateProcess(h, 1)) return null;
            int e = Marshal.GetLastWin32Error();
            return e == 5 ? "access denied" : "terminate failed (error " + e + ")";
        }
        finally { CloseHandle(h); }
    }

    public static string PathOf(int pid)
    {
        IntPtr h = OpenProcess(0x1000, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            var sb = new StringBuilder(1024); int n = sb.Capacity;
            return QueryFullProcessImageName(h, 0, sb, ref n) ? sb.ToString() : null;
        }
        finally { CloseHandle(h); }
    }
}

// ======================================================================= config
class Cfg
{
    public Cfg()
    {
        TopMost = true; OpacityPct = 97; RefreshMs = 1000; ZoomPct = 100; AutoHeight = true;
        ShowCores = true; ShowGpuProcs = true; ShowIgpu = true; ShowOllama = true; Compact = false;
        VramAlertPct = 92; RamAlertPct = 90; GpuTempAlertC = 85; SpillAlertMB = 300;
        OllamaUrl = "http://127.0.0.1:11434";
        ConfirmEndTask = true; ProcRefreshMs = 1500;
        AiKeywords = "ollama, llama, python, lm studio, lms, koboldcpp, comfyui, jan, gpt4all, whisper, oobabooga, vllm, localai, msty, anythingllm";
        X = int.MinValue; Y = int.MinValue; Width = 360; Height = 400; ProcW = 820; ProcH = 540;
    }

    [Category("1. Window"), DisplayName("Always on top")] public bool TopMost { get; set; }
    [Category("1. Window"), DisplayName("Opacity %"), Description("30 to 100.")] public int OpacityPct { get; set; }
    [Category("1. Window"), DisplayName("Refresh interval (ms)"), Description("250 to 10000. Lower is snappier but uses a little more CPU.")] public int RefreshMs { get; set; }
    [Category("1. Window"), DisplayName("Zoom %"), Description("60 to 250. Ctrl + mouse wheel on the widget also zooms.")] public int ZoomPct { get; set; }
    [Category("1. Window"), DisplayName("Auto-fit height"), Description("On: height follows the content. Turns off when you drag the top/bottom edge; extra height then goes to the graphs.")] public bool AutoHeight { get; set; }
    [Category("1. Window"), DisplayName("Start with Windows"), Description("Adds or removes a per-user startup entry (HKCU Run).")] public bool StartWithWindows { get; set; }

    [Category("2. Sections"), DisplayName("Per-core CPU bars")] public bool ShowCores { get; set; }
    [Category("2. Sections"), DisplayName("GPU process list")] public bool ShowGpuProcs { get; set; }
    [Category("2. Sections"), DisplayName("Integrated GPU line")] public bool ShowIgpu { get; set; }
    [Category("2. Sections"), DisplayName("Ollama panel")] public bool ShowOllama { get; set; }
    [Category("2. Sections"), DisplayName("Compact mode"), Description("Hides secondary detail lines (commit, clocks, PCIe, limiter).")] public bool Compact { get; set; }

    [Category("3. Alerts"), DisplayName("VRAM alert at %")] public int VramAlertPct { get; set; }
    [Category("3. Alerts"), DisplayName("RAM alert at %")] public int RamAlertPct { get; set; }
    [Category("3. Alerts"), DisplayName("GPU temperature alert (°C)")] public int GpuTempAlertC { get; set; }
    [Category("3. Alerts"), DisplayName("Shared-memory spill alert (MB)"), Description("VRAM overflow into system RAM above this amount is flagged.")] public int SpillAlertMB { get; set; }

    [Category("4. Ollama"), DisplayName("Ollama URL"), Description("Base URL of the Ollama server, e.g. http://127.0.0.1:11434")] public string OllamaUrl { get; set; }

    [Category("5. Task manager"), DisplayName("Confirm before ending tasks")] public bool ConfirmEndTask { get; set; }
    [Category("5. Task manager"), DisplayName("Process list refresh (ms)"), Description("500 to 10000.")] public int ProcRefreshMs { get; set; }
    [Category("5. Task manager"), DisplayName("AI process keywords"), Description("Comma-separated. Processes whose names contain one of these are highlighted and shown by the 'AI only' filter.")] public string AiKeywords { get; set; }

    [Browsable(false)] public int X { get; set; }
    [Browsable(false)] public int Y { get; set; }
    [Browsable(false)] public int Width { get; set; }
    [Browsable(false)] public int Height { get; set; }
    [Browsable(false)] public int ProcW { get; set; }
    [Browsable(false)] public int ProcH { get; set; }

    static int Clamp(int v, int lo, int hi) { return v < lo ? lo : v > hi ? hi : v; }

    public void Normalize()
    {
        OpacityPct = Clamp(OpacityPct, 30, 100); RefreshMs = Clamp(RefreshMs, 250, 10000); ZoomPct = Clamp(ZoomPct, 60, 250);
        VramAlertPct = Clamp(VramAlertPct, 10, 100); RamAlertPct = Clamp(RamAlertPct, 10, 100);
        GpuTempAlertC = Clamp(GpuTempAlertC, 40, 110); SpillAlertMB = Clamp(SpillAlertMB, 0, 65536);
        ProcRefreshMs = Clamp(ProcRefreshMs, 500, 10000);
        Width = Clamp(Width, 280, 2000); Height = Clamp(Height, 120, 3000);
        if (string.IsNullOrEmpty(OllamaUrl)) OllamaUrl = "http://127.0.0.1:11434";
        OllamaUrl = OllamaUrl.Trim().TrimEnd('/');
        if (AiKeywords == null) AiKeywords = "";
    }

    public string[] ToLines()
    {
        var l = new List<string>();
        foreach (var p in GetType().GetProperties())
            if (p.Name != "StartWithWindows")
                l.Add(p.Name + "=" + Convert.ToString(p.GetValue(this, null), CultureInfo.InvariantCulture));
        return l.ToArray();
    }

    public void FromLines(string[] lines)
    {
        foreach (var line in lines)
        {
            var kv = line.Split(new[] { '=' }, 2); if (kv.Length != 2) continue;
            var p = GetType().GetProperty(kv[0].Trim());
            if (p == null || !p.CanWrite || p.Name == "StartWithWindows") continue;
            try { p.SetValue(this, Convert.ChangeType(kv[1].Trim(), p.PropertyType, CultureInfo.InvariantCulture), null); } catch { }
        }
        Normalize();
    }

    public Cfg Clone() { var c = new Cfg(); c.FromLines(ToLines()); c.StartWithWindows = StartWithWindows; return c; }

    public string[] Keywords()
    {
        var l = new List<string>();
        foreach (var k in AiKeywords.Split(',')) { var t = k.Trim().ToLowerInvariant(); if (t.Length > 0) l.Add(t); }
        return l.ToArray();
    }
}

// ======================================================================= sampling
class Adapter { public string Name; public string Luid; public uint Vendor; }
class GpuProc { public int Pid; public string Name; public double VramMB; public double Util; }
class OllamaModel { public string Name; public double SizeGB; public double VramFrac; public long Ctx; public DateTime Expires; }

class Snap
{
    public double Cpu = -1, CpuGhz = -1; public double[] Cores = new double[0];
    public double RamUsed, RamTotal, CommitUsed, CommitLimit, DiskRead = -1;
    public bool HasNv; public string NvName = "";
    public double NvUtil = -1, NvMemUtil = -1, VramUsed = -1, VramTotal = -1, Temp = -1, Power = -1, PowerLimit = -1;
    public double Sm = -1, SmMax = -1, MemClk = -1, PcieTx = -1, PcieRx = -1, NvShared = -1;
    public int Pstate = -1; public ulong Throttle; public bool ThrottleOk;
    public bool HasIg; public string IgName = ""; public double IgUtil = -1, IgShared = -1;
    public List<GpuProc> Procs = new List<GpuProc>();
    [ScriptIgnore] public Dictionary<int, double> AllVram = new Dictionary<int, double>();
    [ScriptIgnore] public Dictionary<int, double> AllGpu = new Dictionary<int, double>();
    public double SampleMs, SelfCpu, SelfMB;
}

class Sampler
{
    PerformanceCounter cpuUtil, cpuPerf, disk;
    List<PerformanceCounter> cores = new List<PerformanceCounter>();
    double baseMhz;
    IntPtr nv = IntPtr.Zero; bool nvOk;
    Adapter nvAd, igAd;
    Dictionary<string, CounterSample> prevEng = new Dictionary<string, CounterSample>();
    Dictionary<int, string> names = new Dictionary<int, string>();
    bool pcieSupported = true, throttleSupported = true;
    TimeSpan lastCpuT; DateTime lastWall;
    public string CpuName = "CPU";
    public string Diag = "";
    const StringComparison IC = StringComparison.OrdinalIgnoreCase;

    public Sampler()
    {
        try
        {
            using (var k = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0"))
            {
                CpuName = Clean(((string)k.GetValue("ProcessorNameString", "CPU")).Trim());
                baseMhz = Convert.ToDouble(k.GetValue("~MHz", 0));
            }
        }
        catch { }
        try
        {
            cpuUtil = new PerformanceCounter("Processor Information", "% Processor Utility", "_Total");
            cpuPerf = new PerformanceCounter("Processor Information", "% Processor Performance", "_Total");
            var list = new List<string>();
            foreach (var i in new PerformanceCounterCategory("Processor Information").GetInstanceNames())
                if (!i.Contains("_Total")) list.Add(i);
            list.Sort(delegate (string a, string b)
            {
                string[] x = a.Split(','), y = b.Split(',');
                int c = int.Parse(x[0]).CompareTo(int.Parse(y[0]));
                return c != 0 ? c : int.Parse(x[1]).CompareTo(int.Parse(y[1]));
            });
            foreach (var i in list) cores.Add(new PerformanceCounter("Processor Information", "% Processor Utility", i));
        }
        catch (Exception ex) { Diag += "cpu counters: " + ex.Message + "\r\n"; }
        try { disk = new PerformanceCounter("PhysicalDisk", "Disk Read Bytes/sec", "_Total"); } catch { }
        try
        {
            if (Nvml.nvmlInit_v2() == 0)
            {
                uint n;
                if (Nvml.nvmlDeviceGetCount_v2(out n) == 0 && n > 0 && Nvml.nvmlDeviceGetHandleByIndex_v2(0, out nv) == 0) nvOk = true;
            }
        }
        catch (Exception ex) { nvOk = false; Diag += "nvml: " + ex.Message + "\r\n"; }
        EnumAdapters();
        lastCpuT = Process.GetCurrentProcess().TotalProcessorTime; lastWall = DateTime.UtcNow;
    }

    public static string Clean(string s)
    {
        foreach (var junk in new[] { "(TM)", "(R)", "with Radeon Graphics", " Processor", "NVIDIA GeForce ", "AMD " }) s = s.Replace(junk, "");
        s = s.Replace("Laptop GPU", "Laptop");
        while (s.Contains("  ")) s = s.Replace("  ", " ");
        return s.Trim();
    }

    void EnumAdapters()
    {
        try
        {
            Guid g = new Guid("770aae78-f26f-4dba-a829-253c83d1b387");
            IDXGIFactory1 f;
            if (Win.CreateDXGIFactory1(ref g, out f) != 0) return;
            for (uint i = 0; i < 8; i++)
            {
                IDXGIAdapter1 a;
                if (f.EnumAdapters1(i, out a) != 0) break;
                DxgiDesc1 d;
                int hr = a.GetDesc1(out d);
                Diag += string.Format("adapter {0}: hr={1:X} vendor={2:X} flags={3} luid={4:X8}_{5:X8} {6}\r\n", i, hr, d.VendorId, d.Flags, d.LuidHigh, d.LuidLow, d.Description);
                if (hr == 0 && (d.Flags & 2) == 0 && d.VendorId != 0x1414)
                {
                    var ad = new Adapter { Name = Clean(d.Description), Vendor = d.VendorId, Luid = string.Format("luid_0x{0:X8}_0x{1:X8}", d.LuidHigh, d.LuidLow) };
                    if (d.VendorId == 0x10DE) { if (nvAd == null) nvAd = ad; }
                    else if (igAd == null) igAd = ad;
                }
                Marshal.ReleaseComObject(a);
            }
            Marshal.ReleaseComObject(f);
        }
        catch (Exception ex) { Diag += "dxgi: " + ex.Message + "\r\n"; }
    }

    static double Next(PerformanceCounter c) { try { return c == null ? -1 : c.NextValue(); } catch { return -1; } }

    public Snap Sample()
    {
        var s = new Snap();
        s.Cpu = Math.Min(100, Next(cpuUtil));
        double perf = Next(cpuPerf);
        if (perf >= 0 && baseMhz > 0) s.CpuGhz = perf * baseMhz / 100000.0;
        s.Cores = new double[cores.Count];
        for (int i = 0; i < cores.Count; i++) s.Cores[i] = Math.Min(100, Math.Max(0, Next(cores[i])));
        s.DiskRead = Next(disk);

        var m = new Win.MemStatus();
        if (Win.GlobalMemoryStatusEx(m))
        {
            s.RamTotal = m.ullTotalPhys; s.RamUsed = m.ullTotalPhys - m.ullAvailPhys;
            s.CommitLimit = m.ullTotalPageFile; s.CommitUsed = m.ullTotalPageFile - m.ullAvailPageFile;
        }

        if (nvOk)
        {
            s.HasNv = true;
            var sb = new StringBuilder(96);
            if (Nvml.nvmlDeviceGetName(nv, sb, 96) == 0) s.NvName = Clean(sb.ToString());
            Nvml.Util u; if (Nvml.nvmlDeviceGetUtilizationRates(nv, out u) == 0) { s.NvUtil = u.gpu; s.NvMemUtil = u.memory; }
            Nvml.Mem mm; if (Nvml.nvmlDeviceGetMemoryInfo(nv, out mm) == 0) { s.VramUsed = mm.used; s.VramTotal = mm.total; }
            uint v;
            if (Nvml.nvmlDeviceGetTemperature(nv, 0, out v) == 0) s.Temp = v;
            if (Nvml.nvmlDeviceGetPowerUsage(nv, out v) == 0) s.Power = v / 1000.0;
            if (Nvml.nvmlDeviceGetEnforcedPowerLimit(nv, out v) == 0) s.PowerLimit = v / 1000.0;
            if (Nvml.nvmlDeviceGetClockInfo(nv, 1, out v) == 0) s.Sm = v;
            if (Nvml.nvmlDeviceGetMaxClockInfo(nv, 1, out v) == 0) s.SmMax = v;
            if (Nvml.nvmlDeviceGetClockInfo(nv, 2, out v) == 0) s.MemClk = v;
            int p; if (Nvml.nvmlDeviceGetPerformanceState(nv, out p) == 0) s.Pstate = p;
            if (throttleSupported)
            {
                try { ulong r; if (Nvml.nvmlDeviceGetCurrentClocksThrottleReasons(nv, out r) == 0) { s.Throttle = r; s.ThrottleOk = true; } }
                catch (EntryPointNotFoundException) { throttleSupported = false; }
            }
            if (pcieSupported)
            {
                // Each call samples ~20 ms inside the driver; runs on the sampler thread, never the UI thread.
                if (Nvml.nvmlDeviceGetPcieThroughput(nv, 0, out v) == 0) s.PcieTx = v / 1024.0; else pcieSupported = false;
                if (pcieSupported && Nvml.nvmlDeviceGetPcieThroughput(nv, 1, out v) == 0) s.PcieRx = v / 1024.0;
            }
        }

        ReadGpuCounters(s);

        var me = Process.GetCurrentProcess();
        var now = DateTime.UtcNow; var t = me.TotalProcessorTime;
        double wall = (now - lastWall).TotalMilliseconds;
        if (wall > 0) s.SelfCpu = (t - lastCpuT).TotalMilliseconds / wall / Environment.ProcessorCount * 100.0;
        lastCpuT = t; lastWall = now;
        s.SelfMB = me.PrivateMemorySize64 / 1048576.0;
        return s;
    }

    void ReadGpuCounters(Snap s)
    {
        if (igAd != null) { s.HasIg = true; s.IgName = igAd.Name; }
        try
        {
            var mem = new PerformanceCounterCategory("GPU Adapter Memory").ReadCategory();
            foreach (InstanceData d in mem["Shared Usage"].Values)
            {
                if (nvAd != null && d.InstanceName.StartsWith(nvAd.Luid, IC)) s.NvShared = Math.Max(0, s.NvShared) + d.RawValue;
                if (igAd != null && d.InstanceName.StartsWith(igAd.Luid, IC)) s.IgShared = Math.Max(0, s.IgShared) + d.RawValue;
            }
        }
        catch (Exception ex) { Diag += "adapter mem: " + ex.Message + "\r\n"; }
        try
        {
            if (nvAd != null)
            {
                foreach (InstanceData d in new PerformanceCounterCategory("GPU Process Memory").ReadCategory()["Dedicated Usage"].Values)
                {
                    string n = d.InstanceName;
                    if (n.IndexOf(nvAd.Luid, IC) < 0 || d.RawValue < 4 * 1048576) continue;
                    int pid = ParsePid(n); if (pid <= 0) continue;
                    double cur; s.AllVram.TryGetValue(pid, out cur);
                    s.AllVram[pid] = cur + d.RawValue / 1048576.0;
                }
            }
        }
        catch (Exception ex) { Diag += "proc mem: " + ex.Message + "\r\n"; }
        try
        {
            var eng = new PerformanceCounterCategory("GPU Engine").ReadCategory()["Utilization Percentage"];
            var igByType = new Dictionary<string, double>();
            var next = new Dictionary<string, CounterSample>(eng.Count);
            foreach (InstanceData d in eng.Values)
            {
                string n = d.InstanceName; var cs = d.Sample; next[n] = cs;
                CounterSample old;
                if (!prevEng.TryGetValue(n, out old)) continue;
                double val = CounterSample.Calculate(old, cs);
                if (val <= 0.01) continue;
                if (igAd != null && n.IndexOf(igAd.Luid, IC) >= 0)
                {
                    int ti = n.IndexOf("engtype_", IC);
                    string type = ti >= 0 ? n.Substring(ti) : "?";
                    double c; igByType.TryGetValue(type, out c); igByType[type] = c + val;
                }
                else if (nvAd != null && n.IndexOf(nvAd.Luid, IC) >= 0)
                {
                    int pid = ParsePid(n);
                    if (pid > 0) { double c; s.AllGpu.TryGetValue(pid, out c); s.AllGpu[pid] = Math.Min(100, c + val); }
                }
            }
            prevEng = next;
            if (igAd != null) { double mx = 0; foreach (var v in igByType.Values) mx = Math.Max(mx, v); s.IgUtil = Math.Min(100, mx); }
        }
        catch (Exception ex) { Diag += "engine: " + ex.Message + "\r\n"; }

        foreach (var kv in s.AllVram)
        {
            double u; s.AllGpu.TryGetValue(kv.Key, out u);
            s.Procs.Add(new GpuProc { Pid = kv.Key, Name = NameOf(kv.Key), VramMB = kv.Value, Util = u });
        }
        foreach (var kv in s.AllGpu)
            if (!s.AllVram.ContainsKey(kv.Key) && kv.Value >= 1)
                s.Procs.Add(new GpuProc { Pid = kv.Key, Name = NameOf(kv.Key), VramMB = 0, Util = kv.Value });
        s.Procs.Sort(delegate (GpuProc a, GpuProc b) { int c = b.VramMB.CompareTo(a.VramMB); return c != 0 ? c : b.Util.CompareTo(a.Util); });
        if (s.Procs.Count > 5) s.Procs.RemoveRange(5, s.Procs.Count - 5);
    }

    static int ParsePid(string n)
    {
        if (!n.StartsWith("pid_")) return -1;
        int e = n.IndexOf('_', 4); int pid;
        return e > 4 && int.TryParse(n.Substring(4, e - 4), out pid) ? pid : -1;
    }

    string NameOf(int pid)
    {
        string n;
        if (names.TryGetValue(pid, out n)) return n;
        try { using (var p = Process.GetProcessById(pid)) n = p.ProcessName; } catch { n = "pid " + pid; }
        if (names.Count > 500) names.Clear();
        names[pid] = n; return n;
    }
}

class OllamaPoller
{
    public volatile int State; // 0 checking, 1 not reachable, 2 running
    public volatile List<OllamaModel> Models = new List<OllamaModel>();
    public volatile string BaseUrl = "http://127.0.0.1:11434";
    public volatile string LastAction = "";
    readonly JavaScriptSerializer js = new JavaScriptSerializer();

    public void Poll()
    {
        try
        {
            var req = (HttpWebRequest)WebRequest.Create(BaseUrl + "/api/ps");
            req.Proxy = null; req.Timeout = 800; req.ReadWriteTimeout = 800;
            string body;
            using (var resp = req.GetResponse()) using (var r = new StreamReader(resp.GetResponseStream())) body = r.ReadToEnd();
            var root = js.Deserialize<Dictionary<string, object>>(body);
            var list = new List<OllamaModel>();
            object arr;
            if (root != null && root.TryGetValue("models", out arr) && arr is System.Collections.ArrayList)
            {
                foreach (var o in (System.Collections.ArrayList)arr)
                {
                    var d = o as Dictionary<string, object>; if (d == null) continue;
                    double size = Num(d, "size"), vram = Num(d, "size_vram");
                    var mdl = new OllamaModel
                    {
                        Name = d.ContainsKey("name") ? Convert.ToString(d["name"]) : "?",
                        SizeGB = size / 1073741824.0,
                        VramFrac = size > 0 ? vram / size : 0,
                        Ctx = (long)Num(d, "context_length")
                    };
                    DateTime ex;
                    if (d.ContainsKey("expires_at") && DateTime.TryParse(Convert.ToString(d["expires_at"]), null, DateTimeStyles.RoundtripKind, out ex))
                        mdl.Expires = ex.ToLocalTime();
                    list.Add(mdl);
                }
            }
            Models = list; State = 2;
        }
        catch { Models = new List<OllamaModel>(); State = 1; }
    }

    // keep_alive = 0 tells Ollama to unload the model and free its VRAM/RAM immediately.
    public void Unload(string model)
    {
        LastAction = "unloading " + model + "...";
        ThreadPool.QueueUserWorkItem(delegate
        {
            try
            {
                var req = (HttpWebRequest)WebRequest.Create(BaseUrl + "/api/generate");
                req.Method = "POST"; req.ContentType = "application/json"; req.Proxy = null; req.Timeout = 15000;
                var payload = new Dictionary<string, object>(); payload["model"] = model; payload["keep_alive"] = 0;
                var bytes = Encoding.UTF8.GetBytes(js.Serialize(payload));
                using (var st = req.GetRequestStream()) st.Write(bytes, 0, bytes.Length);
                using (req.GetResponse()) { }
                LastAction = "";
            }
            catch (Exception ex) { LastAction = "unload failed: " + ex.Message; }
            Poll();
        });
    }

    static double Num(Dictionary<string, object> d, string k)
    {
        object v; if (!d.TryGetValue(k, out v) || v == null) return 0;
        try { return Convert.ToDouble(v); } catch { return 0; }
    }
}

// ======================================================================= theme
static class Theme
{
    public static readonly Color Bg = Color.FromArgb(17, 20, 24), Panel = Color.FromArgb(28, 32, 38), Txt = Color.FromArgb(230, 232, 235),
        Dim = Color.FromArgb(138, 147, 160), Faint = Color.FromArgb(95, 102, 112), Green = Color.FromArgb(80, 200, 120), Amber = Color.FromArgb(240, 180, 60),
        Red = Color.FromArgb(240, 85, 85), Blue = Color.FromArgb(90, 160, 255), Purple = Color.FromArgb(180, 130, 255), Teal = Color.FromArgb(60, 200, 200),
        Border = Color.FromArgb(45, 50, 58), Input = Color.FromArgb(34, 38, 45);

    public static Button Btn(string text, int w)
    {
        var b = new Button { Text = text, Width = w, Height = 26, FlatStyle = FlatStyle.Flat, BackColor = Input, ForeColor = Txt, Margin = new Padding(4, 4, 0, 0) };
        b.FlatAppearance.BorderColor = Border;
        return b;
    }
}

// ======================================================================= task manager window
class DarkList : ListView
{
    public DarkList() { DoubleBuffered = true; }
}

class ProcForm : Form
{
    class Row { public SysProc P; public string Name; public double Cpu, Vram, Gpu; public bool Ai; }

    readonly MonitorForm owner;
    readonly DarkList lv = new DarkList();
    readonly TextBox filter = new TextBox();
    readonly CheckBox aiOnly = new CheckBox(), gpuOnly = new CheckBox();
    readonly Label status = new Label();
    readonly System.Windows.Forms.Timer timer = new System.Windows.Forms.Timer();
    List<Row> rows = new List<Row>();
    List<SysProc> lastAll = new List<SysProc>();
    Dictionary<int, long[]> prevCpu = new Dictionary<int, long[]>(); // pid -> {create, ticks}
    long prevStamp;
    int sortCol = 2; bool sortDesc = true;
    int selPid = -1; long selCreate; bool restoring;
    static readonly string[] Cols = { "Name", "PID", "CPU %", "Memory", "VRAM", "GPU %", "Threads" };
    static readonly int[] ColW = { 230, 64, 74, 90, 84, 64, 70 };
    static readonly int SelfPid = Process.GetCurrentProcess().Id;

    // Stretch the last column so the header has no unpainted strip on the right.
    void FillLastColumn()
    {
        if (lv.Columns.Count == 0) return;
        int used = 0;
        for (int i = 0; i < lv.Columns.Count - 1; i++) used += lv.Columns[i].Width;
        int w = lv.ClientSize.Width - used;
        if (w > 40) lv.Columns[lv.Columns.Count - 1].Width = w;
    }

    public ProcForm(MonitorForm owner)
    {
        this.owner = owner;
        Text = "Local AI Monitor - Processes";
        Icon = owner.Icon; BackColor = Theme.Bg; ForeColor = Theme.Txt;
        Font = new Font("Segoe UI", 9f);
        AutoScaleDimensions = new SizeF(96f, 96f); AutoScaleMode = AutoScaleMode.Dpi;
        StartPosition = FormStartPosition.Manual;
        var c = owner.Config;
        Size = new Size(c.ProcW, c.ProcH); MinimumSize = new Size(520, 300);
        var wa = Screen.FromControl(owner).WorkingArea;
        Location = new Point(Math.Max(wa.Left, Math.Min(owner.Left - Width - 8, wa.Right - Width)), Math.Max(wa.Top, owner.Top));
        KeyPreview = true;

        var bar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, Padding = new Padding(4, 2, 4, 0), BackColor = Theme.Bg, WrapContents = false };
        var fl = new Label { Text = "Filter", AutoSize = true, ForeColor = Theme.Dim, Margin = new Padding(4, 9, 0, 0) };
        filter.Width = 170; filter.BackColor = Theme.Input; filter.ForeColor = Theme.Txt; filter.BorderStyle = BorderStyle.FixedSingle; filter.Margin = new Padding(6, 6, 6, 0);
        filter.TextChanged += delegate { Rebuild(); };
        aiOnly.Text = "AI only"; aiOnly.AutoSize = true; aiOnly.ForeColor = Theme.Teal; aiOnly.Margin = new Padding(6, 8, 0, 0);
        gpuOnly.Text = "Using GPU"; gpuOnly.AutoSize = true; gpuOnly.ForeColor = Theme.Purple; gpuOnly.Margin = new Padding(6, 8, 6, 0);
        aiOnly.CheckedChanged += delegate { Rebuild(); }; gpuOnly.CheckedChanged += delegate { Rebuild(); };
        var end = Theme.Btn("End task", 80); end.Click += delegate { EndSelected(false); };
        var tree = Theme.Btn("End tree", 80); tree.Click += delegate { EndSelected(true); };
        var loc = Theme.Btn("Open location", 104); loc.Click += delegate { OpenLocation(); };
        bar.Controls.AddRange(new Control[] { fl, filter, aiOnly, gpuOnly, end, tree, loc });

        status.Dock = DockStyle.Bottom; status.Height = 24; status.ForeColor = Theme.Dim; status.BackColor = Theme.Panel;
        status.TextAlign = ContentAlignment.MiddleLeft; status.Padding = new Padding(6, 0, 0, 0);

        lv.Dock = DockStyle.Fill; lv.View = View.Details; lv.FullRowSelect = true; lv.MultiSelect = false; lv.HideSelection = false;
        lv.VirtualMode = true; lv.BackColor = Theme.Bg; lv.ForeColor = Theme.Txt; lv.BorderStyle = BorderStyle.None; lv.OwnerDraw = true;
        for (int i = 0; i < Cols.Length; i++) lv.Columns.Add(Cols[i], ColW[i], i == 0 ? HorizontalAlignment.Left : HorizontalAlignment.Right);
        lv.RetrieveVirtualItem += OnItem;
        lv.ColumnClick += delegate (object s, ColumnClickEventArgs e)
        {
            if (sortCol == e.Column) sortDesc = !sortDesc; else { sortCol = e.Column; sortDesc = e.Column >= 2; }
            Rebuild();
        };
        lv.SelectedIndexChanged += delegate
        {
            if (restoring) return;
            if (lv.SelectedIndices.Count > 0 && lv.SelectedIndices[0] < rows.Count) { var r = rows[lv.SelectedIndices[0]]; selPid = r.P.Pid; selCreate = r.P.Create; }
            else selPid = -1;
        };
        lv.DrawColumnHeader += DrawHeader;
        lv.DrawItem += delegate (object s, DrawListViewItemEventArgs e) { e.DrawDefault = true; };
        lv.DrawSubItem += delegate (object s, DrawListViewSubItemEventArgs e) { e.DrawDefault = true; };
        lv.DoubleClick += delegate { OpenLocation(); };
        lv.Resize += delegate { FillLastColumn(); };
        lv.ColumnWidthChanged += delegate (object s, ColumnWidthChangedEventArgs e) { if (e.ColumnIndex != lv.Columns.Count - 1) FillLastColumn(); };

        var menu = new ContextMenuStrip();
        menu.Items.Add("End task", null, delegate { EndSelected(false); });
        menu.Items.Add("End process tree", null, delegate { EndSelected(true); });
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add("Open file location", null, delegate { OpenLocation(); });
        menu.Items.Add("Copy name", null, delegate { var r = Selected(); if (r != null) Clipboard.SetText(r.Name); });
        menu.Items.Add("Copy PID", null, delegate { var r = Selected(); if (r != null) Clipboard.SetText(r.P.Pid.ToString()); });
        lv.ContextMenuStrip = menu;

        Controls.Add(lv); Controls.Add(bar); Controls.Add(status);

        timer.Interval = c.ProcRefreshMs; timer.Tick += delegate { Sample(); };
        Sample();
        timer.Start();
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        Win.DarkTitle(this);
        try { Win.SetWindowTheme(lv.Handle, "DarkMode_Explorer", null); } catch { }
    }

    protected override void OnShown(EventArgs e) { base.OnShown(e); filter.Focus(); }

    public void ApplyConfig() { timer.Interval = owner.Config.ProcRefreshMs; Rebuild(); }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        if (e.KeyCode == Keys.Delete && !filter.Focused) { EndSelected(e.Shift); e.Handled = true; }
        else if (e.KeyCode == Keys.F && e.Control) { filter.Focus(); filter.SelectAll(); e.Handled = true; }
        else if (e.KeyCode == Keys.F5) { Sample(); e.Handled = true; }
        else if (e.KeyCode == Keys.Escape) { if (filter.Text.Length > 0) filter.Text = ""; else Close(); e.Handled = true; }
        else if (e.KeyCode == Keys.Down && filter.Focused && rows.Count > 0) { lv.Focus(); lv.SelectedIndices.Clear(); lv.SelectedIndices.Add(0); e.Handled = true; }
        base.OnKeyDown(e);
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        timer.Stop();
        if (WindowState == FormWindowState.Normal) { owner.Config.ProcW = Width; owner.Config.ProcH = Height; owner.SaveSettings(); }
        base.OnFormClosed(e);
    }

    void DrawHeader(object s, DrawListViewColumnHeaderEventArgs e)
    {
        using (var b = new SolidBrush(Theme.Panel)) e.Graphics.FillRectangle(b, e.Bounds);
        using (var p = new Pen(Theme.Border)) e.Graphics.DrawLine(p, e.Bounds.Right - 1, e.Bounds.Top + 4, e.Bounds.Right - 1, e.Bounds.Bottom - 4);
        string t = Cols[e.ColumnIndex] + (e.ColumnIndex == sortCol ? (sortDesc ? " ▼" : " ▲") : "");
        var flags = TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | (e.ColumnIndex == 0 ? TextFormatFlags.Left : TextFormatFlags.Right);
        var r = new Rectangle(e.Bounds.X + 6, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height);
        TextRenderer.DrawText(e.Graphics, t, lv.Font, r, e.ColumnIndex == sortCol ? Theme.Txt : Theme.Dim, flags);
    }

    void Sample()
    {
        lastAll = NtProc.Snapshot();
        long stamp = Stopwatch.GetTimestamp();
        double wall100ns = prevStamp == 0 ? 0 : (stamp - prevStamp) * 1e7 / Stopwatch.Frequency;
        prevStamp = stamp;
        var next = new Dictionary<int, long[]>(lastAll.Count);
        var snap = owner.CurrentSnap;
        var kw = owner.Config.Keywords();
        var all = new List<Row>(lastAll.Count);
        foreach (var p in lastAll)
        {
            if (p.Pid == 0) continue;
            long[] prev; double cpu = 0;
            if (wall100ns > 0 && prevCpu.TryGetValue(p.Pid, out prev) && prev[0] == p.Create)
                cpu = Math.Max(0, (p.CpuTicks - prev[1]) / wall100ns / Environment.ProcessorCount * 100.0);
            next[p.Pid] = new long[] { p.Create, p.CpuTicks };
            var r = new Row { P = p, Name = p.Name, Cpu = cpu };
            if (snap != null) { double v; if (snap.AllVram.TryGetValue(p.Pid, out v)) r.Vram = v; if (snap.AllGpu.TryGetValue(p.Pid, out v)) r.Gpu = v; }
            string ln = p.Name.ToLowerInvariant();
            if (p.Pid != SelfPid) foreach (var k in kw) if (ln.Contains(k)) { r.Ai = true; break; }
            all.Add(r);
        }
        prevCpu = next;
        allRows = all;
        Rebuild();
    }

    List<Row> allRows = new List<Row>();

    void Rebuild()
    {
        string f = filter.Text.Trim().ToLowerInvariant();
        var list = new List<Row>(allRows.Count);
        double cpuSum = 0, vramSum = 0; long memSum = 0;
        foreach (var r in allRows)
        {
            cpuSum += r.Cpu; memSum += r.P.PrivateWs; vramSum += r.Vram;
            if (aiOnly.Checked && !r.Ai) continue;
            if (gpuOnly.Checked && r.Vram <= 0 && r.Gpu < 0.5) continue;
            if (f.Length > 0 && r.Name.ToLowerInvariant().IndexOf(f, StringComparison.Ordinal) < 0 && r.P.Pid.ToString() != f) continue;
            list.Add(r);
        }
        int col = sortCol; bool desc = sortDesc;
        list.Sort(delegate (Row a, Row b)
        {
            int c;
            switch (col)
            {
                case 0: c = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase); break;
                case 1: c = a.P.Pid.CompareTo(b.P.Pid); break;
                case 2: c = a.Cpu.CompareTo(b.Cpu); break;
                case 3: c = a.P.PrivateWs.CompareTo(b.P.PrivateWs); break;
                case 4: c = a.Vram.CompareTo(b.Vram); break;
                case 5: c = a.Gpu.CompareTo(b.Gpu); break;
                default: c = a.P.Threads.CompareTo(b.P.Threads); break;
            }
            if (c == 0) c = string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
            return desc ? -c : c;
        });
        rows = list;
        restoring = true;
        try
        {
            lv.VirtualListSize = rows.Count;
            lv.SelectedIndices.Clear();
            if (selPid > 0)
                for (int i = 0; i < rows.Count; i++)
                    if (rows[i].P.Pid == selPid && rows[i].P.Create == selCreate) { lv.SelectedIndices.Add(i); break; }
        }
        finally { restoring = false; }
        lv.Invalidate();
        status.Text = string.Format("{0} processes ({1} shown)   ·   CPU {2:0}%   ·   private memory {3:0.0} GB   ·   VRAM by processes {4:0.0} GB   ·   Del = end task, Shift+Del = end tree",
            allRows.Count, rows.Count, Math.Min(100, cpuSum), memSum / 1073741824.0, vramSum / 1024.0);
    }

    void OnItem(object s, RetrieveVirtualItemEventArgs e)
    {
        if (e.ItemIndex >= rows.Count) { e.Item = new ListViewItem(new[] { "", "", "", "", "", "", "" }); return; }
        var r = rows[e.ItemIndex];
        var it = new ListViewItem(new[] {
            r.Name, r.P.Pid.ToString(), r.Cpu >= 0.05 ? r.Cpu.ToString("0.0") : "0",
            (r.P.PrivateWs / 1048576.0).ToString("N0") + " MB",
            r.Vram > 0 ? r.Vram.ToString("N0") + " MB" : "", r.Gpu >= 0.5 ? r.Gpu.ToString("0") + "%" : "", r.P.Threads.ToString() });
        it.BackColor = e.ItemIndex % 2 == 0 ? Theme.Bg : Color.FromArgb(21, 24, 29);
        it.ForeColor = r.Ai ? Theme.Teal : r.Cpu >= 25 ? Theme.Amber : r.Vram > 0 ? Theme.Purple : Theme.Txt;
        e.Item = it;
    }

    Row Selected()
    {
        if (lv.SelectedIndices.Count == 0) return null;
        int i = lv.SelectedIndices[0];
        return i < rows.Count ? rows[i] : null;
    }

    void EndSelected(bool tree)
    {
        var r = Selected(); if (r == null) return;
        owner.EndTask(this, r.P.Pid, r.P.Create, r.Name, tree);
        Sample();
    }

    void OpenLocation()
    {
        var r = Selected(); if (r == null) return;
        string path = Killer.PathOf(r.P.Pid);
        if (path == null) { MessageBox.Show(this, "Windows did not give access to this process's file path.", "Open file location", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        try { Process.Start("explorer.exe", "/select,\"" + path + "\""); } catch { }
    }
}

// ======================================================================= settings window
class SettingsForm : Form
{
    public Cfg Result;
    readonly PropertyGrid grid = new PropertyGrid();

    public SettingsForm(Cfg current, Icon icon)
    {
        Text = "Local AI Monitor - Settings"; Icon = icon;
        AutoScaleDimensions = new SizeF(96f, 96f); AutoScaleMode = AutoScaleMode.Dpi;
        Font = new Font("Segoe UI", 9f); BackColor = Theme.Bg; ForeColor = Theme.Txt;
        Size = new Size(460, 600); MinimumSize = new Size(380, 400); StartPosition = FormStartPosition.CenterScreen;
        MinimizeBox = false; MaximizeBox = false; ShowInTaskbar = false;
        grid.Dock = DockStyle.Fill; grid.ToolbarVisible = false; grid.PropertySort = PropertySort.Categorized;
        grid.SelectedObject = current.Clone();
        grid.BackColor = Theme.Bg; grid.ViewBackColor = Theme.Bg; grid.ViewForeColor = Theme.Txt; grid.LineColor = Theme.Panel;
        grid.CategoryForeColor = Theme.Teal; grid.HelpBackColor = Theme.Panel; grid.HelpForeColor = Theme.Dim;
        try { grid.CategorySplitterColor = Theme.Panel; grid.ViewBorderColor = Theme.Border; grid.HelpBorderColor = Theme.Border; grid.SelectedItemWithFocusBackColor = Color.FromArgb(40, 70, 110); } catch { }

        var bar = new FlowLayoutPanel { Dock = DockStyle.Bottom, Height = 40, FlowDirection = FlowDirection.RightToLeft, Padding = new Padding(4), BackColor = Theme.Bg };
        var ok = Theme.Btn("Save", 80); var cancel = Theme.Btn("Cancel", 80); var reset = Theme.Btn("Defaults", 80);
        ok.Click += delegate { Result = (Cfg)grid.SelectedObject; Result.Normalize(); DialogResult = DialogResult.OK; Close(); };
        cancel.Click += delegate { DialogResult = DialogResult.Cancel; Close(); };
        reset.Click += delegate
        {
            var d = new Cfg(); var cur = (Cfg)grid.SelectedObject;
            d.X = cur.X; d.Y = cur.Y; d.Width = cur.Width; d.Height = cur.Height; d.ProcW = cur.ProcW; d.ProcH = cur.ProcH; d.StartWithWindows = cur.StartWithWindows;
            grid.SelectedObject = d;
        };
        bar.Controls.AddRange(new Control[] { ok, cancel, reset });
        AcceptButton = ok; CancelButton = cancel;
        Controls.Add(grid); Controls.Add(bar);
    }

    protected override void OnHandleCreated(EventArgs e) { base.OnHandleCreated(e); Win.DarkTitle(this); }
}

// ======================================================================= main widget
class MonitorForm : Form
{
    const int Hist = 120;
    readonly Sampler sampler;
    readonly OllamaPoller ollama = new OllamaPoller();
    public Cfg Config = new Cfg();
    volatile Snap snap;
    public Snap CurrentSnap { get { return snap; } }
    readonly float[] hCpu = new float[Hist], hGpu = new float[Hist], hVram = new float[Hist];
    int hPos, samples;
    volatile bool running = true;
    readonly AutoResetEvent wake = new AutoResetEvent(false);
    float dpi = 1f;
    float S { get { return dpi * Config.ZoomPct / 100f; } }
    int naturalH = 300;            // content height (logical px) at default graph size
    readonly string iniPath;
    bool beat;
    DateTime lastSample = DateTime.MinValue;
    readonly System.Windows.Forms.Timer staleTimer = new System.Windows.Forms.Timer();
    ProcForm procForm;
    Size sizeAtResizeBegin;

    class Target { public RectangleF R; public Action Do; public bool Danger; }
    List<Target> targets = new List<Target>();
    int hover = -1;

    readonly Font fH, fB, fS, fBig;

    public MonitorForm()
    {
        iniPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "LocalAIMonitor.ini");
        FormBorderStyle = FormBorderStyle.None; StartPosition = FormStartPosition.Manual;
        BackColor = Theme.Bg; DoubleBuffered = true; Text = "Local AI Monitor"; ShowInTaskbar = true;
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        using (var g = CreateGraphics()) dpi = g.DpiX / 96f;
        fH = new Font("Segoe UI Semibold", 12.5f, GraphicsUnit.Pixel);
        fB = new Font("Segoe UI", 12f, GraphicsUnit.Pixel);
        fS = new Font("Segoe UI", 10.5f, GraphicsUnit.Pixel);
        fBig = new Font("Segoe UI Semibold", 17f, GraphicsUnit.Pixel);
        Icon = MakeIcon();
        LoadSettings();
        BuildMenu();
        sampler = new Sampler();
        var t = new Thread(SampleLoop) { IsBackground = true, Name = "sampler", Priority = ThreadPriority.BelowNormal }; t.Start();
        var o = new Thread(OllamaLoop) { IsBackground = true, Name = "ollama" }; o.Start();
        staleTimer.Interval = 1000;
        staleTimer.Tick += delegate { if (snap != null && (DateTime.Now - lastSample).TotalMilliseconds > Config.RefreshMs * 3 + 1500) Invalidate(); };
        staleTimer.Start();
    }

    Icon MakeIcon()
    {
        using (var b = new Bitmap(32, 32))
        using (var g = Graphics.FromImage(b))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias; g.Clear(Color.Transparent);
            using (var br = new SolidBrush(Theme.Bg)) g.FillEllipse(br, 1, 1, 30, 30);
            using (var p = new Pen(Theme.Green, 3f)) g.DrawLines(p, new[] { new Point(5, 19), new Point(11, 19), new Point(14, 9), new Point(18, 24), new Point(21, 15), new Point(27, 15) });
            IntPtr h = b.GetHicon(); var ic = (Icon)Icon.FromHandle(h).Clone(); Win.DestroyIcon(h); return ic;
        }
    }

    void SampleLoop()
    {
        while (running)
        {
            var sw = Stopwatch.StartNew();
            Snap s;
            try { s = sampler.Sample(); } catch { s = new Snap(); }
            s.SampleMs = sw.Elapsed.TotalMilliseconds;
            hCpu[hPos] = (float)Math.Max(0, s.Cpu);
            hGpu[hPos] = (float)Math.Max(0, s.NvUtil);
            hVram[hPos] = s.VramTotal > 0 ? (float)(100 * s.VramUsed / s.VramTotal) : 0;
            hPos = (hPos + 1) % Hist; samples++;
            snap = s; lastSample = DateTime.Now; beat = !beat;
            try { if (IsHandleCreated) BeginInvoke((MethodInvoker)Invalidate); } catch { }
            wake.WaitOne(Math.Max(100, Config.RefreshMs - (int)sw.ElapsedMilliseconds));
        }
    }

    void OllamaLoop()
    {
        while (running)
        {
            ollama.BaseUrl = Config.OllamaUrl;
            if (Config.ShowOllama) ollama.Poll();
            Thread.Sleep(ollama.State == 2 ? 2000 : 5000);
        }
    }

    // ---------------------------------------------------------------- settings
    void LoadSettings()
    {
        try { if (File.Exists(iniPath)) Config.FromLines(File.ReadAllLines(iniPath)); } catch { }
        Config.StartWithWindows = StartupEnabled();
        var wa = Screen.PrimaryScreen.WorkingArea;
        Size = new Size((int)(Config.Width * S), (int)(Config.Height * S));
        bool onScreen = false;
        foreach (var sc in Screen.AllScreens) if (sc.WorkingArea.Contains(new Point(Config.X + 40, Config.Y + 10))) onScreen = true;
        Location = onScreen ? new Point(Config.X, Config.Y) : new Point(wa.Right - Width - 16, wa.Top + 16);
        ApplyWindowConfig();
    }

    void ApplyWindowConfig()
    {
        TopMost = Config.TopMost; Opacity = Config.OpacityPct / 100.0;
        MinimumSize = new Size((int)(280 * S), (int)(120 * S));
        ollama.BaseUrl = Config.OllamaUrl;
    }

    public void SaveSettings()
    {
        if (WindowState == FormWindowState.Normal)
        {
            Config.X = Left; Config.Y = Top;
            Config.Width = (int)Math.Round(ClientSize.Width / S); Config.Height = (int)Math.Round(ClientSize.Height / S);
        }
        try { File.WriteAllLines(iniPath, Config.ToLines()); } catch { }
    }

    const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    static bool StartupEnabled()
    {
        try { using (var k = Registry.CurrentUser.OpenSubKey(RunKey)) return k != null && k.GetValue("LocalAIMonitor") != null; } catch { return false; }
    }

    static string SetStartup(bool on)
    {
        try
        {
            using (var k = Registry.CurrentUser.CreateSubKey(RunKey))
                if (on) k.SetValue("LocalAIMonitor", "\"" + Application.ExecutablePath + "\"");
                else k.DeleteValue("LocalAIMonitor", false);
            return null;
        }
        catch (Exception ex) { return ex.Message; }
    }

    void OpenSettings()
    {
        Config.StartWithWindows = StartupEnabled();
        using (var f = new SettingsForm(Config, Icon))
        {
            f.TopMost = TopMost;
            if (f.ShowDialog(this) != DialogResult.OK || f.Result == null) return;
            var n = f.Result;
            float oldS = S;
            n.X = Left; n.Y = Top;
            if (n.StartWithWindows != StartupEnabled())
            {
                string err = SetStartup(n.StartWithWindows);
                if (err != null) MessageBox.Show(this, "Could not change the startup setting: " + err, "Settings", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            int logicalW = (int)Math.Round(ClientSize.Width / oldS), logicalH = (int)Math.Round(ClientSize.Height / oldS);
            Config = n;
            ApplyWindowConfig();
            ClientSize = new Size((int)(logicalW * S), (int)(logicalH * S));
            wake.Set();
            if (procForm != null && !procForm.IsDisposed) procForm.ApplyConfig();
            SaveSettings(); Invalidate();
        }
    }

    void BuildMenu()
    {
        var m = new ContextMenuStrip();
        var procs = new ToolStripMenuItem("Processes / end task...", null, delegate { ShowProcesses(); });
        var settings = new ToolStripMenuItem("Settings...", null, delegate { OpenSettings(); });
        var top = new ToolStripMenuItem("Always on top") { CheckOnClick = true };
        top.CheckedChanged += delegate { Config.TopMost = top.Checked; TopMost = top.Checked; SaveSettings(); };
        var fit = new ToolStripMenuItem("Fit height to content", null, delegate { Config.AutoHeight = true; FitHeight(naturalH, true); SaveSettings(); });
        var compact = new ToolStripMenuItem("Compact mode") { CheckOnClick = true };
        compact.CheckedChanged += delegate { Config.Compact = compact.Checked; SaveSettings(); Invalidate(); };
        var tm = new ToolStripMenuItem("Open Windows Task Manager", null, delegate { try { Process.Start("taskmgr.exe"); } catch { } });
        var admin = new ToolStripMenuItem("Restart as administrator", null, delegate { RestartElevated(); });
        var exit = new ToolStripMenuItem("Exit", null, delegate { Close(); });
        m.Items.AddRange(new ToolStripItem[] { procs, settings, new ToolStripSeparator(), top, compact, fit, new ToolStripSeparator(), tm, admin, new ToolStripSeparator(), exit });
        m.Opening += delegate { top.Checked = Config.TopMost; compact.Checked = Config.Compact; fit.Enabled = !Config.AutoHeight; admin.Visible = !IsElevated(); };
        ContextMenuStrip = m;
    }

    static bool IsElevated()
    {
        try { return new System.Security.Principal.WindowsPrincipal(System.Security.Principal.WindowsIdentity.GetCurrent()).IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator); }
        catch { return false; }
    }

    void RestartElevated()
    {
        SaveSettings();
        try
        {
            Process.Start(new ProcessStartInfo(Application.ExecutablePath, "--handoff") { Verb = "runas", UseShellExecute = true });
            Close();
        }
        catch (Win32Exception) { /* user cancelled the UAC prompt: keep running */ }
    }

    public void ShowProcesses()
    {
        if (procForm == null || procForm.IsDisposed) { procForm = new ProcForm(this); procForm.Show(); }
        else { if (procForm.WindowState == FormWindowState.Minimized) procForm.WindowState = FormWindowState.Normal; procForm.Activate(); }
    }

    // Shared by the widget's GPU list and the Processes window.
    public void EndTask(IWin32Window parent, int pid, long create, string name, bool tree)
    {
        var all = NtProc.Snapshot();
        SysProc p = null; foreach (var x in all) if (x.Pid == pid) p = x;
        if (p == null) return;
        if (create == 0) create = p.Create;
        if (Killer.IsCritical(p)) { MessageBox.Show(parent, p.Name + " is a critical Windows process and is protected from being ended here.", "End task", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }
        int kids = tree ? Killer.Children(all, p).Count : 0;
        if (Config.ConfirmEndTask)
        {
            string q = "End " + name + " (PID " + pid + ")" + (tree ? " and " + kids + " child process" + (kids == 1 ? "" : "es") : "") +
                "?\n\nIts CPU, RAM and GPU memory will be freed. Unsaved work in it will be lost.";
            if (MessageBox.Show(parent, q, "End task", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes) return;
        }
        string err = Killer.Kill(pid, create, tree);
        if (err != null) MessageBox.Show(parent, err, "End task", MessageBoxButtons.OK, MessageBoxIcon.Error);
        wake.Set();
    }

    // ---------------------------------------------------------------- window behaviour
    protected override void WndProc(ref Message m)
    {
        base.WndProc(ref m);
        if (m.Msg == 0x84 && WindowState == FormWindowState.Normal) // WM_NCHITTEST: resizable borderless edges
        {
            long lp = m.LParam.ToInt64();
            var p = PointToClient(new Point((short)(lp & 0xFFFF), (short)((lp >> 16) & 0xFFFF)));
            int g = Math.Max(5, (int)(6 * dpi)), w = ClientSize.Width, h = ClientSize.Height;
            bool l = p.X < g, r = p.X >= w - g, t = p.Y < g, b = p.Y >= h - g;
            int code = t && l ? 13 : t && r ? 14 : b && l ? 16 : b && r ? 17 : l ? 10 : r ? 11 : t ? 12 : b ? 15 : 0;
            if (code != 0) m.Result = (IntPtr)code;
        }
    }

    protected override void OnResizeBegin(EventArgs e) { base.OnResizeBegin(e); sizeAtResizeBegin = Size; }

    protected override void OnResizeEnd(EventArgs e)
    {
        base.OnResizeEnd(e);
        if (Size.Height != sizeAtResizeBegin.Height && sizeAtResizeBegin.Height > 0) Config.AutoHeight = false;
        SaveSettings();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        if (Array.IndexOf(Environment.GetCommandLineArgs(), "--tasks") > 0) ShowProcesses();
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        if ((ModifierKeys & Keys.Control) == 0) return;
        float oldS = S;
        int lw = (int)Math.Round(ClientSize.Width / oldS), lh = (int)Math.Round(ClientSize.Height / oldS);
        Config.ZoomPct = Math.Max(60, Math.Min(250, Config.ZoomPct + (e.Delta > 0 ? 10 : -10)));
        MinimumSize = new Size((int)(280 * S), (int)(120 * S));
        ClientSize = new Size((int)(lw * S), (int)(lh * S));
        SaveSettings(); Invalidate();
    }

    int HitTarget(Point client)
    {
        var p = new PointF(client.X / S, client.Y / S);
        for (int i = 0; i < targets.Count; i++) if (targets[i].R.Contains(p)) return i;
        return -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int h = HitTarget(e.Location);
        Cursor = h >= 0 ? Cursors.Hand : Cursors.Default;
        if (h != hover) { hover = h; Invalidate(); }
    }

    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); if (hover != -1) { hover = -1; Invalidate(); } }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button != MouseButtons.Left) return;
        int h = HitTarget(e.Location);
        if (h >= 0) { targets[h].Do(); return; }
        Win.ReleaseCapture(); Win.SendMessage(Handle, 0xA1, (IntPtr)2, IntPtr.Zero); // drag window
        SaveSettings();
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (e.Control && e.KeyCode == Keys.T) ShowProcesses();
        else if (e.Control && e.KeyCode == Keys.Oemcomma) OpenSettings();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        running = false; wake.Set(); SaveSettings(); base.OnFormClosing(e);
    }

    // ---------------------------------------------------------------- drawing
    static Color LoadColor(double pct) { return pct >= 90 ? Theme.Red : pct >= 70 ? Theme.Amber : Theme.Green; }
    static string GB(double bytes) { return (bytes / 1073741824.0).ToString("0.0"); }
    static readonly StringFormat Typo = StringFormat.GenericTypographic;

    void Bar(Graphics g, float x, float y, float w, float h, double pct, Color c)
    {
        using (var b = new SolidBrush(Theme.Panel)) g.FillRectangle(b, x, y, w, h);
        if (pct > 0) using (var b = new SolidBrush(c)) g.FillRectangle(b, x, y, (float)(w * Math.Min(100, pct) / 100.0), h);
    }

    void Spark(Graphics g, RectangleF r, float[] h, Color c)
    {
        using (var b = new SolidBrush(Theme.Panel)) g.FillRectangle(b, r);
        int n = Math.Min(samples, Hist); if (n < 2) return;
        int shown = Math.Min(n, Math.Max(10, (int)(r.Width / 2)));
        var pts = new PointF[shown + 2];
        for (int i = 0; i < shown; i++)
        {
            float v = h[(hPos - shown + i + Hist * 2) % Hist];
            pts[i] = new PointF(r.Right - (shown - 1 - i) * r.Width / (Math.Max(10, (int)(r.Width / 2)) - 1), r.Bottom - 1 - v / 100f * (r.Height - 2));
        }
        pts[shown] = new PointF(r.Right, r.Bottom); pts[shown + 1] = new PointF(pts[0].X, r.Bottom);
        using (var b = new SolidBrush(Color.FromArgb(60, c))) g.FillPolygon(b, pts);
        var line = new PointF[shown]; Array.Copy(pts, line, shown);
        using (var p = new Pen(c, 1.3f)) g.DrawLines(p, line);
    }

    void T(Graphics g, string s, Font f, Color c, float x, float y) { using (var b = new SolidBrush(c)) g.DrawString(s, f, b, x, y); }

    float TR(Graphics g, string s, Font f, Color c, float right, float y)
    {
        var sz = g.MeasureString(s, f, PointF.Empty, Typo);
        using (var b = new SolidBrush(c)) g.DrawString(s, f, b, right - sz.Width, y, Typo);
        return sz.Width;
    }

    void Section(Graphics g, string s, float y, float R)
    {
        T(g, s, fS, Theme.Dim, 10, y);
        using (var p = new Pen(Theme.Panel)) g.DrawLine(p, 14 + g.MeasureString(s, fS).Width, y + 8, R, y + 8);
    }

    // Clickable text; returns its width.
    float Link(Graphics g, string s, Font f, Color normal, Color hot, float right, float y, Action act, bool danger)
    {
        var sz = g.MeasureString(s, f, PointF.Empty, Typo);
        var r = new RectangleF(right - sz.Width - 3, y - 1, sz.Width + 6, sz.Height + 2);
        int idx = targets.Count;
        targets.Add(new Target { R = r, Do = act, Danger = danger });
        bool isHot = idx == hover;
        if (isHot) using (var b = new SolidBrush(Theme.Panel)) g.FillRectangle(b, r);
        using (var b = new SolidBrush(isHot ? hot : normal)) g.DrawString(s, f, b, right - sz.Width, y, Typo);
        return sz.Width + 6;
    }

    static string Cut(string s, int n) { return s.Length > n ? s.Substring(0, n - 1) + "…" : s; }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        float sc = S;
        g.ScaleTransform(sc, sc);
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        g.Clear(Theme.Bg);
        float W = ClientSize.Width / sc, H = ClientSize.Height / sc;
        using (var p = new Pen(Theme.Border)) g.DrawRectangle(p, 0, 0, W - 1, H - 1);
        // resize grip hint
        using (var p = new Pen(Theme.Faint)) { g.DrawLine(p, W - 4, H - 10, W - 10, H - 4); g.DrawLine(p, W - 4, H - 6, W - 6, H - 4); }
        targets = new List<Target>();
        var c = Config;
        var s = snap;
        float y = 8;
        const float L = 10; float R = W - 10;
        float extra = 0;
        int graphs = (s != null && s.HasNv) ? 2 : 1;
        if (!c.AutoHeight) extra = Math.Max(0, Math.Min(400, (H - naturalH) / graphs));
        float gh = 22 + extra, used = 0;
        float sparkW = Math.Max(110, (W - 20) * 0.4f);

        // header
        bool stale = s != null && (DateTime.Now - lastSample).TotalMilliseconds > c.RefreshMs * 3 + 1500;
        Color hb = s == null ? Theme.Dim : stale ? Theme.Red : (beat ? Theme.Green : Color.FromArgb(40, 110, 70));
        using (var b = new SolidBrush(hb)) g.FillEllipse(b, L, y + 4, 8, 8);
        T(g, W >= 330 ? "Local AI Monitor" : "AI Monitor", fH, Theme.Txt, L + 13, y - 1);
        float hx = R;
        hx -= Link(g, "×", fH, Theme.Dim, Theme.Red, hx, y - 2, delegate { Close(); }, false);
        hx -= Link(g, "–", fH, Theme.Dim, Theme.Txt, hx, y - 2, delegate { WindowState = FormWindowState.Minimized; }, false);
        hx -= Link(g, "⚙", fB, Theme.Dim, Theme.Txt, hx, y, delegate { OpenSettings(); }, false);
        hx -= Link(g, "Tasks", fS, Theme.Teal, Theme.Txt, hx - 2, y + 2, delegate { ShowProcesses(); }, false) + 6;
        if (W >= 340)
        {
            string status = s == null ? "starting..." : stale ? "STALLED " + (int)(DateTime.Now - lastSample).TotalSeconds + "s" : DateTime.Now.ToString("HH:mm:ss");
            TR(g, status, fS, stale ? Theme.Red : Theme.Faint, hx - 4, y + 2);
        }
        y += 24;
        if (s == null) { T(g, "Collecting first sample...", fB, Theme.Dim, L, y); FitHeight((int)(y + 30), false); return; }

        var alerts = new List<KeyValuePair<Color, string>>();

        // CPU
        Section(g, "CPU  ·  " + sampler.CpuName, y, R); y += 18;
        T(g, s.Cpu >= 0 ? s.Cpu.ToString("0") + "%" : "n/a", fBig, LoadColor(s.Cpu), L, y - 3);
        T(g, (s.CpuGhz > 0 ? s.CpuGhz.ToString("0.00") + " GHz" : "") + "  ·  " + s.Cores.Length + " thr", fS, Theme.Dim, L + 50, y + 4);
        Spark(g, new RectangleF(R - sparkW, y, sparkW, gh), hCpu, Theme.Blue);
        y += gh + 4; used += extra;
        if (c.ShowCores && s.Cores.Length > 0)
        {
            float cw = (R - L) / s.Cores.Length;
            for (int i = 0; i < s.Cores.Length; i++)
            {
                float bx = L + i * cw;
                using (var b = new SolidBrush(Theme.Panel)) g.FillRectangle(b, bx, y, cw - 2, 16);
                float hh = (float)(16 * s.Cores[i] / 100.0);
                using (var b = new SolidBrush(LoadColor(s.Cores[i]))) g.FillRectangle(b, bx, y + 16 - hh, cw - 2, hh);
            }
            y += 20;
        }

        // RAM
        double ramPct = s.RamTotal > 0 ? 100 * s.RamUsed / s.RamTotal : 0;
        T(g, "RAM", fB, Theme.Txt, L, y);
        TR(g, GB(s.RamUsed) + " / " + GB(s.RamTotal) + " GB (" + ramPct.ToString("0") + "%) · free " + GB(s.RamTotal - s.RamUsed), fS, ramPct >= c.RamAlertPct ? Theme.Red : Theme.Dim, R, y + 2);
        y += 17; Bar(g, L, y, R - L, 6, ramPct, LoadColor(ramPct)); y += 10;
        double cPct = s.CommitLimit > 0 ? 100 * s.CommitUsed / s.CommitLimit : 0;
        if (!c.Compact)
        {
            T(g, "Commit " + GB(s.CommitUsed) + " / " + GB(s.CommitLimit) + " GB" + (s.DiskRead >= 0 ? "   ·   Disk read " + (s.DiskRead / 1048576).ToString("0") + " MB/s" : ""), fS, Theme.Dim, L, y);
            y += 16;
        }
        y += 2;
        if (ramPct >= c.RamAlertPct) alerts.Add(new KeyValuePair<Color, string>(Theme.Red, "RAM " + ramPct.ToString("0") + "% - CPU-offloaded layers may page to disk"));
        if (cPct >= 90) alerts.Add(new KeyValuePair<Color, string>(Theme.Amber, "Commit charge " + cPct.ToString("0") + "% - near paging limit"));

        // NVIDIA
        if (s.HasNv)
        {
            Section(g, "GPU  ·  " + s.NvName + (s.Pstate >= 0 ? "  ·  P" + s.Pstate : ""), y, R); y += 18;
            T(g, s.NvUtil >= 0 ? s.NvUtil.ToString("0") + "%" : "n/a", fBig, LoadColor(s.NvUtil), L, y - 3);
            string tp = (s.Temp >= 0 ? s.Temp.ToString("0") + "°C" : "") + (s.Power >= 0 ? "  ·  " + s.Power.ToString("0.0") + " W" + (s.PowerLimit > 0 ? "/" + s.PowerLimit.ToString("0") : "") : "");
            T(g, tp, fS, s.Temp >= c.GpuTempAlertC ? Theme.Red : s.Temp >= c.GpuTempAlertC - 7 ? Theme.Amber : Theme.Dim, L + 50, y + 4);
            Spark(g, new RectangleF(R - sparkW, y, sparkW, gh), hGpu, Theme.Green);
            y += gh + 4; used += extra;

            double vPct = s.VramTotal > 0 ? 100 * s.VramUsed / s.VramTotal : 0;
            T(g, "VRAM", fB, Theme.Txt, L, y);
            TR(g, GB(s.VramUsed) + " / " + GB(s.VramTotal) + " GB (" + vPct.ToString("0") + "%) · free " + GB(s.VramTotal - s.VramUsed), fS, vPct >= c.VramAlertPct ? Theme.Red : Theme.Dim, R, y + 2);
            y += 17;
            float vsw = Math.Max(50, (R - L) * 0.2f);
            Bar(g, L, y, R - L - vsw - 6, 8, vPct, vPct >= c.VramAlertPct ? Theme.Red : vPct >= 75 ? Theme.Amber : Theme.Purple);
            Spark(g, new RectangleF(R - vsw, y - 4, vsw, 14), hVram, Theme.Purple);
            y += 13;
            bool spill = s.NvShared > c.SpillAlertMB * 1048576.0;
            if (!c.Compact)
            {
                T(g, "Mem bus " + (s.NvMemUtil >= 0 ? s.NvMemUtil.ToString("0") + "%" : "n/a")
                    + "  ·  Core " + (s.Sm >= 0 ? s.Sm.ToString("0") : "?") + (s.SmMax > 0 ? "/" + s.SmMax.ToString("0") : "") + " MHz"
                    + "  ·  Mem " + (s.MemClk >= 0 ? s.MemClk.ToString("0") + " MHz" : "?"), fS, Theme.Dim, L, y);
                y += 15;
            }
            if (!c.Compact || spill)
            {
                T(g, "Shared (spill) " + (s.NvShared >= 0 ? GB(s.NvShared) + " GB" : "n/a")
                    + (s.PcieRx >= 0 && !c.Compact ? "  ·  PCIe in " + s.PcieRx.ToString("0") + " / out " + s.PcieTx.ToString("0") + " MB/s" : ""), fS, spill ? Theme.Amber : Theme.Dim, L, y);
                y += 15;
            }
            string why = s.ThrottleOk ? Throttle(s.Throttle) : "";
            if (s.ThrottleOk && !c.Compact)
            {
                T(g, "Clock limiter: " + why, fS, why.Contains("thermal") || why.Contains("brake") ? Theme.Red : why.Contains("power") ? Theme.Amber : Theme.Dim, L, y); y += 15;
            }
            if (why.Contains("thermal")) alerts.Add(new KeyValuePair<Color, string>(Theme.Red, "GPU thermal throttling - tokens/s will drop"));
            y += 3;
            if (vPct >= c.VramAlertPct) alerts.Add(new KeyValuePair<Color, string>(Theme.Red, "VRAM " + vPct.ToString("0") + "% - bigger model/context will spill to RAM"));
            if (spill) alerts.Add(new KeyValuePair<Color, string>(Theme.Amber, GB(s.NvShared) + " GB in shared GPU memory (system RAM) - slow path"));
            if (s.Temp >= c.GpuTempAlertC) alerts.Add(new KeyValuePair<Color, string>(Theme.Red, "GPU at " + s.Temp.ToString("0") + "°C"));
        }
        else
        {
            Section(g, "GPU", y, R); y += 18; T(g, "NVIDIA NVML not available", fS, Theme.Dim, L, y); y += 18;
        }

        if (c.ShowIgpu && s.HasIg)
        {
            T(g, "iGPU " + s.IgName, fS, Theme.Dim, L, y);
            TR(g, (s.IgUtil >= 0 ? s.IgUtil.ToString("0") + "%" : "n/a") + "  ·  shared " + (s.IgShared >= 0 ? GB(s.IgShared) + " GB" : "n/a"), fS, Theme.Dim, R, y);
            y += 18;
        }

        if (c.ShowGpuProcs && s.Procs.Count > 0)
        {
            Section(g, "GPU processes", y, R); y += 17;
            int nameLen = Math.Max(12, (int)((W - 150) / 6.2));
            foreach (var p in s.Procs)
            {
                var pp = p;
                T(g, Cut(p.Name, nameLen), fS, Theme.Txt, L, y);
                Link(g, "✕", fS, Theme.Faint, Theme.Red, R, y, delegate { EndTask(this, pp.Pid, 0, pp.Name, false); }, true);
                TR(g, p.Util.ToString("0") + "%", fS, LoadColor(p.Util), R - 22, y);
                TR(g, p.VramMB > 0 ? p.VramMB.ToString("0") + " MB" : "—", fS, Theme.Purple, R - 58, y);
                y += 15;
            }
            y += 3;
        }

        // Ollama
        if (c.ShowOllama)
        {
            Section(g, "Ollama", y, R); y += 17;
            int st = ollama.State; var models = ollama.Models;
            if (st == 0) { T(g, "checking " + c.OllamaUrl + "...", fS, Theme.Dim, L, y); y += 15; }
            else if (st == 1) { T(g, "not running (" + c.OllamaUrl.Replace("http://", "") + ")", fS, Theme.Dim, L, y); y += 15; }
            else if (models.Count == 0) { T(g, "running - no model loaded", fS, Theme.Dim, L, y); y += 15; }
            else foreach (var md in models)
                {
                    var mm = md;
                    T(g, Cut(md.Name, Math.Max(12, (int)((W - 140) / 6.5))), fB, Theme.Txt, L, y);
                    TR(g, md.SizeGB.ToString("0.0") + " GB" + (md.Ctx > 0 ? " · ctx " + md.Ctx : ""), fS, Theme.Dim, R, y + 1);
                    y += 16;
                    double gp = md.VramFrac * 100;
                    using (var b = new SolidBrush(Theme.Panel)) g.FillRectangle(b, L, y, R - L, 7);
                    using (var b = new SolidBrush(Theme.Green)) g.FillRectangle(b, L, y, (float)((R - L) * Math.Min(1, md.VramFrac)), 7);
                    if (gp < 99.5) using (var b = new SolidBrush(Theme.Amber)) g.FillRectangle(b, L + (float)((R - L) * md.VramFrac), y, (float)((R - L) * (1 - md.VramFrac)), 7);
                    y += 10;
                    string exp = md.Expires > DateTime.Now ? " · unloads in " + Fmt(md.Expires - DateTime.Now) : "";
                    T(g, (gp >= 99.5 ? "100% GPU" : gp.ToString("0") + "% GPU / " + (100 - gp).ToString("0") + "% CPU") + exp, fS, gp >= 99.5 ? Theme.Green : Theme.Amber, L, y);
                    Link(g, "unload", fS, Theme.Teal, Theme.Red, R, y, delegate
                    {
                        if (!Config.ConfirmEndTask || MessageBox.Show(this, "Unload " + mm.Name + " from Ollama? This frees its VRAM/RAM; the next request reloads it.", "Unload model", MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.Yes)
                            ollama.Unload(mm.Name);
                    }, true);
                    y += 16;
                    if (gp < 99.5) alerts.Add(new KeyValuePair<Color, string>(Theme.Amber, Cut(md.Name, 24) + ": " + (100 - gp).ToString("0") + "% on CPU - much lower tokens/s"));
                }
            string la = ollama.LastAction;
            if (!string.IsNullOrEmpty(la)) { T(g, Cut(la, 60), fS, la.Contains("failed") ? Theme.Red : Theme.Dim, L, y); y += 15; }
            y += 2;
        }

        // alerts
        if (alerts.Count > 0)
        {
            Section(g, "Alerts", y, R); y += 17;
            foreach (var a in alerts) { T(g, "▲ " + a.Value, fS, a.Key, L, y); y += 15; }
            y += 3;
        }

        // footer
        T(g, "sample " + s.SampleMs.ToString("0") + " ms · self " + s.SelfCpu.ToString("0.0") + "% CPU, " + s.SelfMB.ToString("0") + " MB · " + (c.RefreshMs / 1000.0).ToString("0.##") + " s", fS, Theme.Faint, L, y);
        y += 18;
        FitHeight((int)Math.Ceiling(y + 4 - used), false);
    }

    static string Fmt(TimeSpan t)
    {
        return t.TotalHours >= 1 ? ((int)t.TotalHours) + "h " + t.Minutes + "m" : t.TotalMinutes >= 1 ? ((int)t.TotalMinutes) + "m " + t.Seconds + "s" : t.Seconds + "s";
    }

    static string Throttle(ulong r)
    {
        var l = new List<string>();
        if ((r & 0x40) != 0 || (r & 0x20) != 0) l.Add("thermal");
        if ((r & 0x80) != 0) l.Add("power brake");
        if ((r & 0x4) != 0) l.Add("power cap");
        if ((r & 0x8) != 0) l.Add("HW slowdown");
        if ((r & 0x2) != 0) l.Add("app clocks");
        if ((r & 0x100) != 0) l.Add("display clock");
        if (l.Count == 0) return (r & 0x1) != 0 ? "idle" : "none (full boost)";
        return string.Join(", ", l.ToArray());
    }

    // natural = content height at default graph size. Auto mode sizes the window to it.
    void FitHeight(int natural, bool force)
    {
        naturalH = natural;
        if (!Config.AutoHeight || WindowState != FormWindowState.Normal) return;
        int want = (int)(natural * S);
        if (force || Math.Abs(ClientSize.Height - want) > 1)
            BeginInvoke((MethodInvoker)delegate { ClientSize = new Size(ClientSize.Width, want); });
    }
}

// ======================================================================= entry
static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--diag")
        {
            var sp = new Sampler(); sp.Sample(); Thread.Sleep(1000); var sn = sp.Sample();
            var procs = NtProc.Snapshot();
            File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "diag.txt"),
                sp.Diag + "processes=" + procs.Count + " vramPids=" + sn.AllVram.Count + "\r\n" + new JavaScriptSerializer().Serialize(sn));
            return;
        }
        bool created;
        using (var mx = new Mutex(true, "Local\\LocalAIMonitor_single", out created))
        {
            if (!created)
            {
                // "--handoff" = restarted elevated: wait for the old instance to exit.
                if (args.Length == 0 || args[0] != "--handoff") return;
                try { if (!mx.WaitOne(8000)) return; } catch (AbandonedMutexException) { }
            }
            try { Win.SetProcessDPIAware(); } catch { }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MonitorForm());
        }
    }
}
