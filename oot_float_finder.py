# -*- coding: utf-8 -*-
"""
时之笛 Longshot/Triforce 数值定位（只读，按值搜索，含浮点）
================================================================
用途：魔力可能不是 int32，而是 float32 存的。之前按 int32 搜
6、18、24 找出的候选全都无效，很可能因为魔力是浮点数。
本脚本同时按 int32 与 float32 搜目标值，找出匹配的表项。

用法：先启动游戏（longshot.exe），进到存档、能自由行动，
再双击本程序。输入要搜的数值（例如当前魔力 6，或满魔力 24），
按回车。把输出全文贴回给 Muse。只读，不改数值、不写存档。
"""
import ctypes
import struct
import sys
from ctypes import wintypes

MAGIC = 0x84C40718
STRIDE = 40
REF_BASE = 0x10108AA6CAC8
SCAN_LO = 0x10108A000000
SCAN_HI = 0x10108AC00000
NAME_HINTS = ('longshot', 'triforce', 'ocarina', 'zelda', 'oot', 'notrex', 'hook')
IDX_RUPEE = 962
N_ENTRIES = 1259

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
TH32CS_SNAPPROCESS = 0x00000002

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
psapi = ctypes.WinDLL("psapi", use_last_error=True)
k32.OpenProcess.restype = wintypes.HANDLE
k32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD), ("szExeFile", wintypes.WCHAR * 260),
    ]


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD), ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t), ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD), ("Type", wintypes.DWORD),
    ]


class PMC(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
    ]


class Proc:
    def __init__(self, pid):
        self.pid = pid
        self.h = k32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
            False, pid)
        if not self.h:
            raise OSError(ctypes.get_last_error())

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None

    def read(self, addr, size):
        buf = (ctypes.c_char * size)()
        n = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n)):
            return None
        return bytes(buf)[:n.value]

    def read_int(self, a):
        d = self.read(a, 4)
        return struct.unpack('<i', d)[0] if d and len(d) == 4 else None

    def read_uint(self, a):
        d = self.read(a, 4)
        return struct.unpack('<I', d)[0] if d and len(d) == 4 else None

    def read_float(self, a):
        d = self.read(a, 4)
        return struct.unpack('<f', d)[0] if d and len(d) == 4 else None

    def regions(self, lo, hi):
        addr = lo
        mbi = MBI()
        while addr < hi:
            if not k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress
            size = mbi.RegionSize
            if base is None or size == 0:
                break
            if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                    and not (mbi.Protect & PAGE_GUARD) and mbi.Protect != PAGE_NOACCESS):
                s = max(base, lo)
                e = min(base + size, hi)
                if e > s:
                    yield s, e - s
            addr = base + size
            if addr >= (1 << 47):
                break


class Registry:
    def __init__(self, proc):
        self.p = proc
        self.base = None
        self.note = ""

    def entry(self, idx):
        return self.base + idx * STRIDE

    def v1(self, idx):
        return self.p.read_int(self.entry(idx) + 28)

    def verify(self, base):
        try:
            if self.p.read_uint(base) != MAGIC:
                return False
            if self.p.read_uint(base - STRIDE) == MAGIC:
                return False
            for k in (1, 100, 400, 800, 1200):
                if self.p.read_uint(base + k * STRIDE) != MAGIC:
                    return False
            if self.p.read_int(base + 8) not in (8, 32, 24, 1):
                return False
            r = self.p.read_int(base + IDX_RUPEE * STRIDE + 28)
            if r is None or not (0 <= r <= 9999999):
                return False
            return True
        except Exception:
            return False

    def locate(self):
        if self.verify(REF_BASE):
            self.base, self.note = REF_BASE, "已校验"
            return True
        for base, size in self.p.regions(SCAN_LO, SCAN_HI):
            off = 0
            while off < size:
                ln = min(2097152, size - off)
                raw = self.p.read(base + off, ln)
                if raw:
                    for k in range(0, max(0, len(raw) - 4), 4):
                        if struct.unpack_from('<I', raw, k)[0] == MAGIC:
                            a = base + off + k
                            if self.verify(a):
                                self.base, self.note = a, "已重新定位"
                                return True
                off += 2097152
        return False


def scan_procs():
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == -1:
        return []
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(pe)
    out = []
    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        pid = pe.th32ProcessID
        if pid not in (0, 4):
            ws = None
            h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if h:
                pmc = PMC()
                pmc.cb = ctypes.sizeof(pmc)
                if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                    ws = pmc.WorkingSetSize
                k32.CloseHandle(h)
            out.append((pid, pe.szExeFile, ws))
        ok = k32.Process32NextW(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return out


def pick_game(name=None):
    procs = scan_procs()
    if name:
        return [p for p in procs if p[1].lower() == name.lower()], procs
    hint = [p for p in procs if any(h in p[1].lower() for h in NAME_HINTS)]
    big = [p for p in procs if p[2] and p[2] > 1500000000]
    cands = list(hint)
    for b in big:
        if b not in cands:
            cands.append(b)
    return cands, procs


def main():
    print("时之笛 Longshot/Triforce 数值定位（只读，int32 + float32）")
    cands, allp = pick_game()
    if not cands:
        print("没找到游戏进程。请先启动游戏（longshot.exe），进到存档、能自由行动，再运行本程序。")
        return 1
    pr = None
    rg = None
    for p in sorted(cands, key=lambda x: -(x[2] or 0))[:6]:
        pid_tmp, exe_tmp, ws_tmp = p
        try:
            pr = Proc(pid_tmp)
            rg = Registry(pr)
            if rg.locate():
                print("已连接 %s  PID %d  内存 %.1fG" % (exe_tmp, pid_tmp, (ws_tmp or 0) / 1073741824.0))
                break
            pr.close()
            pr = None
            rg = None
        except OSError as e:
            print("找到 %s（PID %d）但打不开，错误码 %s" % (exe_tmp, pid_tmp, e.args[0] if e.args else "?"))
    if rg is None or rg.base is None:
        print("没找到变量表。游戏版本可能和这台不一样。")
        return 2
    print("变量表基址：0x%X（%s）" % (rg.base, rg.note))

    print("=" * 60)
    print("已知项当前值（对照用）：")
    for label, idx in (("卢比", 962), ("炸弹 #1007", 1007),
                       ("德库坚果", 1019), ("德库种子", 1020), ("德库木棒", 1021),
                       ("钱包上限", 976)):
        print("  %s #%d  +28(int)=%s" % (label, idx, rg.v1(idx)))

    try:
        s = input("要搜索的数值（例如当前魔力 6，或满魔力 24）：").strip()
        target = float(s) if s else 6.0
    except (ValueError, EOFError):
        target = 6.0
    itarget = int(target)
    print("=" * 60)
    print("搜索 +28 == %s（int32）与 +28 == %s（float32）的表项…" % (itarget, target))
    hits_int = []
    hits_float = []
    for idx in range(0, N_ENTRIES):
        if rg.p.read_uint(rg.entry(idx)) != MAGIC:
            continue
        v28i = rg.p.read_int(rg.entry(idx) + 28)
        v32i = rg.p.read_int(rg.entry(idx) + 32)
        v28f = rg.p.read_float(rg.entry(idx) + 28)
        v32f = rg.p.read_float(rg.entry(idx) + 32)
        t8 = rg.p.read_int(rg.entry(idx) + 8)
        if v28i == itarget:
            hits_int.append((idx, v28i, v32i, t8))
        if v28f is not None and abs(v28f - target) < 0.001:
            hits_float.append((idx, v28f, v32f, t8))
    print("  int32 == %d：共 %d 条" % (itarget, len(hits_int)))
    for idx, v28, v32, t8 in hits_int:
        print("    #%d  +28=%s  +32=%s  +8=%s" % (idx, v28, v32, t8))
    print("  float32 == %s：共 %d 条" % (target, len(hits_float)))
    for idx, v28, v32, t8 in hits_float:
        print("    #%d  +28=%s  +32=%s  +8=%s" % (idx, v28, v32, t8))
    print("=" * 60)
    print("请把上面全文贴回给 Muse。")
    return 0


if __name__ == "__main__":
    try:
        code = main()
    except Exception:
        import traceback
        traceback.print_exc()
        code = 3
    print()
    try:
        input("按回车键退出…")
    except EOFError:
        pass
    sys.exit(code)
