# -*- coding: utf-8 -*-
"""
时之笛 Longshot/Triforce 炸弹定位（只读，差分法）
================================================================
用途：v5 里箭矢 #1017 / 炸弹 #1018 从未验证过（当时没弓没炸弹，
读 0）。用户实测炸弹 #1018 数据不对、写入无效，说明炸弹在
Triforce 上不是 #1018。本脚本用差分法找真正的炸弹序号。

原理：先把全表 1259 条的数值都记下来，让用户去游戏里扔一颗
炸弹（炸弹数减 1），再扫一遍，找出数值恰好减了 1 的那条，
那就是炸弹。

用法：先启动游戏（longshot.exe），进到存档、能自由行动，
并且身上至少有 1 颗炸弹，再双击本程序（或 python oot_bomb_finder.py）。
按提示操作：第一次扫完后去游戏里扔一颗炸弹，回到窗口按回车，
等第二次扫完，把输出全文贴回给 Muse。
只读，不改数值、不写存档。
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

    def v2(self, idx):
        return self.p.read_int(self.entry(idx) + 32)

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


def snapshot(rg):
    """一次扫全表，返回 {序号: (+28, +32)}，只收 +0 是魔数的有效表项。"""
    out = {}
    for idx in range(0, N_ENTRIES):
        if rg.p.read_uint(rg.entry(idx)) != MAGIC:
            continue
        v28 = rg.v1(idx)
        v32 = rg.v2(idx)
        out[idx] = (v28, v32)
    return out


def main():
    print("时之笛 Longshot/Triforce 炸弹定位（只读，差分法）")
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

    # 对照：v5 认为的消耗品行
    print("=" * 60)
    print("v5 认为的消耗品行当前值（对照用）：")
    for label, idx in (("箭矢", 1017), ("炸弹", 1018), ("德库坚果", 1019),
                       ("德库种子", 1020), ("德库木棒", 1021)):
        print("  %s #%d  +28=%s  +32=%s" % (label, idx, rg.v1(idx), rg.v2(idx)))

    print("=" * 60)
    print("第 1 次扫描全表…")
    snap1 = snapshot(rg)
    print("  已记录 %d 条有效表项的数值。" % len(snap1))
    print()
    print("现在去游戏里扔一颗炸弹（炸弹数量减 1），")
    print("然后回到这个窗口，按回车继续。")
    print("注意：扔炸弹前后不要捡东西、不要开宝箱、不要切换场景，")
    print("只扔一颗炸弹，这样变的应该只有炸弹那一项。")
    try:
        input("扔完炸弹后按回车…")
    except EOFError:
        pass

    print("第 2 次扫描全表…")
    snap2 = snapshot(rg)
    print("  已记录 %d 条有效表项的数值。" % len(snap2))

    print("=" * 60)
    print("两次扫描之间数值发生变化的表项：")
    changed = []
    for idx in sorted(set(snap1) | set(snap2)):
        a = snap1.get(idx)
        b = snap2.get(idx)
        if a != b:
            changed.append((idx, a, b))
    if not changed:
        print("  没有任何表项变化。可能炸弹没扔出去，或者两次扫描之间游戏没动。")
    for idx, a, b in changed:
        print("  #%d  +28: %s -> %s   +32: %s -> %s" % (
            idx, a[0] if a else None, b[0] if b else None,
            a[1] if a else None, b[1] if b else None))
    print()
    dec1 = [c for c in changed
            if c[1] and c[2] and c[1][0] is not None and c[2][0] is not None
            and c[2][0] == c[1][0] - 1]
    if dec1:
        print("其中 +28 恰好减了 1 的候选（最可能是炸弹）：")
        for idx, a, b in dec1:
            print("  #%d  +28: %s -> %s   +32: %s -> %s" % (
                idx, a[0], b[0], a[1], b[1]))
    else:
        print("没有 +28 恰好减 1 的表项。可能炸弹不是减 1，或者扔炸弹时还动了别的。")

    print("=" * 60)
    print("请把上面全文贴回给 Muse，即可按此结果修正修改器里的炸弹序号。")
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
