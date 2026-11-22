# -*- coding: utf-8 -*-
"""
时之笛 Longshot / Triforce 版变量表定位脚本（只读，不改任何数值）
================================================================
背景：v5 修改器是给 Hookshot V2.3.2 懒人整合包做的，它在一张
“变量登记表”里按编号找数值：
  表基址 REF_BASE = 0x10108AA6CAC8（Hookshot V2.3.2 专属，Triforce 上必然不同）
  条目步长 STRIDE = 40 (0x28) 字节，共约 1259 条
  条目内某个偏移处是魔数 MAGIC = 0x84C40718（每条都有，用来认表）
  数值是 int32，位于条目 +28 处；写入时同时写 +28 和 +32（两个 4 字节字段）
  已知编号：卢比 962 / 箭矢 1017 / 炸弹 1018 / 坚果 1019 / 种子 1020 /
            木棒 1021 / 坚果袋上限 973 / 种子袋上限 974 / 木棒袋上限 975 /
            钱包上限 976 / 种子镜像 1213
本脚本只做定位：先试 v5 的旧基址，再全内存扫魔数，用 v5 同款结构校验
（抽查 1/100/400/800/1200 号条目魔数 + 基址+8 处小字段 + 卢比值范围）
确认是同一张表后，打印基址与各字段当前值。把输出全文贴回给 Muse，
下一步就能按这个基址生成 Longshot 版修改器。

用法（Windows，游戏先启动、进到能自由行动的存档）：
  python oot_registry_finder.py
  （若游戏以管理员身份运行，本脚本也要右键“以管理员身份运行”）
只读：全程只用 ReadProcessMemory，不写内存、不改存档。
"""
import ctypes
import struct
import sys
from ctypes import wintypes

MAGIC = 0x84C40718
MAGIC_BYTES = struct.pack("<I", MAGIC)
STRIDE = 40
REF_BASE = 0x10108AA6CAC8  # v5 的 Hookshot V2.3.2 基址，仅作首选试探
SAMPLE_IDX = (1, 100, 400, 800, 1200)
SMALL_FIELD_OK = (8, 32, 24, 1)  # v5 校验：表基址 +8 处的值应为其中之一
IDX = {
    "卢比": 962, "箭矢(未验证)": 1017, "炸弹(未验证)": 1018,
    "德库坚果": 1019, "德库种子(弹弓)": 1020, "德库木棒": 1021,
    "坚果袋上限": 973, "种子袋上限": 974, "木棒袋上限": 975,
    "钱包上限": 976, "种子镜像": 1213,
}
NAME_HINTS = ("triforce", "longshot", "hookshot", "ocarina", "zelda", "oot", "notrex", "hook")

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class MBI(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def scan_procs():
    """列出所有进程：[(pid, exe名, 工作集字节)]"""
    import ctypes as _c
    psapi = _c.WinDLL("psapi", use_last_error=True)
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        raise OSError("CreateToolhelp32Snapshot 失败")
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(pe)
    out = []
    try:
        if not k32.Process32FirstW(snap, ctypes.byref(pe)):
            return out
        while True:
            pid = pe.th32ProcessID
            name = pe.szExeFile
            ws = None
            h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            if h:
                class PMC(ctypes.Structure):
                    _fields_ = [
                        ("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD),
                        ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                        ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                    ]
                pmc = PMC()
                pmc.cb = ctypes.sizeof(pmc)
                if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                    ws = pmc.WorkingSetSize
                k32.CloseHandle(h)
            out.append((pid, name, ws))
            if not k32.Process32NextW(snap, ctypes.byref(pe)):
                break
    finally:
        k32.CloseHandle(snap)
    return out


def pick_game(procs):
    cands = []
    for pid, name, ws in procs:
        low = name.lower()
        if any(h in low for h in NAME_HINTS):
            cands.append((pid, name, ws))
        elif ws and ws > 1500000000:
            cands.append((pid, name, ws))
    return cands


class Proc:
    def __init__(self, pid):
        self.h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not self.h:
            raise OSError("OpenProcess 失败，错误码 %d（可能需以管理员身份运行）" % ctypes.get_last_error())

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        if not k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got)):
            return None
        return buf.raw[:got.value]

    def read_uint(self, addr):
        b = self.read(addr, 4)
        return struct.unpack("<I", b)[0] if b and len(b) == 4 else None

    def read_int(self, addr):
        b = self.read(addr, 4)
        return struct.unpack("<i", b)[0] if b and len(b) == 4 else None

    def regions(self):
        addr = 0
        mbi = MBI()
        while True:
            n = k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not n:
                break
            base = mbi.BaseAddress
            size = mbi.RegionSize
            if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                    and not (mbi.Protect & PAGE_GUARD) and not (mbi.Protect & PAGE_NOACCESS)):
                yield base, size
            if base is None or size == 0:
                break
            addr = base + size
            if addr >= (1 << 47):
                break


def verify(p, base, magic_off):
    """v5 同款结构校验：抽查条目魔数 + 基址+8 小字段 + 卢比值范围。"""
    for k in SAMPLE_IDX:
        v = p.read_uint(base + k * STRIDE + magic_off)
        if v != MAGIC:
            return False
    small = p.read_int(base + 8)
    if small not in SMALL_FIELD_OK:
        return False
    rupee = p.read_int(base + 962 * STRIDE + 28)
    if rupee is None or not (0 <= rupee <= 9999999):
        return False
    return True


def find_registry(p):
    """先试旧基址，再全内存扫。返回 (base, magic_off) 或 None。"""
    for magic_off in (0, 4, 12, 16, 20, 24, 28, 32, 36):
        if verify(p, REF_BASE, magic_off):
            print("[+] 旧基址 0x%X 在 Triforce 上仍有效（魔数偏移 +%d）" % (REF_BASE, magic_off))
            return REF_BASE, magic_off
    print("[*] 旧基址无效，开始全内存扫描魔数 0x84C40718（只读，约需几分钟）…")
    scanned = 0
    checked = 0
    for base, size in p.regions():
        off = 0
        while off < size:
            chunk = min(0x100000, size - off)
            data = p.read(base + off, chunk)
            if not data:
                break
            scanned += len(data)
            pos = data.find(MAGIC_BYTES)
            while pos != -1:
                hit = base + off + pos
                for magic_off in (0, 4, 12, 16, 20, 24, 28, 32, 36):
                    cand = hit - magic_off
                    if cand <= 0:
                        continue
                    checked += 1
                    if verify(p, cand, magic_off):
                        print("[+] 找到变量表：基址 0x%X，魔数偏移 +%d（已扫 %.1f GB，校验候选 %d 个）"
                              % (cand, magic_off, scanned / 1e9, checked))
                        return cand, magic_off
                pos = data.find(MAGIC_BYTES, pos + 1)
            off += chunk
            if scanned % (512 * 1024 * 1024) < 0x100000:
                print("    …已扫 %.1f GB" % (scanned / 1e9), flush=True)
    print("[-] 全内存未找到通过校验的变量表（已扫 %.1f GB，校验候选 %d 个）" % (scanned / 1e9, checked))
    return None


def main():
    print("时之笛 Longshot/Triforce 变量表定位（只读）")
    procs = scan_procs()
    cands = pick_game(procs)
    if not cands:
        big = sorted([x for x in procs if x[2]], key=lambda t: -(t[2] or 0))[:3]
        print("没找到游戏进程。机器上最占内存的三个进程：%s"
              % "、".join("%s(%.1fG)" % (n, (w or 0) / 1e9) for _, n, w in big))
        print("请确认 Triforce.exe 已启动并进到存档、能自由行动，再重跑。")
        return 1
    pid, name, ws = sorted(cands, key=lambda t: -(t[2] or 0))[0]
    print("已连接 %s  PID %d  内存 %.1fG" % (name, pid, (ws or 0) / 1e9))
    p = Proc(pid)
    try:
        found = find_registry(p)
        if not found:
            print("结论：这台 Triforce 构建里没有 v5 那张变量表（或表结构变了），")
            print("      不能直接套用 v5 的编号，Longshot 版修改器需另找数值地址。")
            return 2
        base, magic_off = found
        print("=" * 60)
        print("变量表基址：0x%X（魔数偏移 +%d，步长 40）" % (base, magic_off))
        print("各字段当前值（条目+28 / +32 两处）：")
        for label, idx in IDX.items():
            a = base + idx * STRIDE + 28
            v28 = p.read_int(a)
            v32 = p.read_int(a + 4)
            print("  %-16s #%d  +28=%s  +32=%s" % (label, idx, v28, v32))
        print("=" * 60)
        print("请把上面全文贴回给 Muse，即可按此基址生成 Longshot 版修改器。")
        return 0
    finally:
        p.close()


if __name__ == "__main__":
    sys.exit(main())
