# -*- coding: utf-8 -*-
"""
时之笛 Longshot 修改器 v2（Triforce v3.1.1 / longshot.exe）
================================================================
用法：先启动游戏（longshot.exe），进到存档、能自由行动，再双击本程序。
程序启动后自动连接；点数字框敲数字，点「写入」即生效；改完请在游戏内
存一次档，否则读旧档会回到旧数值。

只改内存，不写存档文件。数值超过容量上限时游戏可能夹回，状态栏会提示。
杀毒软件可能误报（PyInstaller 打包 + 改内存），加白名单即可。

机制（与 Hookshot 版 v5 相同，Triforce v3.1.1 实机验证通过）：
  变量登记表基址 0x10108AA6CAC8（Triforce 上与 v5 相同，已验证），步长 40 字节，
  魔数 0x84C40718；数值 int32 在表项 +28，写入时同时写 +28 与 +32。
  卢比 #962 / 魔力 #963 / 炸弹 #1007 / 坚果 #1019 / 种子 #1020（镜像 #1213）/
  木棒 #1021 / 箭矢 #1017；容量：坚果袋 #973 / 种子袋 #974 / 木棒袋 #975 /
  钱包上限 #976。种子写入时同步写镜像 #1213。
  炸弹 #1007 由差分验证：23:14 时 #1007=24，用户扔 1 颗炸弹后
  23:22 搜 23 仅剩 #1007=23（恰好减 1），确认为炸弹；原 #1018 与
  #964 均非炸弹，用户 23:29 实测炸弹已生效。魔力：存档修改器显示
  当前魔力 6 点（满 24 点），搜 6 得 5 条；此前 #1234、#1238、
  #124、#1065、#15、#1249 均已实测无效。#961（紧挨卢比 #962，
  +8=8）为主候选，#836、#841、#65、#66 为其余候选，均已列入
  界面供实测，哪个生效就定哪个。
  魔力上限：本作满魔力 24 点（8 格，每格 3 点）；「满」默认写 24。
"""
import ctypes
import struct
import sys
import traceback
import tkinter as tk
from tkinter import messagebox
from ctypes import wintypes

# ---------------- 常量（Triforce v3.1.1 实机验证） ----------------
MAGIC = 0x84C40718
STRIDE = 40
REF_BASE = 0x10108AA6CAC8
SCAN_LO = 0x10108A000000
SCAN_HI = 0x10108AC00000
NAME_HINTS = ('longshot', 'triforce', 'ocarina', 'zelda', 'oot', 'notrex', 'hook')
IDX_RUPEE = 962
IDX_MAGIC = 961
IDX_BOMBS = 1007
# 魔力候选（搜 6 的其余未验证项，供实测逐个试）
IDX_MAGIC_C836 = 836
IDX_MAGIC_C841 = 841
IDX_MAGIC_C65 = 65
IDX_MAGIC_C66 = 66
IDX_NUTS = 1019
IDX_SEEDS = 1020
IDX_STICKS = 1021
IDX_ARROWS = 1017
IDX_CAP_NUTS = 973
IDX_CAP_SEEDS = 974
IDX_CAP_STICKS = 975
IDX_CAP_WALLET = 976
MIRROR_SEEDS = [1213]

FIELDS = [
    ('rupee',  '卢比',           IDX_RUPEE,  IDX_CAP_WALLET, True),
    ('magic',  '魔力 #961',      IDX_MAGIC,  None,           True),
    ('magic836', '魔力候选 #836', IDX_MAGIC_C836, None,       True),
    ('magic841', '魔力候选 #841', IDX_MAGIC_C841, None,       True),
    ('magic65', '魔力候选 #65',  IDX_MAGIC_C65, None,         True),
    ('magic66', '魔力候选 #66',  IDX_MAGIC_C66, None,         True),
    ('bombs',  '炸弹',           IDX_BOMBS,  None,           True),
    ('nuts',   '德库坚果',       IDX_NUTS,   IDX_CAP_NUTS,   True),
    ('seeds',  '德库种子(弹弓)', IDX_SEEDS,  IDX_CAP_SEEDS, True),
    ('sticks', '德库木棒',       IDX_STICKS, IDX_CAP_STICKS, True),
    ('arrows', '箭矢（未验证）', IDX_ARROWS, None,           False),
]

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
k32.ReadProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
k32.VirtualProtectEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t,
                                 wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE


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

    def write(self, addr, data):
        old = wintypes.DWORD(0)
        if not k32.VirtualProtectEx(self.h, ctypes.c_void_p(addr), len(data), 64, ctypes.byref(old)):
            return False
        buf = (ctypes.c_char * len(data))(*data)
        n = ctypes.c_size_t(0)
        r = k32.WriteProcessMemory(self.h, ctypes.c_void_p(addr), buf, len(data), ctypes.byref(n))
        k32.VirtualProtectEx(self.h, ctypes.c_void_p(addr), len(data), old.value, ctypes.byref(old))
        return bool(r) and n.value == len(data)

    def read_int(self, a):
        d = self.read(a, 4)
        return struct.unpack('<i', d)[0] if d and len(d) == 4 else None

    def read_uint(self, a):
        d = self.read(a, 4)
        return struct.unpack('<I', d)[0] if d and len(d) == 4 else None

    def write_int(self, a, v):
        return self.write(a, struct.pack('<i', int(v)))

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

    def set(self, idx, value):
        h = self.entry(idx)
        ok1 = self.p.write_int(h + 28, value)
        ok2 = self.p.write_int(h + 32, value)
        return ok1 and ok2

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


def pick_game(name):
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


# ---------------- 界面 ----------------
class Trainer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("时之笛 Longshot 修改器 v2")
        self.geometry("760x800")
        self.attributes("-topmost", True)
        self.proc = None
        self.reg = None
        self.entries = {}
        self.cur_labels = {}
        self.lock_vars = {}
        self.lock_targets = {}
        self._build()
        self.after(200, lambda: self.connect(None))
        self.after(1000, self._refresh_tick)
        self.after(500, self._lock_tick)

    def _build(self):
        top = tk.Frame(self)
        top.pack(fill="x", padx=10, pady=8)
        tk.Label(top, text="进程名：").pack(side="left")
        self.proc_entry = tk.Entry(top, width=22)
        self.proc_entry.pack(side="left", padx=4)
        tk.Button(top, text="用这个进程名连接", command=self.on_connect_named).pack(side="left", padx=4)
        tk.Button(top, text="重新连接", command=lambda: self.connect(self.proc_entry.get().strip() or None)).pack(side="left", padx=4)

        self.status = tk.Label(self, text="正在连接…", anchor="w", fg="blue")
        self.status.pack(fill="x", padx=10, pady=4)

        grid = tk.Frame(self)
        grid.pack(fill="x", padx=10, pady=4)
        headers = ["项目", "当前值", "输入数字", "", "", "锁定"]
        for c, h in enumerate(headers):
            tk.Label(grid, text=h, font=("", 10, "bold")).grid(row=0, column=c, padx=4, pady=2)
        row = 1
        for key, name, idx, capidx, ok in FIELDS:
            tk.Label(grid, text=name).grid(row=row, column=0, sticky="w", padx=4, pady=4)
            cur = tk.Label(grid, text="—", width=10)
            cur.grid(row=row, column=1, padx=4, pady=4)
            self.cur_labels[key] = cur
            ent = tk.Entry(grid, width=12)
            ent.grid(row=row, column=2, padx=4, pady=4)
            self.entries[key] = ent
            tk.Button(grid, text="写入", width=6,
                      command=lambda k=key: self.do_write(k)).grid(row=row, column=3, padx=4, pady=4)
            tk.Button(grid, text="满", width=5,
                      command=lambda k=key: self.do_full(k)).grid(row=row, column=4, padx=4, pady=4)
            var = tk.BooleanVar(value=False)
            self.lock_vars[key] = var
            tk.Checkbutton(grid, variable=var,
                           command=lambda k=key: self.on_lock_toggle(k)).grid(row=row, column=5, padx=4, pady=4)
            row += 1
        # 钱包上限（伪字段）
        tk.Label(grid, text="钱包上限").grid(row=row, column=0, sticky="w", padx=4, pady=4)
        cur = tk.Label(grid, text="—", width=10)
        cur.grid(row=row, column=1, padx=4, pady=4)
        self.cur_labels['cap'] = cur
        ent = tk.Entry(grid, width=12)
        ent.grid(row=row, column=2, padx=4, pady=4)
        self.entries['cap'] = ent
        tk.Button(grid, text="写入", width=6,
                  command=lambda: self.do_write('cap')).grid(row=row, column=3, padx=4, pady=4)
        tk.Button(grid, text="满", width=5,
                  command=lambda: self.do_full('cap')).grid(row=row, column=4, padx=4, pady=4)
        var = tk.BooleanVar(value=False)
        self.lock_vars['cap'] = var
        tk.Checkbutton(grid, variable=var,
                       command=lambda: self.on_lock_toggle('cap')).grid(row=row, column=5, padx=4, pady=4)

        bottom = tk.Frame(self)
        bottom.pack(fill="x", padx=10, pady=10)
        tk.Button(bottom, text="全部应用", width=12, command=self.apply_all).pack(side="left", padx=4)
        tk.Button(bottom, text="一键补满", width=12, command=self.max_all).pack(side="left", padx=4)
        tk.Label(bottom, text="只改内存，不写存档；改完请在游戏内存一次档。\n勾「锁定」后每 0.5 秒把该项重写回锁定值。",
                 fg="gray").pack(side="left", padx=8)

    def set_status(self, msg, color="black"):
        self.status.config(text=msg, fg=color)

    def on_connect_named(self):
        nm = self.proc_entry.get().strip()
        self.connect(nm or None)

    def connect(self, name):
        cands, allp = pick_game(name)
        if not cands:
            tops = sorted([p for p in allp if p[2]], key=lambda p: -p[2])[:3]
            if tops:
                desc = "、".join("%s(%.1fG)" % (p[1], p[2] / 1073741824.0) for p in tops)
                tail = "机器上最占内存的三个进程：%s。游戏若开着，把它的进程名（任务管理器→详细信息）填到「进程名」框再点连接。" % desc
            else:
                tail = "没读到任何进程信息，可能是权限问题。"
            if name:
                self.set_status("没找到叫 %s 的进程。%s" % (name, tail), "red")
            else:
                self.set_status("没找到游戏进程。%s" % tail, "red")
            return False
        msgs = []
        for p in sorted(cands, key=lambda x: -(x[2] or 0))[:6]:
            pid_tmp, exe_tmp, ws_tmp = p
            try:
                pr = Proc(pid_tmp)
                rg = Registry(pr)
                if rg.locate():
                    if self.proc:
                        self.proc.close()
                    self.proc, self.reg = pr, rg
                    self.proc_entry.delete(0, tk.END)
                    self.proc_entry.insert(0, exe_tmp)
                    self.set_status("已连接 %s  PID %d  内存 %.1fG  变量表%s" % (
                        exe_tmp, pid_tmp, (ws_tmp or 0) / 1073741824.0,
                        "已校验" if rg.note == "已校验" else "已重新定位"), "green")
                    self._refresh_values()
                    return True
                pr.close()
                msgs.append("%s（PID %d）能打开，但里面没有这张变量表 → 游戏版本和这台不一样"
                            % (exe_tmp, pid_tmp))
            except OSError as e:
                code = e.args[0] if e.args else 0
                if code == 5:
                    msgs.append("找到 %s（PID %d）但打不开：权限不足 → 右键修改器「以管理员身份运行」"
                                % (exe_tmp, pid_tmp))
                else:
                    msgs.append("找到 %s（PID %d）但打不开，错误码 %d（可能已退出）"
                                % (exe_tmp, pid_tmp, code))
        self.set_status(msgs[0] if msgs else "没找到可用的游戏进程", "red")
        return False

    def cur(self, key):
        if not self.reg or not self.reg.base:
            return None
        for k, name, idx, capidx, ok in FIELDS:
            if k == key:
                return self.reg.v1(idx)
        if key == 'cap':
            return self.reg.v1(IDX_CAP_WALLET)
        return None

    def capof(self, key):
        if not self.reg or not self.reg.base:
            return None
        for k, name, idx, capidx, ok in FIELDS:
            if k == key and capidx:
                return self.reg.v1(capidx)
        return None

    def _idx_of(self, key):
        if key == 'cap':
            return IDX_CAP_WALLET
        for k, name, idx, capidx, ok in FIELDS:
            if k == key:
                return idx
        return None

    def _name_of(self, key):
        if key == 'cap':
            return '钱包上限'
        for k, name, idx, capidx, ok in FIELDS:
            if k == key:
                return name
        return key

    def _set_value(self, key, value):
        idx = self._idx_of(key)
        if idx is None:
            return False
        ok = self.reg.set(idx, value)
        if idx == IDX_SEEDS:
            for m in MIRROR_SEEDS:
                self.reg.set(m, value)
        return ok

    def _refresh_values(self):
        if not self.reg or not self.reg.base:
            return
        for key in self.cur_labels:
            v = self.cur(key)
            self.cur_labels[key].config(text=str(v) if v is not None else "—")

    def _refresh_tick(self):
        try:
            self._refresh_values()
        except Exception:
            pass
        self.after(1000, self._refresh_tick)

    def _lock_tick(self):
        try:
            if self.reg and self.reg.base:
                for key, var in self.lock_vars.items():
                    if var.get():
                        target = self.lock_targets.get(key)
                        if target is not None:
                            self._set_value(key, target)
        except Exception:
            pass
        self.after(500, self._lock_tick)

    def on_lock_toggle(self, key):
        var = self.lock_vars.get(key)
        if var is None:
            return
        if var.get():
            s = self.entries[key].get().strip()
            target = None
            if s:
                try:
                    target = int(s)
                except ValueError:
                    target = None
            if target is None:
                target = self.cur(key)
            if target is None:
                var.set(False)
                self.set_status("锁定失败：读不到当前值", "red")
                return
            self.lock_targets[key] = target
            self.set_status("已锁定 %s = %d（每 0.5 秒重写）" % (self._name_of(key), target), "green")
        else:
            self.lock_targets.pop(key, None)
            self.set_status("已取消锁定 %s" % self._name_of(key), "black")

    def do_write(self, key):
        if not self.reg or not self.reg.base:
            self.set_status("未连接游戏 —— 先点「重新连接」", "red")
            return
        s = self.entries[key].get().strip()
        if not s:
            self.set_status("请先点一下数字框，直接敲数字，再点「写入」", "red")
            return
        try:
            v = int(s)
            v = max(0, min(v, 9999999))
            idx = self._idx_of(key)
            name = self._name_of(key)
            ok = self._set_value(key, v)
            back = self.reg.v1(idx) if idx is not None else None
            if ok and back == v:
                self.entries[key].delete(0, tk.END)
                cap = self.capof(key) if key != 'cap' else None
                msg = "%s 已改成 %d ✔" % (name, v)
                if cap and v > cap:
                    msg += "（超过上限 %d，游戏里可能被夹回）" % cap
                self.set_status(msg, "green")
                self._refresh_values()
            elif ok:
                self.set_status("%s 写入 %d，但回读是 %s（被游戏改回去了）" % (name, v, back), "red")
            else:
                self.set_status("%s 写入失败" % name, "red")
        except ValueError:
            self.set_status("请输入数字", "red")

    def do_full(self, key):
        if not self.reg or not self.reg.base:
            self.set_status("未连接游戏", "red")
            return
        cap = self.capof(key)
        if key == 'cap':
            full_val = 999
        elif key.startswith('magic'):
            full_val = 24
        elif cap and cap > 0:
            full_val = cap
        else:
            full_val = {'arrows': 30, 'bombs': 20}.get(key, 0)
        self.entries[key].delete(0, tk.END)
        self.entries[key].insert(0, str(full_val))
        self.do_write(key)

    def max_all(self):
        if not self.reg or not self.reg.base:
            self.set_status("未连接游戏", "red")
            return
        done = []
        self.reg.set(IDX_CAP_WALLET, 999)
        self.reg.set(IDX_MAGIC, 24)
        done.append("魔力=24")
        self.reg.set(IDX_CAP_NUTS, 20)
        self.reg.set(IDX_CAP_SEEDS, 30)
        self.reg.set(IDX_CAP_STICKS, 10)
        for k, name, idx, capidx, ok in FIELDS:
            cap = self.reg.v1(capidx) if capidx else 0
            if not cap or cap <= 0:
                continue
            if idx == IDX_ARROWS:
                continue
            self.reg.set(idx, cap)
            if idx == IDX_SEEDS:
                for m in MIRROR_SEEDS:
                    self.reg.set(m, cap)
            done.append("%s=%d" % (name, cap))
        if done:
            self.set_status("已补满： " + "、".join(done) + "（箭矢未验证，未动）", "green")
        else:
            self.set_status("没有可补满的项", "red")
        self._refresh_values()

    def apply_all(self):
        if not self.reg or not self.reg.base:
            self.set_status("未连接游戏", "red")
            return
        n = 0
        items = list(FIELDS) + [('cap', '钱包上限', IDX_CAP_WALLET, None, True)]
        for k, name, idx, capidx, ok in items:
            s = self.entries[k].get().strip()
            if not s:
                continue
            try:
                v = int(s)
            except ValueError:
                continue
            self._set_value(k, v)
            self.entries[k].delete(0, tk.END)
            n += 1
        self.set_status("已应用 %d 项" % n + ("（数字框里是空的就跳过）" if n == 0 else ""),
                        "green" if n else "orange")
        self._refresh_values()


def main():
    app = Trainer()
    app.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        tb = traceback.format_exc()
        try:
            messagebox.showerror("时之笛 Longshot 修改器 v2", "程序出错：\n\n" + tb[-1200:])
        except Exception:
            pass
        raise
