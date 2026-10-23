# Easy-Ret2win

**Difficulty:** Easy · **Points:** 200 · **Topic:** Stack buffer overflow

## Description

The program asks how long your feedback is, then reads that many bytes into a
fixed buffer. Get a shell and read the flag.

## Running

```bash
./ret2win
```

The flag is `flag.txt` once you have a shell.

## Notes

- The source is included — read it before reaching for a payload.
- The read has **no length limit**, and that is the whole bug.
- Work out the distance from the buffer to the saved return address from the
  disassembly. Do not copy an offset from anywhere.
- The binary is **not PIE**, so a function's address is a constant you can read
  straight out of the symbol table.
- Nothing here needs a leak, a gadget, or shellcode.
