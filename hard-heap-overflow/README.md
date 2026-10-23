# Hard-Heap Overflow

**Difficulty:** Hard · **Points:** 200 · **Topic:** Heap overflow

## Description

An address book: create, delete, show and edit profiles. Get a shell and read the
flag.

## Running

```bash
./run.sh
```

Do **not** run `./heap_overflow` directly — it was built against an older glibc,
and `run.sh` is what starts it with the loader and libc that ship alongside it.

The flag is `flag.txt` once you have a shell.

## Notes

- The source is included. **Exactly one** of the four operations reads more bytes
  than the buffer it is reading into.
- Every prompt is served by its own `read()`. Send **one write per field**: if you
  pack two fields into one write, the first read swallows both.
- The binary is **not PIE**, and it already contains a function that gives a shell
  — so no leak is needed anywhere. Every address you need is a constant.
- Think about what sits **immediately after** the buffer that gets overrun, and
  what state that memory is in at the moment you overrun it.
- This allocator is old enough that a freed chunk's link pointer is a plain
  address, written in the clear — which is not true on a modern glibc.
