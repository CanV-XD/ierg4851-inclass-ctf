# Medium-Format String

**Difficulty:** Medium · **Points:** 200 · **Topic:** Format string → GOT overwrite

## Description

An echo server that repeats what you type — three times. Get a shell and read the
flag.

## Running

```bash
./fsb_got
```

The flag is `flag.txt` once you have a shell.

## Notes

- The source is included. Look carefully at how your input is handed to `printf`.
- **You get exactly three turns.** Deciding what each one is for is the exercise.
- The binary is **not PIE**, and RELRO is only partial — which means the GOT is
  writable at fixed addresses.
- A `libc.so.6` ships in this directory. Any offset you compute inside libc has to
  come from **that** build, not from your system's.
- Send your payload in a single write; the input is read once per turn.
