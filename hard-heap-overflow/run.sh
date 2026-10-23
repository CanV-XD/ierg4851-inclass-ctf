#!/bin/sh
# Run the challenge against the libc it was built for.
#
# It is linked against glibc 2.31, so it must be started through the loader that
# ships next to it. Running ./heap_overflow directly picks up your system's glibc
# — on a modern one the allocator's free-list pointers are safe-linked and the
# challenge behaves differently.
cd "$(dirname "$0")"
exec ./ld-2.31.so --library-path . ./heap_overflow "$@"
