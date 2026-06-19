# SO Injector
This Project implements a simple Shared-Object injector in linux,
using the `ptreace` mechanism.

# Steps
1. Using ptrace, attach to a running process and stop it
2. preserve remote process state: backup registers
3. allocate string (so path) on the stack
4. set registers to point to necessary value
5. write the `call` opcode to `dlopen` from libc.so
6. continue to next instruction with `ptrace`
7. run the so main - code execution
8. return original state and continue.
