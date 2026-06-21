#pragma once
#include <stdint.h>
#include <stddef.h>
#include <wait.h>

typedef unsigned long long int reg_t;

typedef struct State
{
    pid_t pid;
    uint8_t patched_bytes[BUFSIZ];
    size_t n; // number of patched bytes
    struct user_regs_struct regs;
    uintptr_t libc_addr;
    uintptr_t argv_addr;
} State;

extern const size_t shellcode_bin_len;

int construct_shellcode(State *tracee);

size_t remote_malloc(int pid, void *addr, uint8_t *buff, size_t n);
int remote_attach_process(State *state);
int remote_state_preserve(State *state);
int remote_alloc_args_on_stack(State *state);
int remote_write_shellcode(State *state);
int remote_run_shellcode(State *state);
uintptr_t remote_libc_start_address(State *state);