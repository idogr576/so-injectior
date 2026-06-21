#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <signal.h>

#include "injector.h"

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }
    pid_t pid = atoi(argv[1]);
    if (errno)
    {
        perror("");
        return 2;
    }
    char cmdline[BUFSIZ] = {0};
    char cmdlinePath[BUFSIZ] = {0};
    FILE *fp = NULL;

    snprintf(cmdlinePath, sizeof(cmdlinePath), "/proc/%d/cmdline", pid);
    fp = fopen(cmdlinePath, "r");
    if (!fp)
    {
        printf("could not open file: %s\n", cmdlinePath);
    }
    fread(cmdline, 1, sizeof(cmdline), fp);
    printf("Intercepting PID %d: %s\n", pid, cmdline);

    State remote_state = {.pid = pid, .n = shellcode_bin_len};
    State *pstate = &remote_state;

    if (remote_attach_process(pstate))
    {
        printf("cannot attach to remote process\n");
        return 3;
    }
    printf("stopped remote process at %#llx\n", remote_state.regs.rip);

    uintptr_t p = remote_libc_start_address(pstate);
    printf("libc start address is %#lx\n", p);

    remote_state_preserve(pstate);

    remote_alloc_args_on_stack(pstate);

    printf("using resolved addresses to build a shellcode\n");
    construct_shellcode(pstate);

    remote_write_shellcode(pstate);

    remote_run_shellcode(pstate);
    printf("state restored... detaching\n");

    ptrace(PTRACE_DETACH, pid, 0, 0);

    return 0;
}