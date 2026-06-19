#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>

#define INS_MAX_SIZE 15

// for sleep
#include <unistd.h>

typedef unsigned long long int reg_t;

typedef struct State
{
    struct
    {
        uintptr_t addr;
        uint8_t val;
    } patched_bytes[BUFSIZ];
    int n; // number of patched bytes
    struct user_regs_struct regs;
} State;

int attach_remote_process(int pid);
int preserve_remote_state(int pid, State *state);

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <PID>\n", argv[0]);
        return 1;
    }
    int pid = atoi(argv[1]);
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

    if (attach_remote_process(pid))
    {
        printf("cannot attach to remote process\n");
        return 3;
    }

    State remote_state = {0};
    preserve_remote_state(pid, &remote_state);
    printf("stopped remote process at %#llx\n", remote_state.regs.rip);

    // end of main
    while (1)
    {
        sleep(1);
    }
}

int attach_remote_process(int pid)
{
    int wstatus;
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, &wstatus, 0);
    if (!WIFSTOPPED(wstatus))
    {
        printf("remote process did not stop as expected\n");
        return 1;
    }
    return 0;
}

int preserve_remote_state(int pid, State *state)
{
    if (ptrace(PTRACE_GETREGS, pid, NULL, &state->regs) == -1)
    {
        perror("");
        errno;
    }

    reg_t ip = state->regs.rip;
    state->n = 0;

    for (int i = 0; i < INS_MAX_SIZE; i++)
    {
        uint8_t byte = (uint8_t)ptrace(PTRACE_PEEKDATA, pid, ip + i, NULL);
        state->patched_bytes[i].addr = ip + i;
        state->patched_bytes[i].val = byte;
        state->n++;
    }
    return 0;
}