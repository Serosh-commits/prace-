#include <sys/ptrace.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
int main() {
    pid_t pid = fork();
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl("/bin/ls", "ls", NULL);
        perror("execl failed");
        return 1;
    } else {
        int status;
        wait(&status);
        ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
        printf("Quantum PolyLDE Curiosity Nexus: Tracing traps\n");
    }
    return 0;
}
