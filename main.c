#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

int do_child(int argc, char **argv) {
	// Create new args table
    char *args [argc+1];
    // Copy old args table to new
    memcpy(args, argv, argc * sizeof(char*));
    // Set last arg element to NULL
    args[argc] = NULL;
    // System call that tells that this process is tracable
    ptrace(PTRACE_TRACEME);
    // Send signal SIGSTOP to child(myself), that will wait for parent
    kill(getpid(), SIGSTOP);
    // Execute program with args
    return execvp(args[0], args);
}

int wait_for_syscall(pid_t child) {
    int status;
    while (1) {
    	
    	// Continue child with tracing for system call
        ptrace(PTRACE_SYSCALL, child, 0, 0);
        
        // Wait for next stop of child
        waitpid(child, &status, 0);
        
        // Check if child has stopped for system call
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;

        // Check if child exited then we need to end monitoring
       	if (WIFEXITED(status))
            return 1;

        // Otherwise it stopped for some other reasons, so we just wait for next stop
    }
}


int do_trace(pid_t child) {
    int status, syscall, retval;
    // Wait for child
    waitpid(child, &status, 0);

    // Set options for traceing
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);

    // Start traceing in loop
    while(1) {
    	// Wait for system call start
        if (wait_for_syscall(child) != 0) break;

        // System cal start has accoured
        // Get system call
        syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
        if(syscall==1){
            fprintf(stderr, "%d write", syscall);

            int arg1 = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RDI);
            fprintf(stderr, "(%d) = ", arg1);
        }
        // Wait for system call return
        if (wait_for_syscall(child) != 0) break;

        // Get return value of system call
        retval = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);
        //fprintf(stderr, "%d\n", retval);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s prog args\n", argv[0]);
        exit(1);
    }

    // Fork for child
    pid_t child = fork();
    if (child == 0) {
    	// Execute child
        return do_child(argc-1, argv+1);
    } else {
        return do_trace(child);
    }
}