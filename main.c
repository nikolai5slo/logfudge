#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include "user.h"
#include <sys/socket.h>

#if WORDSIZE == 64
	#define SYSCALL_OPEN 2
	#define SYSCALL_WRITE 1
	#define SYSCALL_SELECT 32
	#define SYSCALL_CONNECT 42
	#define SYSCALL_SENDTO 44
	#define SYSCALL_SYSLOG 103
#endif

int exe_child(int argc, char **argv);
int wait_for_syscall(pid_t pid);
int monitor_child(pid_t pid, char* outfilename);
char* get_str_from_addr(pid_t pid, long addr);
long uregs_regs(struct user_regs_struct uregs, int regnum);


int exe_child(int argc, char **argv) {
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

int wait_for_syscall(pid_t pid) {
    int status;
    while (1) {
    	
    	// Continue child with tracing for system call
        ptrace(PTRACE_SYSCALL, pid, 0, 0);
        
        // Wait for next stop of child
        waitpid(pid, &status, 0);
        
        // Check if child has stopped for system call
        if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
            return 0;

        // Check if child exited then we need to end monitoring
       	if (WIFEXITED(status))
            return 1;

        // Otherwise it stopped for some other reasons, so we just wait for next stop
    }
}
/*
char* get_str_from_addr(pid_t pid,long addr,int len){
	char* str=malloc(sizeof(char)*len);
	for(int i;i<len;i++)
	    str[i]=ptrace(PTRACE_PEEKDATA, pid, (void*)(addr++),NULL);
	return str;
}*/

char* get_str_from_addr(pid_t pid,long addr){
	char* str=NULL;
	int i=0;
	do{
		str=realloc(str,sizeof(char)*(i+1));
		str[i]=ptrace(PTRACE_PEEKDATA, pid, (void*)(addr++));
	}
	while(str[i++]!=0);

	return str;
}

void write_form_addr(int fd,pid_t pid,long addr,size_t len){
	long buffer;
	for(int i=0;i<len;i+=sizeof(long)){
		buffer=ptrace(PTRACE_PEEKDATA, pid, addr);
		write(fd, &buffer, sizeof(long));
		addr+=sizeof(long);
	}

	buffer=ptrace(PTRACE_PEEKDATA, pid, addr);
	write(fd, &buffer, sizeof(long)%sizeof(long));
} 

long uregs_regs(struct user_regs_struct uregs, int regnum){
	#if WORDSIZE == 64
		switch(regnum){
			case 0: return uregs.orig_rax;
			case 1: return uregs.rdi;
			case 2: return uregs.rsi;
			case 3: return uregs.rdx;
			case 4: return uregs.r10;
			case 5: return uregs.r8;
			case 6: return uregs.r9;
			default: return 0;
		}
	#else

	#endif
}

int monitor_child(pid_t pid, char* outfilename) {
    int status, syscall, retval;
    // Wait for child
    waitpid(pid, &status, 0);

    // Set options for traceing
    ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

    struct user_regs_struct uregs;
    int out=open(outfilename,O_WRONLY|O_CREAT, S_IRUSR | S_IRGRP | S_IROTH);

    if(!out){
    	fprintf(stderr, "Error opening output file \"%s\" for write.\n",outfilename);
    	fflush(stderr);
    	exit(1);
    }

    // Start traceing in loop
    while(1) {
    	// Wait for system call start
        if (wait_for_syscall(pid) != 0) break;

        // System cal start has accoured
        // Get system call
        syscall = ptrace(PTRACE_GETREGS, pid, 0, &uregs);
        char* str;
        long tmp;
        short sa_family;

        //fprintf(stderr,"%d\n",uregs.orig_rax);
        //printf("HERE %d",uregs_regs(uregs,0)); fflush(stdout);
        switch(uregs_regs(uregs,0)){
        	case SYSCALL_OPEN: // If it is systemcall for open save descriptor
        		tmp=uregs_regs(uregs,2);
	        	if(tmp & O_WRONLY || tmp & O_RDWR){
	        		str=get_str_from_addr(pid, uregs_regs(uregs,1));

	        		tmp=SYSCALL_OPEN;
	        		write(out,&tmp,sizeof(tmp));
	        		
	        		tmp=uregs_regs(uregs,1);
	        		write(out,&tmp,sizeof(tmp));
	        		
	        		// Write string length
	        		tmp=strlen(str);
	        		write(out,&tmp,sizeof(tmp));

	        		// Write actual string
	        		write(out,str,sizeof(char)*strlen(str));
	            	fprintf(stderr,"%s\n",str);    
	            }
        		break;
        	case SYSCALL_WRITE:
        		str=get_str_from_addr(pid, uregs_regs(uregs,2));

        		tmp=SYSCALL_WRITE;
        		write(out,&tmp,sizeof(tmp));
        		
        		tmp=uregs_regs(uregs,1);
        		write(out,&tmp,sizeof(tmp));
        		
        		// Write data length
        		tmp=uregs_regs(uregs,3);
        		write(out,&tmp,sizeof(tmp));

        		// Write actual data
        		write_form_addr(out, pid, uregs_regs(uregs,2), uregs_regs(uregs,3));

            	fprintf(stderr,"WRITE %s %X\n",str,uregs_regs(uregs,3));   
        		break;
        	case SYSCALL_CONNECT: 

        		sa_family=ptrace(PTRACE_PEEKDATA, pid, uregs_regs(uregs,2));
        		if(sa_family==AF_UNIX){
        			write_form_addr(out, pid, uregs_regs(uregs,2)+sizeof(short), 108);
        			
        			str=get_str_from_addr(pid, uregs_regs(uregs,2)+sizeof(short));
        			fprintf(stderr,"CONNECT %d %s\n",uregs_regs(uregs,1),str);  
        		}

        		break;
        	case SYSCALL_SENDTO:
        		str=get_str_from_addr(pid, uregs_regs(uregs,2));
				tmp=SYSCALL_WRITE;
        		write(out,&tmp,sizeof(tmp));
        		

        		tmp=uregs_regs(uregs,1);
        		write(out,&tmp,sizeof(tmp));
        		
        		// Write data length
        		tmp=uregs_regs(uregs,3);
        		write(out,&tmp,sizeof(tmp));

        		// Write actual data
        		write_form_addr(out, pid, uregs_regs(uregs,2), uregs_regs(uregs,3));

        		fprintf(stderr,"SENDTO %s\n",str); 
        		break;
        	case SYSCALL_SYSLOG:
        		str=get_str_from_addr(pid,uregs_regs(uregs,2));

        		tmp=SYSCALL_SYSLOG;
        		write(out,&tmp,sizeof(tmp));
        		
        		// Write string length
        		tmp=strlen(str);
        		write(out,&tmp,sizeof(tmp));

        		// Write actual string
        		write(out,str,sizeof(char)*strlen(str));

        		fprintf(stderr,"%s\n",str);         
        		break;
        }

        // Wait for system call return
        if (wait_for_syscall(pid) != 0) break;

        // Get return value of system call
        retval = ptrace(PTRACE_PEEKUSER, pid, sizeof(long)*RAX);
        //fprintf(stderr, "%d\n", retval);

        //fflush(out);
    }
    close(out);
    return 0;
}

void simulate(char* intfilename){
	int in=open(intfilename,O_RDONLY);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s prog args\n", argv[0]);
        exit(1);
    }
    // Fork for chil
    pid_t child = fork();
    if (child == 0) {
    	// Execute child
        return exe_child(argc-2, argv+2);
    } else {
    	// Parent monitors child write and log syscalls
        return monitor_child(child,argv[1]);
    }
}