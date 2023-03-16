#include <sys/ptrace.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include "hw3_part1.h"
#include "elf64.h"

pid_t run_target(const char* programname,char *const argv[]);
void debugger(pid_t child_pid, unsigned long addr,int flag);


pid_t run_target(const char* programname,char *const argv[]){
    pid_t pid;
    pid = fork();
    if(pid > 0){
        return pid;
    }
    else if (pid == 0){
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            perror("ptrace");
            exit(1);
        }
        //execl(programname, programname, NULL);
	execv(programname, (argv+2));
    }
    else{
        perror("fork");
        exit(1);
    }
}
void debugger(pid_t child_pid, unsigned long addr,int flag){
    int counter =0;
    int wait_status;
    struct user_regs_struct regs;
    wait(&wait_status);
 if (WIFEXITED(wait_status)) {
			exit(0);
        } 
    if(flag == 1){
        unsigned long got_entry = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)addr,NULL);
	 long add_data = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)got_entry,NULL);
	unsigned long bp_data = (add_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
	ptrace(PTRACE_POKETEXT,child_pid,(void*)got_entry,(void*) bp_data);
	ptrace(PTRACE_CONT,child_pid,NULL,NULL);
	wait(&wait_status);
 	if (WIFEXITED(wait_status)) {
			exit(0);
        } 
	ptrace(PTRACE_POKETEXT,child_pid,(void*)got_entry,(void*)add_data);
	ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
	regs.rip-=1;
 	ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
	while(WIFSTOPPED(wait_status)){
		if(ptrace(PTRACE_PEEKTEXT,child_pid,(void*)addr,NULL) == got_entry){
			ptrace(PTRACE_SINGLESTEP,child_pid,NULL,NULL);
			wait(&wait_status);
 if (WIFEXITED(wait_status)) {
			exit(0);
        } 
		}
		else{
			addr = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)addr,NULL);
			break;
		}
	}
    }
    while(WIFSTOPPED(wait_status)){  
	long first_inst_in_func = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)addr, NULL);
        unsigned long breakpoint = (first_inst_in_func & 0xFFFFFFFFFFFFFF00) | 0xCC;
ptrace(PTRACE_POKETEXT,child_pid, (void*)addr, (void*)breakpoint);
ptrace(PTRACE_CONT, child_pid,NULL,NULL);
 wait(&wait_status);
 if (WIFEXITED(wait_status)) {
			exit(0);
        } 
ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
ptrace(PTRACE_POKETEXT,child_pid,(void*)addr,(void*)first_inst_in_func);
regs.rip-=1;
ptrace(PTRACE_SETREGS,child_pid,NULL, &regs);
ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
    unsigned long ret_add = ptrace(PTRACE_PEEKTEXT,child_pid,(void*)(regs.rsp), NULL); 
    long ret_data = ptrace(PTRACE_PEEKTEXT,child_pid,ret_add, NULL);
    unsigned long ret_bp = (ret_data & 0xFFFFFFFFFFFFFF00) | 0xCC;
    ptrace(PTRACE_POKETEXT, child_pid, ret_add, (void*)ret_bp);
	ptrace(PTRACE_CONT, child_pid, NULL,NULL);
	wait(&wait_status);
   if (WIFEXITED(wait_status)) {
			break;
        } 
	ptrace(PTRACE_POKETEXT, child_pid, (void*)ret_add, (void*)ret_data);
        ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
        regs.rip-=1;
        ptrace(PTRACE_SETREGS, child_pid,NULL,&regs);
	counter++;
        printf("PRF:: run #%d returned with %lld\n",counter,regs.rax);
    }
}
int main(int argc, char *const argv[]){
    int dyn_flag =0,err_val = 0;
    unsigned long ret_add = find_symbol(argv[1],argv[2],&err_val);
    if(err_val == -3){
        printf("PRF:: %s not an executable! :(\n", argv[2]);
        return 0;
    }
    if(err_val == -1){
        printf("PRF:: %s not found!\n", argv[1]);
        return 0;
    }
    if(err_val == -2){
        printf("PRF:: %s is not a global symbol! :(\n", argv[1]);
        return 0;
    }
   if(err_val == -4){ //part5
        dyn_flag=1;
    }
    pid_t child_pid=run_target(argv[2],argv);
    debugger(child_pid, ret_add,dyn_flag);
    return 0;
}