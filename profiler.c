# include <stdio.h>
# include <stdlib.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <unistd.h>
# include <sys/user.h>
# include <sys/ptrace.h>
# include <string.h>
# include <stdbool.h>
# include <assert.h>

/*---------------------GLOBALS------------------------*/

# define BUF_SIZE 256
# define NUM_REGS 16
# define RAX 0
# define RBX 1
# define RDI 2
# define RSI 3
# define RDX 4
# define RCX 5
# define RBP 6
# define RSP 7
# define R8 8
# define R9 9
# define R10 10
# define R11 11
# define R12 12
# define R13 13
# define R14 14
# define R15 15

bool need_to_check_regs[NUM_REGS];
char var_names[NUM_REGS][BUF_SIZE];
char toPrint[NUM_REGS][BUF_SIZE];


/*---------------------CHECK REGS------------------------*/

bool is_rax(char reg[]) {
    if (strcmp(reg,"rax") == 0 || strcmp(reg,"eax") == 0 || strcmp(reg,"ax") == 0 || strcmp(reg,"al") == 0 || strcmp(reg,"ah") == 0) {
        return true;
    }
    return false;
}

bool is_rbx(char reg[]) {
    if (strcmp(reg,"rbx") == 0 || strcmp(reg,"ebx") == 0 || strcmp(reg,"bx") == 0 || strcmp(reg,"bl") == 0  || strcmp(reg,"bh") == 0) {
        return true;
    }
    return false;
}

bool is_rcx(char reg[]) {
    if (strcmp(reg,"rcx") == 0 || strcmp(reg,"ecx") == 0 || strcmp(reg,"cx") == 0 || strcmp(reg,"cl") == 0 || strcmp(reg,"ch") == 0) {
        return true;
    }
    return false;
}

bool is_rdx(char reg[]) {
    if (strcmp(reg,"rdx") == 0 || strcmp(reg,"edx") == 0 || strcmp(reg,"dx") == 0 || strcmp(reg,"dl") == 0 || strcmp(reg,"dh") == 0) {
        return true;
    }
    return false;
}

bool is_rsi(char reg[]) {
    if (strcmp(reg,"rsi") == 0 || strcmp(reg,"esi") == 0 || strcmp(reg,"si") == 0 || strcmp(reg,"sil") == 0) {
        return true;
    }
    return false;
}

bool is_rdi(char reg[]) {
    if (strcmp(reg,"rdi") == 0 || strcmp(reg,"edi") == 0 || strcmp(reg,"di") == 0 || strcmp(reg,"dil") == 0) {
        return true;
    }
    return false;
}

bool is_rbp(char reg[]) {
    if (strcmp(reg,"rbp") == 0 || strcmp(reg,"ebp") == 0 || strcmp(reg,"bp") == 0 || strcmp(reg,"bpl") == 0) {
        return true;
    }
    return false;
}

bool is_rsp(char reg[]) {
    if (strcmp(reg,"rsp") == 0 || strcmp(reg,"esp") == 0 || strcmp(reg,"sp") == 0 || strcmp(reg,"spl") == 0) {
        return true;
    }
    return false;
}

bool is_r8(char reg[]) {
    if (strcmp(reg,"r8") == 0 || strcmp(reg,"r8d") == 0 || strcmp(reg,"r8b") == 0 || strcmp(reg,"r8w") == 0) {
        return true;
    }
    return false;
}

bool is_r9(char reg[]) {
    if (strcmp(reg,"r9") == 0 || strcmp(reg,"r9d") == 0 || strcmp(reg,"r9b") == 0 || strcmp(reg,"r9w") == 0) {
        return true;
    }
    return false;
}

bool is_r10(char reg[]) {
    if (strcmp(reg,"r10") == 0 || strcmp(reg,"r10d") == 0 || strcmp(reg,"r10b") == 0 || strcmp(reg,"r10w") == 0) {
        return true;
    }
    return false;
}

bool is_r11(char reg[]) {
    if (strcmp(reg,"r11") == 0 || strcmp(reg,"r11d") == 0 || strcmp(reg,"r11b") == 0 || strcmp(reg,"r11w") == 0) {
        return true;
    }
    return false;
}

bool is_r12(char reg[]) {
    if (strcmp(reg,"r12") == 0 || strcmp(reg,"r12d") == 0 || strcmp(reg,"r12b") == 0 || strcmp(reg,"r12w") == 0) {
        return true;
    }
    return false;
}

bool is_r13(char reg[]) {
    if (strcmp(reg,"r13") == 0 || strcmp(reg,"r13d") == 0 || strcmp(reg,"r13b") == 0 || strcmp(reg,"r13w") == 0) {
        return true;
    }
    return false;
}

bool is_r14(char reg[]) {
    if (strcmp(reg,"r14") == 0 || strcmp(reg,"r14d") == 0 || strcmp(reg,"r14b") == 0 || strcmp(reg,"r14w") == 0) {
        return true;
    }
    return false;
}

bool is_r15(char reg[]) {
    if (strcmp(reg,"r15") == 0 || strcmp(reg,"r15d") == 0 || strcmp(reg,"r15b") == 0 || strcmp(reg,"r15w") == 0) {
        return true;
    }
    return false;
}

/*------------------AUX FUNCTIONS------------------------*/

void check_changes(struct user_regs_struct regs_before, struct user_regs_struct regs_after) {
    int counter = 0;
    char tempBuf[BUF_SIZE];

    // check changes
    if (need_to_check_regs[RAX] && regs_before.rax != regs_after.rax) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[RAX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.rax);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.rax);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[RBX] && regs_before.rbx != regs_after.rbx) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[RBX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.rbx);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.rbx);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[RCX] && regs_before.rcx != regs_after.rcx) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[RCX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.rcx);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.rcx);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[RDX] && regs_before.rdx != regs_after.rdx) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[RDX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.rdx);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.rdx);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[RSI] && regs_before.rsi != regs_after.rsi) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[RSI]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.rsi);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.rsi);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[RDI] && regs_before.rdi != regs_after.rdi) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[RDI]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.rdi);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.rdi);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[RBP] && regs_before.rbp != regs_after.rbp) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[RBP]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.rbp);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.rbp);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[RSP] && regs_before.rsp != regs_after.rsp) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[RSP]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.rsp);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.rsp);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[R8] && regs_before.r8 != regs_after.r8) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[R8]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.r8);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.r8);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[R9] && regs_before.r9 != regs_after.r9) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[R9]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.r9);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.r9);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[R10] && regs_before.r10 != regs_after.r10) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[R10]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.r10);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.r10);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[R11] && regs_before.r11 != regs_after.r11) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[R11]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.r11);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.r11);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[R12] && regs_before.r12 != regs_after.r12) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[R12]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.r12);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.r12);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[R13] && regs_before.r13 != regs_after.r13) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[R13]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.r13);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.r13);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[R14] && regs_before.r14 != regs_after.r14) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[R14]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.r14);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.r14);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[R15] && regs_before.r15 != regs_after.r15) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[R15]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", regs_before.r15);
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", regs_after.r15);
        strcat(toPrint[counter], tempBuf);
        counter++;
    }

    // sort
    int swapped=1;
    while(swapped > 0) {
        swapped=0;
        for (int i=1; i<counter; i++) {
            if (strcmp(toPrint[i-1], toPrint[i]) > 0) {
                char temp[BUF_SIZE];
                strcpy(temp, toPrint[i]);
                strcpy(toPrint[i], toPrint[i-1]);
                strcpy(toPrint[i-1], temp);
                swapped=1;
            }
        }
    }

    // print
    for (int j=0; j<counter; j++) {
        printf("%s\n", toPrint[j]);
    }
}

int main (int argc, char* argv[]) {
	unsigned long start_addr = strtol(argv[1], NULL, 16);
	unsigned long end_addr = strtol(argv[2], NULL, 16);
	for (int i=0; i<NUM_REGS; i++) need_to_check_regs[i] = false;

	// get vars from user
	char var[BUF_SIZE];
	char reg[BUF_SIZE];		
	scanf("%s%s", var, reg);
	while (strcmp(var,"run") != 0 && strcmp(reg,"profile") != 0) {
		if (is_rax) {
		    strcpy(var_names[RAX], var);
		    need_to_check_regs[RAX] = true;
		}
		else if (is_rbx) {
	        strcpy(var_names[RBX], var);
            need_to_check_regs[RBX] = true;
		}
		else if (is_rcx) {
            strcpy(var_names[RCX], var);
            need_to_check_regs[RCX] = true;
		}
		else if (is_rdx) {
            strcpy(var_names[RDX], var);
            need_to_check_regs[RDX] = true;
		}
		else if (is_rsi) {
		    strcpy(var_names[RSI], var);
		    need_to_check_regs[RSI] = true;
		}
		else if (is_rdi) {
		    strcpy(var_names[RDI], var);
		    need_to_check_regs[RDI] = true;
		}
		else if (is_rbp) {
		    strcpy(var_names[RBP], var);
		    need_to_check_regs[RBP] = true;
		}
		else if (is_rsp) {
		    strcpy(var_names[RSP], var);
		    need_to_check_regs[RSP] = true;
		}
		else if (is_r8) {
		    strcpy(var_names[R8], var);
		    need_to_check_regs[R8] = true;
		}
		else if (is_r9) {
		    strcpy(var_names[R9], var);
		    need_to_check_regs[R9] = true;
		}
		else if (is_r10) {
		    strcpy(var_names[R10], var);
		    need_to_check_regs[R10] = true;
		}
		else if (is_r11) {
		    strcpy(var_names[R11], var);
		    need_to_check_regs[R11] = true;
		}
		else if (is_r12) {
		    strcpy(var_names[R12], var);
		    need_to_check_regs[R12] = true;
		}
		else if (is_r13) {
		    strcpy(var_names[R13], var);
		    need_to_check_regs[R13] = true;
		}
		else if (is_r14) {
		    strcpy(var_names[R14], var);
		    need_to_check_regs[R14] = true;
		}
		else if (is_r15) {
		    strcpy(var_names[R15], var);
		    need_to_check_regs[R15] = true;
		}
		else {
		    assert(false); // not supposed to get here
		}
	
		scanf("%s%s", var, reg); // get next strings
	}

	// debug
	pid_t child_pid;
	child_pid = fork();

	if (child_pid < 0) {
	    perror("fork");
	    exit(1);
	}

	else if (child_pid == 0) { // child
	    if(ptrace(PTRACE_TRACEME, 0, NULL, NULL)<0) {
	        perror("ptrace_traceme");
	        exit(1);
	    }

	    execv(argv[3], &argv[4]);

	    perror("execv"); // not supposed to get here
	    exit(1);
	}

	else { // parent process        
	    int wait_status;
        struct user_regs_struct regs_before , regs_after;

        // wait for child to stop after execv
        if (wait(&wait_status)<0) {
            perror("first wait");
            exit(1);
        }

        // set first breakpoint
        long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)start_addr, NULL);
        if (data<0) {
            perror("first peektext");
            exit(1);
        }
        unsigned long data_trap =(data & 0xFFFFFFFFFFFFFF00)|0xCC;
        if(ptrace(PTRACE_POKETEXT, child_pid, (void*)start_addr, (void*)data_trap)<0) {
            perror("first poketext");
            exit(1);
        }

        // continue
        if(ptrace(PTRACE_CONT, child_pid, NULL, NULL)<0) {
            perror ("first cont");
            exit(1);
        }

        // wait for child to reach the first breakpoint
        if (wait(&wait_status)<0) {
            perror("first wait");
            exit(1);
        }

        // get regs at the first breakpoint
        if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs_before)<0) {
            perror("first getregs");
            exit(1);
        }

        // remove first breakpoint
        if(ptrace(PTRACE_POKETEXT, child_pid, (void*)start_addr, (void*)data)<0) {
            perror("poketext before removing first breakpoint");
            exit(1);
        }
        regs_before.rip -=1;
        if(ptrace(PTRACE_SETREGS, child_pid, 0, &regs_before)<0) {
            perror("setregs after removing first breakpoint");
            exit(1);
        }

        // set second breakpoint
        data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)end_addr, NULL);
        if (data<0) {
            perror("second peektext");
            exit(1);
        }
        data_trap = (data & 0xFFFFFFFFFFFFFF00)|0xCC;
        if(ptrace(PTRACE_POKETEXT, child_pid, (void*)end_addr, (void*)data_trap)<0) {
            perror("second poketext");
            exit(1);
        }

        // continue
        if(ptrace(PTRACE_CONT, child_pid, NULL, NULL)<0) {
            perror ("second cont");
            exit(1);
        }

        // wait for child to reach second breakpoint
        if (wait(&wait_status)<0) {
            perror("second wait");
            exit(1);
        }

        // get regs after second breakpoint
        if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs_after)<0) {
            perror("second getregs");
            exit(1);
        }

        // remove second breakpoint
        if(ptrace(PTRACE_POKETEXT, child_pid, (void*)end_addr, (void*)data)<0) {
            perror("poketext before removing second breakpoint");
            exit(1);
        }
        regs_after.rip -=1;
        if(ptrace(PTRACE_SETREGS, child_pid, 0, &regs_after)<0) {
            perror("setregs after removing second breakpoint");
            exit(1);
        }

        // continue
        if(ptrace(PTRACE_CONT, child_pid, 0, 0)<0) {
            perror("last cont");
            exit(1);
        }

        // wait for child to finish
        if (wait(&wait_status)<0) {
            perror("last wait");
            exit(1);
        }
        if(WIFEXITED(wait_status)) {
            // child exited properly		
		    check_changes(regs_before, regs_after);
        }
        else {          
		    assert(false); //should not get here
        }
	}
}