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
# include <errno.h>

/*---------------------GLOBALS------------------------*/

# define BUF_SIZE 512
# define NUM_REGS 24
# define RAX 0
# define EAX 1
# define AX 2
# define AH 3
# define AL 4
# define RBX 5
# define EBX 6
# define BX 7
# define BH 8
# define BL 9
# define RCX 10
# define ECX 11
# define CX 12
# define CH 13
# define CL 14
# define RDX 15
# define EDX 16
# define DX 17
# define DH 18
# define DL 19
# define RSI 20
# define ESI 21
# define SI 22
# define SIL 23


bool need_to_check_regs[NUM_REGS];
char var_names[NUM_REGS][BUF_SIZE];
char toPrint[NUM_REGS][BUF_SIZE];


/*---------------------CHECK REGS------------------------*/

bool is_rax(char reg[]) {
    if (strcmp(reg,"rax") == 0) {
        return true;
    }
    return false;
}

bool is_eax(char reg[]) {
    if (strcmp(reg,"eax") == 0) {
        return true;
    }
    return false;
}

bool is_ax(char reg[]) {
    if (strcmp(reg,"ax") == 0) {
        return true;
    }
    return false;
}

bool is_ah(char reg[]) {
    if (strcmp(reg,"ah") == 0) {
        return true;
    }
    return false;
}

bool is_al(char reg[]) {
    if (strcmp(reg,"al") == 0) {
        return true;
    }
    return false;
}

bool is_rbx(char reg[]) {
    if (strcmp(reg,"rbx") == 0) {
        return true;
    }
    return false;
}

bool is_ebx(char reg[]) {
    if (strcmp(reg,"ebx") == 0) {
        return true;
    }
    return false;
}

bool is_bx(char reg[]) {
    if (strcmp(reg,"bx") == 0) {
        return true;
    }
    return false;
}

bool is_bh(char reg[]) {
    if (strcmp(reg,"bh") == 0) {
        return true;
    }
    return false;
}

bool is_bl(char reg[]) {
    if (strcmp(reg,"bl") == 0) {
        return true;
    }
    return false;
}

bool is_rcx(char reg[]) {
    if (strcmp(reg,"rcx") == 0) {
        return true;
    }
    return false;
}

bool is_ecx(char reg[]) {
    if (strcmp(reg,"ecx") == 0) {
        return true;
    }
    return false;
}

bool is_cx(char reg[]) {
    if (strcmp(reg,"cx") == 0) {
        return true;
    }
    return false;
}

bool is_ch(char reg[]) {
    if (strcmp(reg,"ch") == 0) {
        return true;
    }
    return false;
}

bool is_cl(char reg[]) {
    if (strcmp(reg,"cl") == 0) {
        return true;
    }
    return false;
}

bool is_rdx(char reg[]) {
    if (strcmp(reg,"rdx") == 0) {
        return true;
    }
    return false;
}

bool is_edx(char reg[]) {
    if (strcmp(reg,"edx") == 0) {
        return true;
    }
    return false;
}

bool is_dx(char reg[]) {
    if (strcmp(reg,"dx") == 0) {
        return true;
    }
    return false;
}

bool is_dh(char reg[]) {
    if (strcmp(reg,"dh") == 0) {
        return true;
    }
    return false;
}

bool is_dl(char reg[]) {
    if (strcmp(reg,"dl") == 0) {
        return true;
    }
    return false;
}

bool is_rsi(char reg[]) {
    if (strcmp(reg,"rsi") == 0) {
        return true;
    }
    return false;
}

bool is_esi(char reg[]) {
    if (strcmp(reg,"esi") == 0) {
        return true;
    }
    return false;
}

bool is_si(char reg[]) {
    if (strcmp(reg,"si") == 0) {
        return true;
    }
    return false;
}

bool is_sil(char reg[]) {
    if (strcmp(reg,"sil") == 0) {
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
    if (need_to_check_regs[EAX] && (regs_before.rax & 0xFFFFFFFF) != (regs_after.rax & 0xFFFFFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[EAX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rax & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rax & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[AX] && (regs_before.rax & 0xFFFF) != (regs_after.rax & 0xFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[AX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rax & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rax & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[AH] && (regs_before.rax & 0xFF00) != (regs_after.rax & 0xFF00)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[AH]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rax & 0xFF00));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rax & 0xFF00));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[AL] && (regs_before.rax & 0xFF) != (regs_after.rax & 0xFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[AL]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rax & 0xFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rax & 0xFF));
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
    if (need_to_check_regs[EBX] && (regs_before.rbx & 0xFFFFFFFF) != (regs_after.rbx & 0xFFFFFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[EBX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rbx & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rbx & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[BX] && (regs_before.rbx & 0xFFFF) != (regs_after.rbx & 0xFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[BX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rbx & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rbx & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[BH] && (regs_before.rbx & 0xFF00) != (regs_after.rbx & 0xFF00)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[BH]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rbx & 0xFF00));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rbx & 0xFF00));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[BL] && (regs_before.rbx & 0xFF) != (regs_after.rbx & 0xFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[BL]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rbx & 0xFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rbx & 0xFF));
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
    if (need_to_check_regs[ECX] && (regs_before.rcx & 0xFFFFFFFF) != (regs_after.rcx & 0xFFFFFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[ECX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rcx & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rcx & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[CX] && (regs_before.rcx & 0xFFFF) != (regs_after.rcx & 0xFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[CX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rcx & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rcx & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[CH] && (regs_before.rcx & 0xFF00) != (regs_after.rcx & 0xFF00)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[CH]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rcx & 0xFF00));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rcx & 0xFF00));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[CL] && (regs_before.rcx & 0xFF) != (regs_after.rcx & 0xFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[CL]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rcx & 0xFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rcx & 0xFF));
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
    if (need_to_check_regs[EDX] && (regs_before.rdx & 0xFFFFFFFF) != (regs_after.rdx & 0xFFFFFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[EDX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rdx & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rdx & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[DX] && (regs_before.rdx & 0xFFFF) != (regs_after.rdx & 0xFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[DX]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rdx & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rdx & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[DH] && (regs_before.rdx & 0xFF00) != (regs_after.rdx & 0xFF00)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[DH]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rdx & 0xFF00));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rdx & 0xFF00));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[DL] && (regs_before.rdx & 0xFF) != (regs_after.rdx & 0xFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[DL]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rdx & 0xFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rdx & 0xFF));
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
    if (need_to_check_regs[ESI] && (regs_before.rsi & 0xFFFFFFFF) != (regs_after.rsi & 0xFFFFFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[ESI]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rsi & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rsi & 0xFFFFFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[SI] && (regs_before.rsi & 0xFFFF) != (regs_after.rsi & 0xFFFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[SI]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rsi & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rsi & 0xFFFF));
        strcat(toPrint[counter], tempBuf);
        counter++;
    }
    if (need_to_check_regs[SIL] && (regs_before.rsi & 0xFF) != (regs_after.rsi & 0xFF)) {
        strcpy(toPrint[counter],"PRF:: ");
        strcat(toPrint[counter], var_names[SIL]);
        strcat(toPrint[counter], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rsi & 0xFF));
        strcat(toPrint[counter], tempBuf);
        strcat(toPrint[counter], "->");
        sprintf(tempBuf, "%lld", (regs_after.rsi & 0xFF));
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
		if (is_rax(reg)) {
			strcpy(var_names[RAX], var);
			need_to_check_regs[RAX] = true;
		}
        else if (is_eax(reg)) {
            strcpy(var_names[EAX], var);
            need_to_check_regs[EAX] = true;
        }
        else if (is_ax(reg)) {
            strcpy(var_names[AX], var);
            need_to_check_regs[AX] = true;
        }
        else if (is_ah(reg)) {
            strcpy(var_names[AH], var);
            need_to_check_regs[AH] = true;
        }
        else if (is_al(reg)) {
            strcpy(var_names[AL], var);
            need_to_check_regs[AL] = true;
        }
		else if (is_rbx(reg)) {
		    strcpy(var_names[RBX], var);
		    need_to_check_regs[RBX] = true;
		}
        else if (is_ebx(reg)) {
            strcpy(var_names[EBX], var);
            need_to_check_regs[EBX] = true;
        }
        else if (is_bx(reg)) {
            strcpy(var_names[BX], var);
            need_to_check_regs[BX] = true;
        }
        else if (is_bh(reg)) {
            strcpy(var_names[BH], var);
            need_to_check_regs[BH] = true;
        }
        else if (is_bl(reg)) {
            strcpy(var_names[BL], var);
            need_to_check_regs[BL] = true;
        }
		else if (is_rcx(reg)) {
		    strcpy(var_names[RCX], var);
		    need_to_check_regs[RCX] = true;
		}
        else if (is_ecx(reg)) {
            strcpy(var_names[ECX], var);
            need_to_check_regs[ECX] = true;
        }
        else if (is_cx(reg)) {
            strcpy(var_names[CX], var);
            need_to_check_regs[CX] = true;
        }
        else if (is_ch(reg)) {
            strcpy(var_names[CH], var);
            need_to_check_regs[CH] = true;
        }
        else if (is_cl(reg)) {
            strcpy(var_names[CL], var);
            need_to_check_regs[CL] = true;
        }
		else if (is_rdx(reg)) {
		    strcpy(var_names[RDX], var);
		    need_to_check_regs[RDX] = true;
		}
        else if (is_edx(reg)) {
            strcpy(var_names[EDX], var);
            need_to_check_regs[EDX] = true;
        }
        else if (is_dx(reg)) {
            strcpy(var_names[DX], var);
            need_to_check_regs[DX] = true;
        }
        else if (is_dh(reg)) {
            strcpy(var_names[DH], var);
            need_to_check_regs[DH] = true;
        }
        else if (is_dl(reg)) {
            strcpy(var_names[DL], var);
            need_to_check_regs[DL] = true;
        }
		else if (is_rsi(reg)) {
		    strcpy(var_names[RSI], var);
		    need_to_check_regs[RSI] = true;
		}
		else if (is_esi(reg)) {
		    strcpy(var_names[ESI], var);
		    need_to_check_regs[ESI] = true;
		}
        else if (is_si(reg)) {
            strcpy(var_names[SI], var);
            need_to_check_regs[SI] = true;
        }
        else if (is_sil(reg)) {
            strcpy(var_names[SIL], var);
            need_to_check_regs[SIL] = true;
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
	    exit(1);
	}

	else if (child_pid == 0) { // child
	        errno = 0;
	    	if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == (-1) && errno != 0) {
	    	    exit(1);
	    	}

	    	execv(argv[3], &argv[4]);

	    	// not supposed to get here
	    	exit(1);
	}

	else { // parent process        
	    	int wait_status;
        	struct user_regs_struct regs_before , regs_after;

        	// wait for child to stop after execv
        	if (wait(&wait_status)<0) {
        	    exit(1);
        	}
		
		// set first breakpoint (first time)
		errno = 0;
		long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)start_addr, NULL);
		if (data == (-1) && errno != 0) {
		    exit(1);
		}
		unsigned long data_trap =(data & 0xFFFFFFFFFFFFFF00)|0xCC;
		if(ptrace(PTRACE_POKETEXT, child_pid, (void*)start_addr, (void*)data_trap) == (-1) && errno != 0) {
		    exit(1);
		}
		
		// continue
		if(ptrace(PTRACE_CONT, child_pid, NULL, NULL) == (-1) && errno != 0) {
		    exit(1);
		}
		
		// wait for child to reach first breakpoint
        	if (wait(&wait_status) < 0) {
        	    exit(1);
        	}
	
		while (!WIFEXITED(wait_status)) { // while child didn't finished
			// REACHED FIRST BREAKPOINT
			// get regs at the first breakpoint
			if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs_before) == (-1) && errno != 0) {
			    exit(1);
			}

			// remove first breakpoint
			if(ptrace(PTRACE_POKETEXT, child_pid, (void*)start_addr, (void*)data) == (-1) && errno != 0) {
			    exit(1);
			}
			regs_before.rip -=1;
			if(ptrace(PTRACE_SETREGS, child_pid, 0, &regs_before) == (-1) && errno != 0) {
			    exit(1);
			}

			// set second breakpoint
			data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)end_addr, NULL);
			if (data == (-1) && errno != 0) {
			    exit(1);
			}
			data_trap = (data & 0xFFFFFFFFFFFFFF00)|0xCC;
			if(ptrace(PTRACE_POKETEXT, child_pid, (void*)end_addr, (void*)data_trap) == (-1) && errno != 0) {
			    exit(1);
			}

			// continue
			if(ptrace(PTRACE_CONT, child_pid, NULL, NULL) == (-1) && errno != 0) {
			    exit(1);
			}

			// wait for child to reach second breakpoint
			if (wait(&wait_status)<0) {
			    exit(1);
			}
		
			if (WIFEXITED(wait_status)) break; // child finished before reaching second breakpoint
		
			// REACHED SECOND BREAKPOINT
			// get regs at second breakpoint
			if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs_after) == (-1) && errno != 0) {
			    exit(1);
			}
			
			// remove second breakpoint
			if(ptrace(PTRACE_POKETEXT, child_pid, (void*)end_addr, (void*)data) == (-1) && errno != 0) {
			    exit(1);
			}
			regs_after.rip -=1;
			if(ptrace(PTRACE_SETREGS, child_pid, 0, &regs_after) == (-1) && errno != 0) {
			    exit(1);
			}
			
			// continue one command
			if (ptrace(PTRACE_SINGLESTEP, child_pid, NULL, NULL) < 0) {
				exit(1);
			}
			if (wait(&wait_status)<0) {
			    exit(1);
			}
			
			// get regs after second breakpoint
			if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs_after) == (-1) && errno != 0) {
				exit(1);
			} 
		
			// print changes
			check_changes(regs_before, regs_after);
		
			// set first breakpoint again
			data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)start_addr, NULL);
			if (data == (-1) && errno != 0) {
			    exit(1);
			}
			data_trap =(data & 0xFFFFFFFFFFFFFF00)|0xCC;
			if(ptrace(PTRACE_POKETEXT, child_pid, (void*)start_addr, (void*)data_trap) == (-1) && errno != 0) {
			    exit(1);
			}

			// continue
			if(ptrace(PTRACE_CONT, child_pid, NULL, NULL) == (-1) && errno != 0) {
			    exit(1);
			}

			// wait for child to reach the first breakpoint again
			if (wait(&wait_status)<0) {
			    exit(1);
			}
		}
		
		// if reached here child finished, so debugger (father) finished also
	}
}
