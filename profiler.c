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
# define NUM_REGS 16
# define RAX 0
# define RBX 1
# define RCX 2
# define RDX 3
# define RSI 4


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
		else if (is_rbx(reg)) {
	        	strcpy(var_names[RBX], var);
            		need_to_check_regs[RBX] = true;
		}
		else if (is_rcx(reg)) {
            		strcpy(var_names[RCX], var);
            		need_to_check_regs[RCX] = true;
		}
		else if (is_rdx(reg)) {
            		strcpy(var_names[RDX], var);
            		need_to_check_regs[RDX] = true;
		}
		else if (is_rsi(reg)) {
		    	strcpy(var_names[RSI], var);
		    	need_to_check_regs[RSI] = true;
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
	        errno = 0;
	    	if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) == (-1) && errno != 0) {
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
            		perror("wait after execv");
            		exit(1);
        	}
		
		// set first breakpoint (first time)
		errno = 0;
		long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)start_addr, NULL);
		if (data == (-1) && errno != 0) {
	    		perror("first peektext");
	    		exit(1);
		}
		unsigned long data_trap =(data & 0xFFFFFFFFFFFFFF00)|0xCC;
		if(ptrace(PTRACE_POKETEXT, child_pid, (void*)start_addr, (void*)data_trap) == (-1) && errno != 0) {
	    		perror("first poketext");
	    		exit(1);
		}
		
		// continue
		if(ptrace(PTRACE_CONT, child_pid, NULL, NULL) == (-1) && errno != 0) {
	    		perror ("first cont");
	    		exit(1);
		}
		
		// wait for child to reach first breakpoint
        	if (wait(&wait_status) < 0) {
            		perror("first wait");
            		exit(1);
        	}
	
		while (!WIFEXITED(wait_status)) { // while child didn't finished
			// REACHED FIRST BREAKPOINT
			// get regs at the first breakpoint
			if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs_before) == (-1) && errno != 0) {
		    		perror("first getregs");
		    		exit(1);
			}

			// remove first breakpoint
			if(ptrace(PTRACE_POKETEXT, child_pid, (void*)start_addr, (void*)data) == (-1) && errno != 0) {
		    		perror("poketext before removing first breakpoint");
		    		exit(1);
			}
			regs_before.rip -=1;
			if(ptrace(PTRACE_SETREGS, child_pid, 0, &regs_before) == (-1) && errno != 0) {
		    		perror("setregs after removing first breakpoint");
		    		exit(1);
			}

			// set second breakpoint
			data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)end_addr, NULL);
			if (data == (-1) && errno != 0) {
		    		perror("second peektext");
		    		exit(1);
			}
			data_trap = (data & 0xFFFFFFFFFFFFFF00)|0xCC;
			if(ptrace(PTRACE_POKETEXT, child_pid, (void*)end_addr, (void*)data_trap) == (-1) && errno != 0) {
		    		perror("second poketext");
		    		exit(1);
			}

			// continue
			if(ptrace(PTRACE_CONT, child_pid, NULL, NULL) == (-1) && errno != 0) {
		    		perror ("second cont");
		    		exit(1);
			}

			// wait for child to reach second breakpoint
			if (wait(&wait_status)<0) {
		    		perror("second wait");
		    		exit(1);
			}
		
			if (WIFEXITED(wait_status)) break; // child finished before reaching second breakpoint
		
			// REACHED SECOND BREAKPOINT
			// get regs after second breakpoint
			if(ptrace(PTRACE_GETREGS, child_pid, 0, &regs_after) == (-1) && errno != 0) {
				    perror("second getregs");
		    		exit(1);
			}

			// remove second breakpoint
			if(ptrace(PTRACE_POKETEXT, child_pid, (void*)end_addr, (void*)data) == (-1) && errno != 0) {
		    		perror("poketext before removing second breakpoint");
		    		exit(1);
			}
			regs_after.rip -=1;
			if(ptrace(PTRACE_SETREGS, child_pid, 0, &regs_after) == (-1) && errno != 0) {
		    		perror("setregs after removing second breakpoint");
		    		exit(1);
			}
		
			// print changes
			check_changes(regs_before, regs_after);
		
			// set first breakpoint again
			data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)start_addr, NULL);
			if (data == (-1) && errno != 0) {
		    		perror("third peektext");
		    		exit(1);
			}
			data_trap =(data & 0xFFFFFFFFFFFFFF00)|0xCC;
			if(ptrace(PTRACE_POKETEXT, child_pid, (void*)start_addr, (void*)data_trap) == (-1) && errno != 0) {
		    		perror("third poketext");
		    		exit(1);
			}

			// continue
			if(ptrace(PTRACE_CONT, child_pid, NULL, NULL) == (-1) && errno != 0) {
		    		perror ("third cont");
		    		exit(1);
			}

			// wait for child to reach the first breakpoint again
			if (wait(&wait_status)<0) {
		    		perror("third wait");
		    		exit(1);
			}
		}
		
		// if reached here child finished, so debuger (father) finished also
	}
}
