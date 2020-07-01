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
int print_order[NUM_REGS];
char to_sort[NUM_REGS][2][BUF_SIZE];
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
    char tempBuf[BUF_SIZE];
    bool need_to_print[NUM_REGS];
    for (int i=0; i<NUM_REGS; i++) need_to_print[i] = false;

    // check changes
    if (need_to_check_regs[RAX] && regs_before.rax != regs_after.rax) {
	need_to_print[RAX] = true;
        strcpy(toPrint[RAX],"PRF:: ");
        strcat(toPrint[RAX], var_names[RAX]);
        strcat(toPrint[RAX], ": ");
        sprintf(tempBuf, "%lld", regs_before.rax);
        strcat(toPrint[RAX], tempBuf);
        strcat(toPrint[RAX], "->");
        sprintf(tempBuf, "%lld", regs_after.rax);
        strcat(toPrint[RAX], tempBuf);
    }
    if (need_to_check_regs[EAX] && (regs_before.rax & 0xffffffff) != (regs_after.rax & 0xffffffff)) {
	need_to_print[EAX] = true;
        strcpy(toPrint[EAX],"PRF:: ");
        strcat(toPrint[EAX], var_names[EAX]);
        strcat(toPrint[EAX], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rax & 0xffffffff));
        strcat(toPrint[EAX], tempBuf);
        strcat(toPrint[EAX], "->");
        sprintf(tempBuf, "%lld", (regs_after.rax & 0xffffffff));
        strcat(toPrint[EAX], tempBuf);
        
    }
    if (need_to_check_regs[AX] && (regs_before.rax & 0xffff) != (regs_after.rax & 0xffff)) {
	need_to_print[AX] = true;
        strcpy(toPrint[AX],"PRF:: ");
        strcat(toPrint[AX], var_names[AX]);
        strcat(toPrint[AX], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rax & 0xffff));
        strcat(toPrint[AX], tempBuf);
        strcat(toPrint[AX], "->");
        sprintf(tempBuf, "%lld", (regs_after.rax & 0xffff));
        strcat(toPrint[AX], tempBuf);
        
    }
    if (need_to_check_regs[AH] && (regs_before.rax & 0xff00) != (regs_after.rax & 0xff00)) {
	need_to_print[AH] = true;
        strcpy(toPrint[AH],"PRF:: ");
        strcat(toPrint[AH], var_names[AH]);
        strcat(toPrint[AH], ": ");
        sprintf(tempBuf, "%lld", ((regs_before.rax >> 8) & 0xff));
        strcat(toPrint[AH], tempBuf);
        strcat(toPrint[AH], "->");
        sprintf(tempBuf, "%lld", ((regs_after.rax >> 8) & 0xff));
        strcat(toPrint[AH], tempBuf);
        
    }
    if (need_to_check_regs[AL] && (regs_before.rax & 0xff) != (regs_after.rax & 0xff)) {
	need_to_print[AL] = true;
        strcpy(toPrint[AL],"PRF:: ");
        strcat(toPrint[AL], var_names[AL]);
        strcat(toPrint[AL], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rax & 0xff));
        strcat(toPrint[AL], tempBuf);
        strcat(toPrint[AL], "->");
        sprintf(tempBuf, "%lld", (regs_after.rax & 0xff));
        strcat(toPrint[AL], tempBuf);
        
    }
    if (need_to_check_regs[RBX] && regs_before.rbx != regs_after.rbx) {
	need_to_print[RBX] = true;
        strcpy(toPrint[RBX],"PRF:: ");
        strcat(toPrint[RBX], var_names[RBX]);
        strcat(toPrint[RBX], ": ");
        sprintf(tempBuf, "%lld", regs_before.rbx);
        strcat(toPrint[RBX], tempBuf);
        strcat(toPrint[RBX], "->");
        sprintf(tempBuf, "%lld", regs_after.rbx);
        strcat(toPrint[RBX], tempBuf);
        
    }
    if (need_to_check_regs[EBX] && (regs_before.rbx & 0xffffffff) != (regs_after.rbx & 0xffffffff)) {
	need_to_print[EBX] = true;
        strcpy(toPrint[EBX],"PRF:: ");
        strcat(toPrint[EBX], var_names[EBX]);
        strcat(toPrint[EBX], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rbx & 0xffffffff));
        strcat(toPrint[EBX], tempBuf);
        strcat(toPrint[EBX], "->");
        sprintf(tempBuf, "%lld", (regs_after.rbx & 0xffffffff));
        strcat(toPrint[EBX], tempBuf);
        
    }
    if (need_to_check_regs[BX] && (regs_before.rbx & 0xffff) != (regs_after.rbx & 0xffff)) {
	need_to_print[BX] = true;
        strcpy(toPrint[BX],"PRF:: ");
        strcat(toPrint[BX], var_names[BX]);
        strcat(toPrint[BX], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rbx & 0xffff));
        strcat(toPrint[BX], tempBuf);
        strcat(toPrint[BX], "->");
        sprintf(tempBuf, "%lld", (regs_after.rbx & 0xffff));
        strcat(toPrint[BX], tempBuf);
    }
    if (need_to_check_regs[BH] && (regs_before.rbx & 0xff00) != (regs_after.rbx & 0xff00)) {
	need_to_print[BH] = true;
        strcpy(toPrint[BH],"PRF:: ");
        strcat(toPrint[BH], var_names[BH]);
        strcat(toPrint[BH], ": ");
        sprintf(tempBuf, "%lld", ((regs_before.rbx >> 8) & 0xff));
        strcat(toPrint[BH], tempBuf);
        strcat(toPrint[BH], "->");
        sprintf(tempBuf, "%lld", ((regs_after.rbx >> 8) & 0xff));
        strcat(toPrint[BH], tempBuf);
        
    }
    if (need_to_check_regs[BL] && (regs_before.rbx & 0xff) != (regs_after.rbx & 0xff)) {
	need_to_print[BL] = true;
        strcpy(toPrint[BL],"PRF:: ");
        strcat(toPrint[BL], var_names[BL]);
        strcat(toPrint[BL], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rbx & 0xff));
        strcat(toPrint[BL], tempBuf);
        strcat(toPrint[BL], "->");
        sprintf(tempBuf, "%lld", (regs_after.rbx & 0xff));
        strcat(toPrint[BL], tempBuf);
        
    }
    if (need_to_check_regs[RCX] && regs_before.rcx != regs_after.rcx) {
	need_to_print[RCX] = true;
        strcpy(toPrint[RCX],"PRF:: ");
        strcat(toPrint[RCX], var_names[RCX]);
        strcat(toPrint[RCX], ": ");
        sprintf(tempBuf, "%lld", regs_before.rcx);
        strcat(toPrint[RCX], tempBuf);
        strcat(toPrint[RCX], "->");
        sprintf(tempBuf, "%lld", regs_after.rcx);
        strcat(toPrint[RCX], tempBuf);
        
    }
    if (need_to_check_regs[ECX] && (regs_before.rcx & 0xffffffff) != (regs_after.rcx & 0xffffffff)) {
	need_to_print[ECX] = true;
        strcpy(toPrint[ECX],"PRF:: ");
        strcat(toPrint[ECX], var_names[ECX]);
        strcat(toPrint[ECX], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rcx & 0xffffffff));
        strcat(toPrint[ECX], tempBuf);
        strcat(toPrint[ECX], "->");
        sprintf(tempBuf, "%lld", (regs_after.rcx & 0xffffffff));
        strcat(toPrint[ECX], tempBuf);
        
    }
    if (need_to_check_regs[CX] && (regs_before.rcx & 0xffff) != (regs_after.rcx & 0xffff)) {
	need_to_print[CX] = true;
        strcpy(toPrint[CX],"PRF:: ");
        strcat(toPrint[CX], var_names[CX]);
        strcat(toPrint[CX], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rcx & 0xffff));
        strcat(toPrint[CX], tempBuf);
        strcat(toPrint[CX], "->");
        sprintf(tempBuf, "%lld", (regs_after.rcx & 0xffff));
        strcat(toPrint[CX], tempBuf);
        
    }
    if (need_to_check_regs[CH] && (regs_before.rcx & 0xff00) != (regs_after.rcx & 0xff00)) {
	need_to_print[CH] = true;
        strcpy(toPrint[CH],"PRF:: ");
        strcat(toPrint[CH], var_names[CH]);
        strcat(toPrint[CH], ": ");
        sprintf(tempBuf, "%lld", ((regs_before.rcx >> 8) & 0xff));
        strcat(toPrint[CH], tempBuf);
        strcat(toPrint[CH], "->");
        sprintf(tempBuf, "%lld", ((regs_after.rcx >> 8) & 0xff));
        strcat(toPrint[CH], tempBuf);
        
    }
    if (need_to_check_regs[CL] && (regs_before.rcx & 0xff) != (regs_after.rcx & 0xff)) {
	need_to_print[CL] = true;
        strcpy(toPrint[CL],"PRF:: ");
        strcat(toPrint[CL], var_names[CL]);
        strcat(toPrint[CL], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rcx & 0xff));
        strcat(toPrint[CL], tempBuf);
        strcat(toPrint[CL], "->");
        sprintf(tempBuf, "%lld", (regs_after.rcx & 0xff));
        strcat(toPrint[CL], tempBuf);
        
    }
    if (need_to_check_regs[RDX] && regs_before.rdx != regs_after.rdx) {
	need_to_print[RDX] = true;
        strcpy(toPrint[RDX],"PRF:: ");
        strcat(toPrint[RDX], var_names[RDX]);
        strcat(toPrint[RDX], ": ");
        sprintf(tempBuf, "%lld", regs_before.rdx);
        strcat(toPrint[RDX], tempBuf);
        strcat(toPrint[RDX], "->");
        sprintf(tempBuf, "%lld", regs_after.rdx);
        strcat(toPrint[RDX], tempBuf);
        
    }
    if (need_to_check_regs[EDX] && (regs_before.rdx & 0xffffffff) != (regs_after.rdx & 0xffffffff)) {
	need_to_print[EDX] = true;
        strcpy(toPrint[EDX],"PRF:: ");
        strcat(toPrint[EDX], var_names[EDX]);
        strcat(toPrint[EDX], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rdx & 0xffffffff));
        strcat(toPrint[EDX], tempBuf);
        strcat(toPrint[EDX], "->");
        sprintf(tempBuf, "%lld", (regs_after.rdx & 0xffffffff));
        strcat(toPrint[EDX], tempBuf);
        
    }
    if (need_to_check_regs[DX] && (regs_before.rdx & 0xffff) != (regs_after.rdx & 0xffff)) {
	need_to_print[DX] = true;
        strcpy(toPrint[DX],"PRF:: ");
        strcat(toPrint[DX], var_names[DX]);
        strcat(toPrint[DX], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rdx & 0xffff));
        strcat(toPrint[DX], tempBuf);
        strcat(toPrint[DX], "->");
        sprintf(tempBuf, "%lld", (regs_after.rdx & 0xffff));
        strcat(toPrint[DX], tempBuf);
        
    }
    if (need_to_check_regs[DH] && (regs_before.rdx & 0xff00) != (regs_after.rdx & 0xff00)) {
	need_to_print[DH] = true;
        strcpy(toPrint[DH],"PRF:: ");
        strcat(toPrint[DH], var_names[DH]);
        strcat(toPrint[DH], ": ");
        sprintf(tempBuf, "%lld", ((regs_before.rdx >> 8) & 0xff));
        strcat(toPrint[DH], tempBuf);
        strcat(toPrint[DH], "->");
        sprintf(tempBuf, "%lld", ((regs_after.rdx >> 8) & 0xff));
        strcat(toPrint[DH], tempBuf);
        
    }
    if (need_to_check_regs[DL] && (regs_before.rdx & 0xff) != (regs_after.rdx & 0xff)) {
	need_to_print[DL] = true;
        strcpy(toPrint[DL],"PRF:: ");
        strcat(toPrint[DL], var_names[DL]);
        strcat(toPrint[DL], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rdx & 0xff));
        strcat(toPrint[DL], tempBuf);
        strcat(toPrint[DL], "->");
        sprintf(tempBuf, "%lld", (regs_after.rdx & 0xff));
        strcat(toPrint[DL], tempBuf);
        
    }
    if (need_to_check_regs[RSI] && regs_before.rsi != regs_after.rsi) {
	need_to_print[RSI] = true;
        strcpy(toPrint[RSI],"PRF:: ");
        strcat(toPrint[RSI], var_names[RSI]);
        strcat(toPrint[RSI], ": ");
        sprintf(tempBuf, "%lld", regs_before.rsi);
        strcat(toPrint[RSI], tempBuf);
        strcat(toPrint[RSI], "->");
        sprintf(tempBuf, "%lld", regs_after.rsi);
        strcat(toPrint[RSI], tempBuf);
        
    }
    if (need_to_check_regs[ESI] && (regs_before.rsi & 0xffffffff) != (regs_after.rsi & 0xffffffff)) {
	need_to_print[ESI] = true;
        strcpy(toPrint[ESI],"PRF:: ");
        strcat(toPrint[ESI], var_names[ESI]);
        strcat(toPrint[ESI], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rsi & 0xffffffff));
        strcat(toPrint[ESI], tempBuf);
        strcat(toPrint[ESI], "->");
        sprintf(tempBuf, "%lld", (regs_after.rsi & 0xffffffff));
        strcat(toPrint[ESI], tempBuf);
        
    }
    if (need_to_check_regs[SI] && (regs_before.rsi & 0xffff) != (regs_after.rsi & 0xffff)) {
	need_to_print[SI] = true;
        strcpy(toPrint[SI],"PRF:: ");
        strcat(toPrint[SI], var_names[SI]);
        strcat(toPrint[SI], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rsi & 0xffff));
        strcat(toPrint[SI], tempBuf);
        strcat(toPrint[SI], "->");
        sprintf(tempBuf, "%lld", (regs_after.rsi & 0xffff));
        strcat(toPrint[SI], tempBuf);
        
    }
    if (need_to_check_regs[SIL] && (regs_before.rsi & 0xff) != (regs_after.rsi & 0xff)) {
	need_to_print[SIL] = true;
        strcpy(toPrint[SIL],"PRF:: ");
        strcat(toPrint[SIL], var_names[SIL]);
        strcat(toPrint[SIL], ": ");
        sprintf(tempBuf, "%lld", (regs_before.rsi & 0xff));
        strcat(toPrint[SIL], tempBuf);
        strcat(toPrint[SIL], "->");
        sprintf(tempBuf, "%lld", (regs_after.rsi & 0xff));
        strcat(toPrint[SIL], tempBuf);
        
    }

    // print
    for (int j=0; j<NUM_REGS; j++) {
	if (need_to_print[(int)to_sort[j][1]]) {
        	printf("%s\n", toPrint[(int)to_sort[j][1]]);
	}
    }
}

int main (int argc, char* argv[]) {

	unsigned long long start_addr = strtol(argv[1], NULL, 16);
	unsigned long long end_addr = strtol(argv[2], NULL, 16);
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

	// sort vars
	for (int i=0; i<NUM_REGS; i++) {
		to_sort[i][1][0] = i;
		if (need_to_check_regs[i]) {
			strcpy(to_sort[i][0], var_names[i]);
		}
	}
	// sort
    	int swapped=1;
    	while(swapped > 0) {
        	swapped=0;
        	for (int i=1; i<NUM_REGS; i++) {
            		if (strcmp(to_sort[i-1][0], to_sort[i][0]) > 0) {
                		char temp[BUF_SIZE];
				char temp_num;
                		strcpy(temp, to_sort[i][0]);
                		strcpy(to_sort[i][0], to_sort[i-1][0]);
                		strcpy(to_sort[i-1][0], temp);
				temp_num = to_sort[i][1][0];
				to_sort[i][1][0] = to_sort[i-1][1][0];
				to_sort[i-1][1][0] = temp_num;
                		swapped=1;
        	    	}
        	}
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

	    	execv(argv[3], argv+3);

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
		long long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)start_addr, NULL);
		if (data == (-1) && errno != 0) {
		    exit(1);
		}
		unsigned long long data_trap =(data & 0xFFFFFFFFFFFFFF00)|0xCC;
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
