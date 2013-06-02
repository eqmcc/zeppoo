/******************************************************************************/
/* symbols.c  -- see http://www.zeppoo.net                                    */
/*                                                                            */
/* The project zeppoo is (C) 2006 : contact@zeppoo.net                        */
/* This program is free software;                                             */
/* you can redistribute it and/or modify it under the terms of the GNU        */
/* General Public License as published by the Free Software Foundation;       */
/* Version 2. This guarantees your right to use, modify, and                  */
/* redistribute this software under certain conditions.                       */
/*                                                                            */
/* Source is provided to this software because we believe users have a        */
/* right to know exactly what a program is going to do before they run        */
/* it.                                                                        */
/*                                                                            */
/* This program is distributed in the hope that it will be                    */
/* useful, but WITHOUT ANY WARRANTY; without even the implied                 */
/* warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR                    */
/* PURPOSE. See the GNU General Public License for more details (             */
/* http://www.gnu.org/copyleft/gpl.html ).                                    */
/*                                                                            */
/******************************************************************************/

#include "zeppoo.h"

pKernelSym inittask_sym[] = { 
        { "proc_root_readdir", "proc_pid_readdir", 1, 1, 0xe9, 0, 0, 0 },
	{ "proc_pid_readdir", "get_tgid_list", 2, 1, 0xe8, 0, 0, 0 },
	{ "get_tgid_list", "init_task", 3, 1, 0x81, 0, 0, 0 },
	{ NULL, NULL, 0, 0, 0, 0, 0, 0 }
};

void zeppoo_init_symb(void){
	if(zepversion.kernel >= KERNEL26)
		init_symb_k26();
	else
		init_symb_k24();
}

void init_symb_k26(void){
	zepsymb.vFindInitTask = find_init_task_k26;
	zepsymb.vLookupRoot = lookup_root_k26;

	if((zepversion.kernel >= 2.615000 && zepversion.kernel < 2.615999) || (zepversion.kernel >= 2.617000))
		zepsymb.proc_root_operations = 36;
        else
		zepsymb.proc_root_operations = 32;

	zepsymb.proc_root_readdir = 24;
	
	if(zepversion.kernel >= 2.617000 && zepversion.kernel < 2.618000)
		zepsymb.get_tgid_list = 0x3d;
	else
		zepsymb.get_tgid_list = 0x81;
}

void init_symb_k24(void){


}

unsigned long zeppoo_lookup_root(){
        unsigned long proc_root;
	proc_root = zepsymb.vLookupRoot();
	return proc_root;
}

/* Thanks to c0de @ UNF <c0de@uskf.com> for lookup_root */
/* Get @ lookup_root */
unsigned long lookup_root_k26(){
	int i;
	unsigned char buffer[4096];
	unsigned char proc_root[32];
  	unsigned long t = zepglob.kernel_start;
    
	while (t < zepglob.kernel_end) {
		zeppoo_read_memory(t, buffer, 4096);
      		for (i = 0; i < 4096; i++) {
			if(buffer[i] == PROC_ROOT_INO  && buffer[i+2] == PROC_ROOT_NOTHING && buffer[i+4] == PROC_ROOT_NAMELEN && buffer[i+12] == PROC_ROOT_MODE) {
					zeppoo_read_memory(t+i, proc_root, sizeof(proc_root));
				
					if(proc_root[16] == 0 && proc_root[20] == 0)
						return t+i;
			}
		}
		t+=4096;
	}
	return 0;
}

unsigned long zeppoo_find_init_task(void){
	unsigned long init_task;
	init_task = zepsymb.vFindInitTask();
	return init_task;
}

/* Get @ init_task */
/* proc_root => proc_root_operations => proc_root_readdir => init_task */
unsigned long find_init_task_k26(void){
	unsigned long proc_root, proc_root_operations, proc_root_readdir, init_task;

	if(valmmap){
		init_task = zeppoo_walk_krstab("init_task", ptr, strlen ("init_task") + 2);
		if(zeppoo_valid_addr(init_task)){
			printf("[-] Unable to resolve init_task !!\n");
			exit(-1);
		}
#ifdef _DEBUG_
		printf("[+] INIT_TASK 0x%.8lx\n", (unsigned long)init_task);
#endif
	}
	else{					
		proc_root = zeppoo_lookup_root();
		if(zeppoo_valid_addr(proc_root)){
			printf("[-] Unable to resolve proc_root !!\n");
			exit(-1);
		}
#ifdef _DEBUG_	
		printf("[+] proc_root @ 0x%.8lx\n", (unsigned long)proc_root);
#endif
		zeppoo_read_memory(proc_root+zepsymb.proc_root_operations, &proc_root_operations, 4);

		if(zeppoo_valid_addr(proc_root_operations)){
			printf("[-] Unable to resolve proc_root_operations\n");
			exit(-1);
		}
#ifdef _DEBUG_
		printf("[+] proc_root_operations @ 0x%.8lx\n",(unsigned long)proc_root_operations);
#endif

		zeppoo_read_memory(proc_root_operations+zepsymb.proc_root_readdir, &proc_root_readdir, 4);

		if(zeppoo_valid_addr(proc_root_readdir)){
			printf("[-] Unable to resolve proc_root_readdir\n");
			exit(-1);
		}
#ifdef _DEBUG_
		printf("[+] proc_root_readdir @ 0x%.8lx\n",(unsigned long)proc_root_readdir);
#endif	

		inittask_sym[0].start = proc_root_readdir;
		inittask_sym[2].prefix = zepsymb.get_tgid_list;
		init_task = zeppoo_walk_tree(inittask_sym);
		
		if(zeppoo_valid_addr(init_task)){
			printf("[-] Unable to resolve init_task\n");
			exit(-1);
		}
	}

	return init_task;
}

int struc_size(pKernelSym *ksym) {
	int i;
	for (i = 0; ksym[i].caller; i++);
        return i;
}

unsigned long zeppoo_walk_tree(pKernelSym *ksym){
	int i, j, nb, ok, size;
	unsigned char buf[8192];
	unsigned long addr, t;
	pKernelSym *q;
	signed long offset;
	
	ok = 0;
	q = ksym;
	size = struc_size(ksym);
	t = q->start;

	for (i = 0; i < size; i++) {
		zeppoo_read_memory(t, buf, 8192);
		nb = 1;
		ok = 0;
		
		for (j = 0; j < 8192 && !ok; j++) {
			if (buf[j] == q->prefix){
				switch(q->prefix) {
					case 0xe9 : 
					case 0xe8 :
					if(buf[j+1] == q->prefix){
						j++;
					}
					zeppoo_read_memory(t + j + 1, &offset, sizeof(offset));
					addr = offset + 5 + t + j; 
					if(!zeppoo_valid_addr(addr)) {
						q->address = addr;
						q->resolved = 1;
#ifdef _DEBUG_
						printf("\t[+] 0x%x => %s 0x%.8lx\n", q->prefix, q->callee, (unsigned long)q->address);
#endif	
						if(q->r == 1){
							t = addr;
							ok = 1;
						}
						q++;
					}
					break;
					
					case 0x81 :
					case 0x3d :
					if(buf[j+1] == q->prefix){
						j++;
					}

					if(q->prefix == 0x81)
						zeppoo_read_memory(t + j + 2, &addr, sizeof(addr));
					else
						zeppoo_read_memory(t + j + 1, &addr, sizeof(addr));
					if(!zeppoo_valid_addr(addr)) {
						q->address = addr;
						q->resolved = 1;
#ifdef _DEBUG_
						printf("\t[+] 0x%x => %s 0x%.8lx\n", q->prefix, q->callee, (unsigned long)q->address);
#endif
						if(q->r == 1){
							t = addr;
							ok = 1;
						}
						q++;
					}
					break;

					case 0xc7 :
						zeppoo_read_memory(t + j + 6, &addr, sizeof(addr));
						if(!zeppoo_valid_addr(addr)) {
							q->address = addr;
							q->resolved = 1;
#ifdef _DEBUG_
							printf("\t[+] 0x%x => %s 0x%.8lx\n", q->prefix, q->callee, (unsigned long)q->address);
#endif
							if(q->r == 1){
								t = addr;
								ok = 1;
							}
							q++;
						}
						break;
				}
			}
		}
	}
	return addr;
}

/* Based on phalanx rootkit :) */
unsigned long zeppoo_walk_krstab(char *symbol, void *base, int size){
	char srch[512];
	char tab[] = { '\0', '\xff' };
	unsigned long kstrtab, x, i;
	int j;
	x = i = j = 0;
		
	memcpy (srch + 1, symbol, size);
	srch[size] = '\0';

	while(j <= 1){
	srch[0] = tab[j];
	while(zeppoo_valid_addr(kstrtab)){
		for (x = 0, i = 0; x < 20 * 1024 * 1024; x++, i++){
#ifdef _DEBUG_
			if (i % 500000 == 0)
				write (1, "?", 1);
			else if (i == 4000001){
  		 		write (1, "\b\b\b\b\b\b\b\b        \b\b\b\b\b\b\b\b", 24);
				i = 0;
			}
#endif
      			if(memcmp ((unsigned char *) (base + x), srch, size) == 0){
		  		kstrtab = zepglob.kernel_start + x + 1;
				break;
			}
   		}
		j++;
		srch[0] = tab[j];
	}

#ifdef _DEBUG_
#ifdef _AMD64_
	printf("kstrtab = 0x%Lx\n", (long long)kstrtab);
#else
	printf("kstrtab = 0x%.8lx\n", (unsigned long)kstrtab);
#endif
#endif

	if(!zeppoo_valid_addr(kstrtab)){
	  	for (x = 0, i = 0; x < 20 * 1024 * 1024; x++, i++){
#ifdef _DEBUG_
		if (i % 500000 == 0)
				write (1, "?", 1);
      	        else if(i == 4000001){
	  		write (1, "\b\b\b\b\b\b\b\b        \b\b\b\b\b\b\b\b", 24);
	  		i = 0;
		}
#endif
		if (*(unsigned long *) (base + x) == kstrtab)
			return *(unsigned long *) (base + x - LENADDR);
    		}
	}
	kstrtab = 0;
	}
	return 0;
}

void zeppoo_resolve_listsymbols(pKernelSyms *listKernelSyms){
	int i = 0;
	
	while(listKernelSyms[i].ksym != NULL){
		zeppoo_walk_tree(listKernelSyms[i].ksym);
		i++;
	}
}

int zeppoo_get_symbols(FILE *output){
	FILE *input;
	char line[80];
	char *tok;
	int i;
	unsigned long addr;
	char name[64];

	if((input = fopen("/proc/kallsyms", "r")) == NULL){
		perror("fopen :");
		return -1;
	}

	while(fgets(line, sizeof(line) - 1, input) != NULL){
		for(tok = strtok(line, " "), i = 0; tok; tok = strtok(NULL, " "), i++){
			switch(i){
				case 0 :
					addr = strtoul(tok, NULL, 16);
					break;
				case 2 :
					memset(name, '\0', 64);
					memcpy(name, tok, sizeof(name) - 1);
					if(name[strlen(name) - 1] == '\n')
						name[strlen(name) - 1] = '\0';
			}
		}
		
		if(!zeppoo_valid_addr(addr)){
			fprintf(output, "0x%.8lx %s\n", (unsigned long)addr, name);
		}
	}
	return 0;
}
