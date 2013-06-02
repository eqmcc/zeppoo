/******************************************************************************/
/* syscalls.c  -- see http://www.zeppoo.net                                   */
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

#include "syscalls.h"

void getSyscallsMemory(pTable *mysyscalls, char *file){
	zeppoo_get_syscalls(mysyscalls);
	zeppoo_resolve_syscalls(mysyscalls, file);
}

void simpleViewSyscalls(pTable *mysyscalls){
        pItem *tmp;
        pSyscall *tmpsysc;
#ifdef _AMD64_
	printf("POS\t\t\tMEM\t\t\t\t\t     NAME\n");
#else
        printf("POS\t\tMEM\t\t\t\t\t     NAME\n");
#endif
	
        tmp = mysyscalls->first;
        while(tmp != NULL){ 
		tmpsysc = (pSyscall *)tmp->el->value;
#ifdef _AMD64_            
		printf("%d\t 0x%.16Lx\t %40s\n", tmpsysc->pos, (long long)tmpsysc->addr, tmpsysc->name);
#else
		printf("%d\t 0x%.8lx\t %40s\n", tmpsysc->pos, (unsigned long)tmpsysc->addr, tmpsysc->name);
#endif		 
                tmp = tmp->next;
		
        }
}

void viewSyscallsMemory(char *file){
	pTable *syscallsmemory;
	syscallsmemory = hash_new((void *)free_syscall);

	getSyscallsMemory(syscallsmemory, file);
	simpleViewSyscalls(syscallsmemory);	
	
	hash_delete(syscallsmemory);
}

void writeSyscallsMemory(FILE *output, char *file){
	pTable *syscallsmemory;
	pItem *tmp;
	pSyscall *tmpsysc;
					      
	char md5sum_mem[BUFSYSFINGER];

	syscallsmemory = hash_new((void *)free_syscall);

	getSyscallsMemory(syscallsmemory, file);	

	printf("\t[+] Begin : Generating Syscalls Fingerprints\n");
	
	tmp = syscallsmemory->first;
	while(tmp != NULL){
		tmpsysc = (pSyscall *)tmp->el->value;
		zeppoo_get_syscall_md5sum(tmpsysc, md5sum_mem, sizeof(md5sum_mem));
#ifdef _AMD64_
		fprintf(output,"%d 0x%.16Lx %s %s\n", tmpsysc->pos, (long long)tmpsysc->addr, tmpsysc->name, md5sum_mem);
#else
		fprintf(output,"%d 0x%.8lx %s %s\n", tmpsysc->pos, (unsigned long)tmpsysc->addr, tmpsysc->name, md5sum_mem);
#endif		
		tmp = tmp->next;
	}					

	printf("\t[+] End : Generating Syscalls Fingerprints\n\n");
	
	hash_delete(syscallsmemory);
}

void viewHijackSyscalls(FILE *input, char *file){
	pTable *syscallsmemory = NULL;
	pTable *hijacksyscalls = NULL;
	pSyscall *syscmem, *hijacksysc;
	pElement *hsyscall;

	char *pos, *addr, *name, *md5sum;
	pSyscall *tmp_syscall;
			
	char key[KEYSIZE];
	char line[256];
	char md5sum_fing[BUFSYSFINGER];
	char md5sum_mem[BUFSYSFINGER];

	syscallsmemory = hash_new((void *)free_syscall);
	hijacksyscalls = hash_new((void *)free_syscall);
	
	getSyscallsMemory(syscallsmemory, file);
	
	fgets(line, 256, input);
	while(strcmp(line,"[END SYSCALLS]\n")){
		pos = strtok(line, " ");
		addr = strtok(NULL, " ");
		name = strtok(NULL, " ");
		md5sum = strtok(NULL, " ");
		
		tmp_syscall = (pSyscall *)malloc(sizeof(pSyscall));
		if(tmp_syscall == NULL)
			zeppoo_fatal("malloc error");
		
		tmp_syscall->pos = atoi(pos);
		tmp_syscall->addr = strtoull(addr, NULL, 16);

		memcpy(tmp_syscall->name, name, sizeof(tmp_syscall->name) - 1);
		
		memset(md5sum_fing, '\0', sizeof(md5sum_fing));
		memcpy(md5sum_fing, md5sum, sizeof(md5sum_fing) - 1);
		md5sum_fing[strlen(md5sum_fing) - 1] = '\0';


		memset(key, '\0', KEYSIZE);
		snprintf(key, KEYSIZE - 1, "%d", tmp_syscall->pos);
		
		hsyscall = (pElement *)hash_get(syscallsmemory, key, KEYSIZE);
		syscmem = (pSyscall *)hsyscall->value;
	
		zeppoo_get_syscall_md5sum(syscmem, md5sum_mem, sizeof(md5sum_mem));
		if((tmp_syscall->addr != syscmem->addr) || strcmp(md5sum_fing, md5sum_mem)){
			hijacksysc = (pSyscall *)malloc(sizeof(pSyscall));
			if(hijacksysc == NULL)
				zeppoo_fatal("malloc error");
		
			memset(hijacksysc->name, '\0', sizeof(hijacksysc->name));
			memcpy(hijacksysc->name, tmp_syscall->name, sizeof(hijacksysc->name));
			hijacksysc->pos = tmp_syscall->pos;
			hijacksysc->addr = tmp_syscall->addr;
										                        
			hash_insert(hijacksyscalls, key, KEYSIZE, hijacksysc);
		}

		free(tmp_syscall);
		fgets(line, 256, input);
	}
	
	printf("-------------------------------------------------------------------------------\n");
	printf("[+] Begin : Syscall\n\n");
	
	if(hijacksyscalls->first != NULL){
		printf("LIST OF HIJACK SYSCALLS\n");
		simpleViewSyscalls(hijacksyscalls);
		printf("\n");
	}
	else
		printf("NO HIJACK SYSCALL\n\n");

	printf("[+] End : Syscall\n");
	printf("-------------------------------------------------------------------------------\n\n");
	
	hash_delete(syscallsmemory);
	hash_delete(hijacksyscalls);
}
