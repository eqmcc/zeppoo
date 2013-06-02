/******************************************************************************/
/* syscalls.c  -- see http://www.zeppoo.ne                                    */
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

void free_syscall(pSyscall *tmp){
	free(tmp);
}

void zeppoo_init_syscalls(void){
/* Syscalls are same as 2.6 and 2.4, but we applied the same method */
	init_syscalls_kgeneric();
}

void init_syscalls_kgeneric(void){
	if(zepversion.arc == 0)
		zepsyscalls.vGetSyscallTable = get_syscalltable_i386;
	else
		zepsyscalls.vGetSyscallTable = get_syscalltable_amd64;

	zepsyscalls.vGetSyscall = get_syscall_kgeneric;
	zepsyscalls.vGetSyscalls = get_syscalls_kgeneric;
	zepsyscalls.vGetSyscallMd5sum = get_syscall_md5sum_kgeneric;
	zepsyscalls.vResolveSyscalls = resolve_syscalls_kgeneric;
}

unsigned long zeppoo_get_syscalltable(void){
	asm("sidt %0" : "=m" (idtr));
#ifdef _DEBUG_
#ifdef _AMD64_
	fprintf(stdout, "IDTR BASE 0x%Lx LIMIT 0x%x\n",(long long)idtr.base,idtr.limit);
#else
	fprintf(stdout, "IDTR BASE 0x%.8lx LIMIT 0x%x\n",(unsigned long)idtr.base, idtr.limit);
#endif
#endif
	zeppoo_read_memory(idtr.base+(2*LENADDR)*0x80, &idt, sizeof(idt));
	zepsyscalls.system_call = (idt.off2 << 16) | idt.off1;

#ifdef _DEBUG_
#ifdef _AMD64_
	printf("idt80: flags = %d flags=%X sel=%X off1=%x off2=%X\n",idt.flags,(unsigned)idt.flags,(unsigned)idt.sel,(unsigned)idt.off1, (unsigned)idt.off2);
	printf("SYSTEM_CALL : 0x%Lx\n", (long long)zepsyscalls.system_call);
#else
	printf("idt80: flags = %d flags=%X sel=%X off1=%x off2=%X\n",idt.flags,(unsigned)idt.flags,(unsigned)idt.sel,(unsigned)idt.off1, (unsigned)idt.off2);
	printf("SYSTEM_CALL : 0x%.8lx\n", (unsigned long)zepsyscalls.system_call);
#endif
#endif
			
	return zepsyscalls.vGetSyscallTable();
}

unsigned long get_syscalltable_i386(void){
	char buffer[256];
	char *p;
		
	zeppoo_read_memory(zepsyscalls.system_call, buffer, 255);
	p = (char *)memmem(buffer,255,"\xff\x14\x85",3);
	zepsyscalls.sys_call_table = *(unsigned long *)(p + 3);
#ifdef _DEBUG_
	printf("Sys Call Table 0x%.8lx\n", (unsigned long)zepsyscalls.sys_call_table);
#endif
	return zepsyscalls.sys_call_table;	
}

unsigned long get_syscalltable_amd64(void){
	char buffer[256];
	char *p;

	if(valmmap && zepversion.kernel < 2.618000){
		zepsyscalls.sys_call_table = zeppoo_walk_krstab("ia32_sys_call_table", ptr, strlen("ia32_sys_call_table") + 2);
	}
	else{
		zeppoo_read_memory(zepsyscalls.system_call, buffer, 255);
		p = (char *)memmem(buffer, 255, "\xff\x14\xc5", 3);
		zepsyscalls.sys_call_table = *(unsigned long *)(p + 3);
#ifdef _AMD64_		
		zepsyscalls.sys_call_table = (zepsyscalls.sys_call_table & 0x00000000ffffffff) | 0xffffffff00000000;
#endif	
	}

#ifdef _DEBUG_
#ifdef _AMD64_
	printf("Sys Call Table 0x%Lx\n", (long long)zepsyscalls.sys_call_table);
#endif
#endif
		
	return zepsyscalls.sys_call_table;
}

unsigned long zeppoo_get_syscall(int num){
	zeppoo_get_syscalltable();
	return zepsyscalls.vGetSyscall(num);
}

unsigned long get_syscall_kgeneric(int num){
	unsigned long addr;
	zeppoo_read_memory(zepsyscalls.sys_call_table + (4*num), &addr, 4);
	return addr;
}

int zeppoo_get_syscalls(pTable *mysyscalls){
	zeppoo_get_syscalltable();
	return zepsyscalls.vGetSyscalls(mysyscalls);
}

int get_syscalls_kgeneric(pTable *mysyscalls){
	int i;
	char key[KEYSIZE];
	pSyscall *tmp_syscall;
	
	for(i=0;i<_NR_syscalls;i++){
		memset(key, '\0', KEYSIZE);
		snprintf(key, KEYSIZE - 1, "%d", i);
		tmp_syscall = (pSyscall *)malloc(sizeof(pSyscall));
		if(tmp_syscall == NULL){
			perror("malloc");
			exit(-1);
		}
		tmp_syscall->pos = i;
		zeppoo_read_memory(zepsyscalls.sys_call_table + (LENADDR*tmp_syscall->pos), &tmp_syscall->addr, LENADDR);
		hash_insert(mysyscalls, key, KEYSIZE, tmp_syscall);
	}
	
	return 0;
}

void zeppoo_get_syscall_md5sum(pSyscall *mysyscall, char *buf, size_t size){
	zepsyscalls.vGetSyscallMd5sum(mysyscall, buf, size);
}

void get_syscall_md5sum_kgeneric(pSyscall *mysyscall, char *buf, size_t size){
	char md5dump[BUFSYSFINGER];
	
	memset(buf, '\0', size);

	if(mysyscall->addr != 0){
		zeppoo_read_memory(mysyscall->addr, md5dump, sizeof(md5dump));
		dumpmd5(md5dump, sizeof(md5dump), buf);
	}
	else
		memcpy(buf, "00000000000000000000000000000000", size);
}

int resolve_syscalls_kgeneric(pTable *mysyscalls, char *file){
	return zepsyscalls.vResolveSyscalls(mysyscalls, file);
}

int zeppoo_resolve_syscalls(pTable *mysyscalls, char *file){
	pItem *tmp;
        pSyscall *tmpsysc;

	tmp = mysyscalls->first;
	while(tmp != NULL){
		tmpsysc = tmp->el->value;
		resolve(file, tmpsysc->addr, tmpsysc->name, sizeof(tmpsysc->name));
		tmp = tmp->next;
	}

	return 0;
}
