/******************************************************************************/
/* idt.c  -- see http://www.zeppoo.net                                        */
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

void free_didt(pDescIdt *tmp){
	free(tmp);
}

void zeppoo_init_idt(void){
	init_idt_kgeneric();
}

void init_idt_kgeneric(void){
	zepidt.vGetIdt = get_idt_kgeneric;
	zepidt.vResolveIdt = resolve_idt_kgeneric;
	zepidt.vGetIdtMd5sum = get_idt_md5sum_kgeneric;
}

unsigned long get_addr_idt(void){
	asm("sidt %0" : "=m" (idtr));
	return idtr.base;        
}

unsigned short get_size_idt(void){
	asm("sidt %0" : "=m" (idtr));
	return idtr.limit;
}

int zeppoo_get_idt(pTable *myidt){
	return zepidt.vGetIdt(myidt);
}

int get_idt_kgeneric(pTable *myidt){
	unsigned long idt_table;
	unsigned short idt_size;
	int i;
	char key[KEYSIZE];
	pDescIdt *tmpdidt;
	
	idt_table = get_addr_idt();
	idt_size = get_size_idt();

#ifdef _DEBUG_
	printf("IDT TABLE : 0x%.8lx , SIZE : %d\n", (unsigned long)idt_table, idt_size);
#endif
	memset(key, '\0', KEYSIZE);
	
	for(i = 0;i < (idt_size + 1)/(LENADDR*2); i++){
		tmpdidt = (pDescIdt *)malloc(sizeof(pDescIdt));
		if(tmpdidt == NULL){
			perror("malloc :");
			exit(-1);
		}
		zeppoo_read_memory(idt_table+LENADDR*2*i, &idt, sizeof(idt));
		tmpdidt->pos = i;
#ifdef _AMD64_
		tmpdidt->stub_addr = (long long)(idt.off2 << 16) + idt.off1;
#else
		tmpdidt->stub_addr = (unsigned long)(idt.off2 << 16) + idt.off1;
#endif

		snprintf(key, KEYSIZE - 1, "%d", tmpdidt->pos);
		hash_insert(myidt, key, KEYSIZE, tmpdidt);
		memset(key, '\0', KEYSIZE);
	}
	
	return 0;
}

int zeppoo_resolve_idt(pTable *myidt, char *file){
	return zepidt.vResolveIdt(myidt, file);
}

int resolve_idt_kgeneric(pTable *myidt, char *file){
	pItem *tmp;
        pDescIdt *tmpdidt;

	tmp = myidt->first;
	while(tmp != NULL){
		tmpdidt = tmp->el->value;
		resolve(file, tmpdidt->stub_addr, tmpdidt->name, sizeof(tmpdidt->name));
		tmp = tmp->next;
	}

	return 0;
}

void zeppoo_get_idt_md5sum(pDescIdt *myidt, char *buf, size_t size){
	zepidt.vGetIdtMd5sum(myidt, buf, size);
}

void get_idt_md5sum_kgeneric(pDescIdt *myidt, char *buf, size_t size){
	char md5dump[BUFIDTFINGER];
	
	memset(buf, '\0', size);
	if(myidt->stub_addr != 0){
		zeppoo_read_memory(myidt->stub_addr, md5dump, sizeof(md5dump));
		dumpmd5(md5dump, sizeof(md5dump), buf);
	}
	else
		memcpy(buf, "00000000000000000000000000000000", size);
}
