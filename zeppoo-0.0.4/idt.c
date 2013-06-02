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

#include "idt.h"

void getIdtMemory(pTable *myidt, char *file){
	zeppoo_get_idt(myidt);
	zeppoo_resolve_idt(myidt, file);
}

void simpleViewIdt(pTable *myidt){
        pItem *tmp;
        pDescIdt *tmpdidt;
#ifdef _AMD64_
	printf("POS\t\t\tMEM\t\t\t\t\t     NAME\n");
#else
	printf("POS\t\tMEM\t\t\t\t\t     NAME\n");
#endif
	
        tmp = myidt->first;
        while(tmp != NULL){ 
                tmpdidt = (pDescIdt *)tmp->el->value;
#ifdef _AMD64_
		printf("%d\t 0x%.16Lx\t %40s\n", tmpdidt->pos, (long long)tmpdidt->stub_addr, tmpdidt->name);
#else
		printf("%d\t 0x%.8lx\t %40s\n", tmpdidt->pos, (unsigned long)tmpdidt->stub_addr, tmpdidt->name);
#endif		 
                tmp = tmp->next;
        }
	
}

void viewIdtMemory(char *file){
	pTable *idtmemory;
	idtmemory = hash_new((void *)free_didt);

	getIdtMemory(idtmemory, file);
	simpleViewIdt(idtmemory);	
	
	hash_delete(idtmemory);
}

void writeIdtMemory(FILE *output, char *file){
	pTable *idtmemory;
	pItem *tmp;
	pDescIdt *tmpdidt;
	
	char md5sum_mem[BUFIDTFINGER];

	idtmemory = hash_new((void *)free_didt);

	getIdtMemory(idtmemory, file);

	printf("\t[+] Begin : Generating IDT Fingerprints\n");
	
	tmp = idtmemory->first;
	while(tmp != NULL){
		tmpdidt = (pDescIdt *)tmp->el->value;
		zeppoo_get_idt_md5sum(tmpdidt, md5sum_mem, sizeof(md5sum_mem));
#ifdef _AMD64_
		fprintf(output,"%d 0x%.16Lx %s %s\n", tmpdidt->pos, (long long)tmpdidt->stub_addr, tmpdidt->name, md5sum_mem);
#else
		fprintf(output,"%d 0x%.8lx %s %s\n", tmpdidt->pos, (unsigned long)tmpdidt->stub_addr, tmpdidt->name, md5sum_mem);
#endif	
		tmp = tmp->next;
	}			

	printf("\t[+] End : Generating IDT Fingerprints\n\n");
	
	hash_delete(idtmemory);
}

void viewHijackIdt(FILE *input, char *file){
	pTable *idtmemory = NULL;
	pTable *hijackidt = NULL;
	pDescIdt *didtmem, *hijackdidt;
	pElement *hdidt;

	char *pos, *stub_addr, *name, *md5sum;
	pDescIdt *tmp_didt;
	
	char key[KEYSIZE];
	char line[256];
	char md5sum_fing[BUFIDTFINGER];
	char md5sum_mem[BUFIDTFINGER];
		
	idtmemory = hash_new((void *)free_didt);
	hijackidt = hash_new((void *)free_didt);
	
	getIdtMemory(idtmemory, file);
	
	fgets(line, 256, input);
	while(strcmp(line,"[END IDT]\n")){
		pos = strtok(line, " ");
		stub_addr = strtok(NULL, " ");
		name = strtok(NULL, " ");
		md5sum = strtok(NULL, " ");	
		
		tmp_didt = (pDescIdt *)malloc(sizeof(pDescIdt));
		if(tmp_didt == NULL)
			zeppoo_fatal("malloc error");
		
		tmp_didt->pos = atoi(pos);
		tmp_didt->stub_addr = strtoull(stub_addr, NULL, 16);
		
		memcpy(tmp_didt->name, name, sizeof(tmp_didt->name));
	
		memset(md5sum_fing, '\0', sizeof(md5sum_fing));
		memcpy(md5sum_fing, md5sum, sizeof(md5sum_fing) - 1);
		md5sum_fing[strlen(md5sum_fing) - 1] = '\0';

		memset(key, '\0', KEYSIZE);
		snprintf(key, KEYSIZE - 1, "%d", tmp_didt->pos);

		hdidt = (pElement *)hash_get(idtmemory, key, KEYSIZE);
		didtmem = (pDescIdt *)hdidt->value;

		zeppoo_get_idt_md5sum(didtmem, md5sum_mem, sizeof(md5sum_mem));
		
		if((tmp_didt->stub_addr != didtmem->stub_addr) || (strcmp(md5sum_fing, md5sum_mem))){           
			hijackdidt = (pDescIdt *)malloc(sizeof(pDescIdt));
			if(hijackdidt == NULL)
				zeppoo_fatal("malloc error");
			
			memcpy(hijackdidt->name, tmp_didt->name, sizeof(hijackdidt->name));
			hijackdidt->pos = tmp_didt->pos;
			hijackdidt->stub_addr = tmp_didt->stub_addr;
						                        
			hash_insert(hijackidt, key, KEYSIZE, hijackdidt);
		
		}
		
		free(tmp_didt);
		fgets(line, 256, input);
	}

	printf("-------------------------------------------------------------------------------\n");
	printf("[+] Begin : IDT\n\n");
	
	if(hijackidt->first != NULL){
		printf("LIST OF HIJACK IDT\n");
		simpleViewIdt(hijackidt);
		printf("\n");
	}
	else
		printf("NO HIJACK IDT\n\n");

	printf("[+] End : IDT\n");
	printf("-------------------------------------------------------------------------------\n\n");
	
	hash_delete(idtmemory);
	hash_delete(hijackidt);
}
