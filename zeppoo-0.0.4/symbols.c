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

#include "symbols.h"

void free_symb(pSymbol *tmp){
	free(tmp);
}

void simpleViewSymbols(pTable *mysymbs){
	pItem *tmp;
	pSymbol *tmpsymb;

	printf("MEM\t\t NAME\n");
	tmp = mysymbs->first;
	while(tmp != NULL){
		tmpsymb = (pSymbol *)tmp->el->value;

		printf("0x%.8lx\t %s\n", (unsigned long)tmpsymb->addr, tmpsymb->name);

		tmp = tmp->next;
	}
}

void writeSymbols(FILE *output, char *file){
	printf("\t[+] Begin : Generating Symbols Fingerprints\n");
	zeppoo_get_symbols(output);
	printf("\t[+] End : Generating Symbols Fingerprints\n\n");
}

void getSymbolsFingerprints(FILE *input, pTable *myallsymbs){
	char line[256];
	char name[64];
	char key[KEYSIZE];
	int i;
	unsigned long addr;
	char *tok;
	pSymbol *tmp_symb;
	
	fgets(line, 256, input);
	while(strcmp(line ,"[END SYMBOLS]\n")){
		for(tok=strtok(line, " "), i=0; tok; tok=strtok(NULL, " "), i++){
			switch(i){
				case 0 : 
					addr = strtoul(tok, NULL, 16);
					break;
					 
				case 1 :
					memset(name, '\0', 64);
					memcpy(name, tok, sizeof(name) - 1);
					name[strlen(tok) - 1] = '\0';
					break;
			}
		}
	
		/* Check JMP instruction, we can't compare opcodes, because
		some symbols have their opcodes changed */
		if(!zeppoo_search_jmp(addr)){
			tmp_symb = (pSymbol *)malloc(sizeof(pSymbol));
			tmp_symb->addr = addr;
			memcpy(tmp_symb->name, name, sizeof(tmp_symb->name) - 1);
			memset(key, '\0', KEYSIZE);
			snprintf(key, KEYSIZE - 1, "%lx", (unsigned long)tmp_symb->addr);
			hash_insert(myallsymbs, key, KEYSIZE, tmp_symb);
		}

		fgets(line, 256, input);
	}
}

void viewHijackSymbols(FILE *input){
	pTable *hijacksymbs;

	hijacksymbs = hash_new((void *)free_symb);

	getSymbolsFingerprints(input, hijacksymbs);
	
	printf("-------------------------------------------------------------------------------\n");
        printf("[+] Begin : Symbols\n\n");

	if(hijacksymbs->first != NULL){
		printf("LIST OF HIJACK SYMBOLS\n");
		simpleViewSymbols(hijacksymbs);
		printf("\n");
	}
	else 
		printf("NO HIJACK SYMBOLS\n\n");
	
	printf("[+] End : Symbols\n");
	printf("-------------------------------------------------------------------------------\n\n");

	hash_delete(hijacksymbs);
}
