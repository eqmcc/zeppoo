/******************************************************************************/
/* zeppoo.c  -- see http://www.zeppoo.net                                     */
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

void zeppoo_init(void){
	if(zepversion.arc == 0){
		zepglob.kernel_start = KERNEL_I386_START;
		zepglob.kernel_end = KERNEL_I386_END;
		zepglob.page_offset = PAGE_I386_OFFSET;
		zepglob.page_max = PAGE_I386_MAX;
	}
	else if(zepversion.arc == 1){
#ifdef _AMD64_            
		zepglob.kernel_start = KERNEL_AMD64_START;
		zepglob.kernel_end = KERNEL_AMD64_END;
		zepglob.page_offset = PAGE_AMD64_OFFSET;
		zepglob.page_max = PAGE_AMD64_MAX;
#endif
	}

#ifdef _DEBUG_
#ifdef _AMD64_
	printf("KERNEL_START 0x%Lx\n", (long long)zepglob.kernel_start);
	printf("KERNEL_END 0x%Lx\n", (long long)zepglob.kernel_end);
	printf("PAGE_OFFSET 0x%Lx\n", (long long)zepglob.page_offset);
	printf("PAGE_MAX 0x%Lx\n", (long long)zepglob.page_max);
#else
	printf("KERNEL_START 0x%.8lx\n", (unsigned long)zepglob.kernel_start);
	printf("KERNEL_END 0x%.8lx\n", (unsigned long)zepglob.kernel_end);
	printf("PAGE_OFFSET 0x%.8lx\n", (unsigned long)zepglob.page_offset);
	printf("PAGE_MAX 0x%.8lx\n", (unsigned long)zepglob.page_max);
#endif
#endif
}

int resolve(char *file, unsigned long addr, char *name, int size){
	FILE *input;
	char line[256];
	char caddr[32];
	char *paddr, *pname, *end;

	memset(name, '\0', size);
	memset(caddr, '\0', sizeof(caddr));
#ifdef _AMD64_
	snprintf(caddr, sizeof(caddr) - 1, "0x%Lx", (long long)addr);
#else
	snprintf(caddr, sizeof(caddr) - 1, "0x%lx", (unsigned long)addr);
#endif	
	if((input = fopen(file, "r")) != NULL){
		while(fgets(line, sizeof(line) - 1, input) != NULL){
			paddr = strtok(line, " ");
			if(strstr(caddr, paddr)){
				pname = strtok(NULL, " ");
				pname = strtok(NULL, " ");
				end = strstr(pname, "\n");
				if(pname[0] != '_'){
					memcpy(name, pname, size - 1);
					name[end - pname] = '\0';
					fclose(input);
					return 0;
				}
			}

		}
		fclose(input);
	}
		
	memcpy(name, "UNKNOWN", size - 1);
	return -1;
}

unsigned long rresolve(char *file, char *name){
	FILE *input;
	char *paddr, *pname;
	char line[256];
	unsigned long addr = 0;

	if((input = fopen(file, "r")) != NULL){
		while(fgets(line, sizeof(line) - 1, input) != NULL){
			paddr = strtok(line, " ");
			pname = strtok(NULL, " ");
			pname = strtok(NULL, " ");
			pname[strlen(pname) - 1] = '\0';
			
			if(!strcmp(pname, name)){
				addr = strtoull(paddr, NULL, 16);
				fclose(input);
				return addr;
			}
		}
		fclose(input);
	}
	return addr;
}

void get_opcodes(unsigned long addr, unsigned long *tabopcodes){
	if(!zeppoo_valid_addr(addr)){
		zeppoo_read_memory(addr, &tabopcodes[0], 4);
		zeppoo_read_memory(addr+4, &tabopcodes[1], 4);
	}
	else{
		tabopcodes[0] = tabopcodes[1] = 0;
	}
}

int zeppoo_valid_addr(unsigned long addr){
	if(addr > zepglob.kernel_start && addr < zepglob.kernel_end)
		return 0;
	else
		return -1;
}

void zeppoo_fatal(const char *fmt, ...){
	va_list args;
	
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	fflush(stderr);
	va_end(args);
	exit(-1);
}

int zeppoo_search_jmp(unsigned long addr){
	char buffer[64];
	memset(buffer, '\0', sizeof(buffer));
	
	/* JMP lame detection */
	zeppoo_read_memory(addr, buffer, sizeof(buffer) - 1);
	if((memmem(buffer, sizeof(buffer) - 1, "\xb8", 1) != NULL) && (memmem(buffer, sizeof(buffer) - 1, "\xff\xe0", 2) != NULL))
		return 0;
	
/*	if(((memmem(buffer, sizeof(buffer) - 1, "\xb8\x90", 2) != NULL) || (memmem(buffer, sizeof(buffer) - 1, "\x90\xb8", 2) != NULL)) && (memmem(buffer, sizeof(buffer) - 1, "\x90\x90", 2) != NULL))
		return 0;
*/
	return -1;
}
