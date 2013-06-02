/******************************************************************************/
/* fingerprints.c  -- see http://www.zeppoo.net                               */
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

#include "fingerprints.h"
#include "syscalls.h"
#include "idt.h"
#include "symbols.h"
#include "binaries.h"

int doFingerprints(char *file, char *mapfile){
	FILE *output;
	char tampon[256];
	struct utsname uts;
	time_t timeval;
	struct tm *ptr_tm;

	printf("[+] Begin Generating Fingerprints in %s\n\n", file);
	if((output = fopen(file, "w")) == NULL){
		perror("fopen :");
		return -1;
	}
	uname(&uts);
	(void)time(&timeval);
	ptr_tm = localtime(&timeval);
	strftime(tampon, 256, "%A %d %B %Y, %I:%S %p", ptr_tm);
	fprintf(output,"[BEGIN]\n");
	fprintf(output,"[DATE %s]\n", tampon);
	fprintf(output,"[INFO %s %s %s]\n", uts.sysname, uts.machine, uts.release);
	fprintf(output,"[BEGIN SYSCALLS]\n");
	writeSyscallsMemory(output, mapfile);	
	fprintf(output,"[END SYSCALLS]\n");
	
	fprintf(output,"[BEGIN IDT]\n");
	writeIdtMemory(output, mapfile);
	fprintf(output,"[END IDT]\n");

	fprintf(output,"[BEGIN SYMBOLS]\n");
	writeSymbols(output, mapfile);
	fprintf(output,"[END SYMBOLS]\n");

	fprintf(output,"[BEGIN BINFMT]\n");
	writeBinfmt(output, mapfile);
	fprintf(output,"[END BINFMT]\n");
	
	fprintf(output,"[END]\n");
	
	printf("[+] End Generating Fingerprints in %s\n", file);
	
	fclose(output);
	return 0;
}

int checkFingerprints(char *file, char *mapfile){
	FILE *input;
	char line[80];

	fprintf(stdout, "[+] Begin Checking Fingerprints in %s\n\n", file);
	
	if((input = fopen(file, "r")) == NULL){
		perror("fopen :");
		return -1;
	}
	while(fgets(line, 80, input) != NULL){
		if(!strcmp(line, "[BEGIN SYSCALLS]\n"))
			viewHijackSyscalls(input, mapfile);
		else if(!strcmp(line, "[BEGIN IDT]\n"))
			viewHijackIdt(input, mapfile);
		else if(!strcmp(line, "[BEGIN SYMBOLS]\n"))
			viewHijackSymbols(input);
#ifndef _AMD64_		
		else if(!strcmp(line, "[BEGIN BINFMT]\n"))
			viewHijackBinfmt(input, mapfile);
#endif		
		else if(!strncmp(line, "[DATE", 5))
			fprintf(stdout, "[+] %s", line);
		else if(!strncmp(line, "[INFO", 5))
			fprintf(stdout, "[+] %s\n", line);
	}

	fprintf(stdout, "[+] End Checking Fingerprints in %s\n", file);
	
	fclose(input);
	return 0;
}
