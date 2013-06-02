/******************************************************************************/
/* kmem.c  -- see http://www.zeppoo.net                                       */
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

#define _LARGEFILE64_SOURCE

#include "zeppoo.h"

void init_kmem_k24(){
	/* Use same function as 2.6.X for now */
	zepmem.vOpen = openkmem_k24;
	zepmem.vClose = closekmem;
	zepmem.vRead = readkmem;
	zepmem.vWrite = writekmem;
}

void init_kmem_k26(){
	zepmem.vOpen = openkmem_k26;
	zepmem.vClose = closekmem;
	zepmem.vRead = readkmem;
	zepmem.vWrite = writekmem;
}

void openkmem_k26(){
	printf("Memory : /dev/kmem\n");

	if(valmmap){
		printf("MMAP NOT SUPPORTED WITH /dev/kmem\n");
		exit(-1);
	}
	
	if((mem = open("/dev/kmem", fdmode)) == -1){
		perror("open kmem:");
		exit(-1);
	}
}

void openkmem_k24(int mode){
}

void closekmem(int mode){
	close(mem);
}

/* Using lseek64 because lseek doesn't work with kernel > 2.6.9 */
int readkmem(unsigned long offset, void *buf, int size){
	int rlen;
	
	if(lseek64(mem, (off64_t) offset, SEEK_SET) == -1){
		perror("kmem lseek :");
		exit(-1);
	}

	if((rlen = read(mem, buf, size)) != size){
		perror("kmem read :");
		exit(-1);
	}

	return rlen;
}

int writekmem(unsigned long offset, void *buf, int size){
	int wlen;
	
	if(lseek64(mem, (off64_t)offset, SEEK_SET) == -1){
		perror("kmem lseek :");
		exit(-1);
	}

	if((wlen = write(mem, buf, size)) != size){
		perror("kmem write :");
		exit(-1);
	}

	return wlen;
}
