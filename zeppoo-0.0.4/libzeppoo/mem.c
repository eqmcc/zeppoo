/******************************************************************************/
/* mem.c  -- see http://www.zeppoo.net                                        */
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

#ifdef _AMD64_
struct page_offset tabpage[] = {
	{ 0xffffffff80000000, 0xffffffffff000000, 0x0000000000ffffff },
	{ 0xffff810000000000, 0xffffff0000000000, 0x000000ffffffffff },
	{ 0, 0, 0 }
};
#endif		

unsigned long get_addr(struct page_offset *tabpage, unsigned long addr){
#ifdef _AMD64_
	struct page_offset *tmp_page;
	unsigned long tmp;
#endif
	unsigned long raddr = 0;
	
#ifdef _AMD64_
	tmp_page = tabpage;
        while(tmp_page->realmask != 0){
		//printf("MASK 0x%Lx RMASK 0x%Lx\n", tmp_page->mask, tmp_page->rmask);
		tmp = addr & tmp_page->mask;
		if(tmp == tmp_page->realmask){
			//printf("MASK TROUVE !!\n");
			raddr = (addr & tmp_page->rmask);
			//printf("ADDR 0x%Lx\n", raddr);
			return raddr;
		}
		tmp_page++;
	}
#endif
	return raddr;
}

void init_mem_k24(){
	/* Use same function as 2.6.X for now */
	zepmem.vOpen = openmem;
	zepmem.vClose = closemem;
	zepmem.vRead = readmem;
	zepmem.vWrite = writemem;
}

void init_mem_k26(){
	zepmem.vOpen = openmem;
	zepmem.vClose = closemem;
	zepmem.vRead = readmem;
	zepmem.vWrite = writemem;
}

void openmem(){
	printf("Memory : /dev/mem\n");
	
	if((mem = open("/dev/mem", fdmode)) == -1){
		perror("open mem");
		exit(-1);
	}

	if(valmmap){
		if((ptr = mmap (0, 200 * 1024 * 1024, protmode, flagsmode, mem, 0)) == MAP_FAILED){
			perror("mmap ");
			exit(-1);
		}
	}
}

void closemem(){

	if(valmmap){
		if(munmap((void *)ptr, 200 * 1024 * 1024) == -1){
			perror("munmap ");
			exit(-1);
		}
	}

	close(mem);
}

int readmem(unsigned long offset, void *buf, int size){
	int rlen;
	unsigned long roffset;

#ifdef _AMD64_
	roffset = get_addr(tabpage, offset);	
#else
	roffset = offset - zepglob.page_offset;
#endif

	if(valmmap){
		memcpy(buf, ptr+roffset, size);
	}
	else{
		if(lseek64(mem, (off64_t) roffset, SEEK_SET) == -1){
			perror("mem lseek :");
			exit(-1);
		}

		if((rlen = read(mem, buf, size)) != size){
			perror("mem read :");
			exit(-1);
		}
	}
	
	return rlen;
}

int writemem(unsigned long offset, void *buf, int size){
	int wlen;
        unsigned long roffset;
#ifdef _AMD64_
	roffset = get_addr(tabpage, offset);
#else
	roffset = offset - zepglob.page_offset;
#endif
			
	if(valmmap){
		memcpy(ptr+roffset, buf, size);
		msync(ptr, 200 * 1024 * 1024, MS_SYNC);
	}
	else {
		if(lseek64(mem, (off64_t) roffset, SEEK_SET) == -1){
			perror("mem lseek :");
			exit(-1);
		}

		if((wlen = write(mem, buf, size)) != size){
			perror("mem write :");
			exit(-1);
		}
	}
	return wlen;
}

