/******************************************************************************/
/* memory.c  -- see http://www.zeppoo.net                                     */
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

void zeppoo_init_memory(char *device, int mode, int val){
	valmmap = val;
	if(mode == 0){
		fdmode = O_RDONLY;
		protmode = PROT_READ;
		flagsmode = MAP_PRIVATE;
	}
	else{
		fdmode = O_RDWR;
		protmode = PROT_WRITE;
		flagsmode = MAP_SHARED;
	}

	if(!strcmp(device, "/dev/kmem")){
		if(zepversion.kernel >= KERNEL26)
			init_kmem_k26();
		else
			init_kmem_k24();
	}
	else if(!strcmp(device, "/dev/mem")){
		if(zepversion.kernel >= KERNEL26)
			init_mem_k26();
		else
			init_mem_k24();
	}
}

void zeppoo_open_memory(){
	zepmem.vOpen();	
}

void zeppoo_close_memory(){
	zepmem.vClose();
}

int zeppoo_read_memory(unsigned long offset, void *buf, int size){
	int ret;
	if(offset < zepglob.page_offset || offset >= zepglob.page_max)
		return -1;

	ret = zepmem.vRead(offset, buf, size);
	return ret;
}

int zeppoo_fread_memory(unsigned long offset, void *buf, int size){
	int ret;
	int temp = valmmap;
	
	if(offset < zepglob.page_offset || offset >= zepglob.page_max)
		return -1;
	
	valmmap = 0;
	ret = zepmem.vRead(offset, buf, size);
	valmmap = temp;
	return ret;
}

int zeppoo_write_memory(unsigned long offset, void *buf, int size){
	int ret;
	
	if(offset < zepglob.page_offset || offset >= zepglob.page_max)
		return -1;
	
	ret = zepmem.vWrite(offset, buf, size);
	return ret;
}

int zeppoo_fwrite_memory(unsigned long offset, void *buf, int size){
	int ret;
	int temp = valmmap;
	
	if(offset < zepglob.page_offset || offset >= zepglob.page_max)
		return -1;

	valmmap = 0;
	ret = zepmem.vWrite(offset, buf, size);
	valmmap = temp;
	return ret;
}
