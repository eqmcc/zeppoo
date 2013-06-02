/******************************************************************************/
/* vfs.c  -- see http://www.zeppoo.net                                        */
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

#include "vfs.h"

void simpleViewVFS(pTable *myvfs){
	pItem *tmp;
	pSops *tmpsops;

	tmp = myvfs->first;
	while(tmp != NULL){
		tmpsops = (pSops *)tmp->el->value;
		if(tmpsops->fs_readdir != 0){
			printf("SOPS %s 0x%.8lx\n", tmpsops->name, (unsigned long)tmpsops->fs_sops);
			printf("\t READ_INODES 0x%.8lx %s\n", (unsigned long)tmpsops->fs_read_inodes, tmpsops->md5sum_read_inodes);
			printf("\t DIR_OPERATIONS 0x%.8lx\n", (unsigned long)tmpsops->fs_dir_operations);
			printf("\t READDIR 0x%.8lx %s\n", (unsigned long)tmpsops->fs_readdir, tmpsops->md5sum_readdir);
		}
		tmp = tmp->next;
	}
}

void getVFSMemory(pTable *myvfs, char *file){
	pItem *tmp;
        pSops *tmpsops;
	
	zeppoo_get_vfs(myvfs, file);

	tmp = myvfs->first;
        while(tmp != NULL){
		tmpsops = (pSops *)tmp->el->value;
		if(!strcmp(tmpsops->name, "ext3_sops")){
			zeppoo_get_ext3(tmpsops);
		}

		tmp = tmp->next;
	}
	
	zeppoo_get_vfs_md5sum(myvfs);	
}

void viewVFS(char *file){
	pTable *vfs;
	
	vfs = hash_new((void *)free_sops);

	getVFSMemory(vfs, file);
	
	simpleViewVFS(vfs);
	
	hash_delete(vfs);
}
