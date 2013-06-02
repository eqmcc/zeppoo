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

#include "zeppoo.h"

pKernelSym superblocks_sym[] = {
	{ "sys_sync", "do_sync", 1, 1, 0xe8, 0, 0, 0, 0 },
	{ "do_sync", "wakeup_pdflush", 2, 0, 0xe8, 0, 0, 0, 0 },
	{ "do_sync", "sync_inodes", 3, 0, 0xe8, 0, 0, 0, 0 },
	{ "do_sync", "sync_dquots", 4, 0, 0xe8, 0, 0, 0, 0 },
	{ "do_sync", "sync_supers", 4, 0, 0xe8, 0, 0, 0, 0 },
	{ "do_sync", "sync_filesystems", 5, 1, 0xe8, 0, 0, 0, 0 },
	{ "sync_filesystems", "super_blocks", 6, 0, 0x81, 0, 0, 0, 0 },
	{ NULL, NULL, 0, 0, 0, 0, 0, 0, 0 }
};

pKernelSym ext3dirop_sym[] = {
	{ "ext3_read_inode", "__ext3_get_inode_loc", 1, 0, 0xe8, 0, 0, 0, 0 },
	{ "ext3_read_inode", "__brelse", 2, 0, 0xe8, 0, 0, 0, 0 },
	{ "ext3_read_inode", "ext3_file_inode_operations", 3, 0, 0xc7, 0, 0, 0, 0 },
	{ "ext3_read_inode", "ext3_file_operations", 4, 0, 0xc7, 0, 0, 0, 0 },
	{ "ext3_read_inode", "ext3_dir_inode_operations", 5, 0, 0xc7, 0, 0, 0, 0 },
	{ "ext3_read_inode", "ext3_dir_operations", 6, 0, 0xc7, 0, 0, 0, 0 },
	{ NULL, NULL, 0, 0, 0, 0, 0, 0, 0 }
};

void free_sops(pSops *tmp){
	free(tmp);
}

void zeppoo_init_vfs(void){
	if(zepversion.kernel >= KERNEL26)
		init_vfs_k26();
	else
		init_vfs_k24();
}

void init_vfs_k26(void){
	zepvfs.vGetVfs = get_vfs_k26;
	zepvfs.vGetVfsMd5sum = get_vfs_md5sum_kgeneric;
	zepvfs.vGetExt3 = get_ext3_k26; 
}

void init_vfs_k24(void){

}


void zeppoo_get_vfs(pTable *myvfs, char *file){
	zepvfs.vGetVfs(myvfs, file);
}

void get_vfs_k26(pTable *myvfs, char *file){
	char key[KEYSIZE];
	unsigned long super_blocks, next;
	unsigned long fs_sops, fs_read_inodes;
	pSops *mysops;

	superblocks_sym[0].start = zeppoo_get_syscall(__NR_sync);	
	super_blocks = zeppoo_walk_tree(superblocks_sym);

	printf("SUPERBLOCKS 0x%lx\n", (unsigned long)super_blocks);

	zeppoo_read_memory(super_blocks+32, &fs_sops, sizeof(fs_sops));

	zeppoo_read_memory(super_blocks, &next, sizeof(next));
	while(super_blocks != next){
		zeppoo_read_memory(next+32, &fs_sops, sizeof(fs_sops));

		if(fs_sops != 0){
			zeppoo_read_memory(fs_sops+8, &fs_read_inodes, sizeof(fs_read_inodes));
			mysops = (pSops *)malloc(sizeof(pSops));
			resolve(file, fs_sops, mysops->name, sizeof(mysops->name));
			mysops->fs_sops = fs_sops;
			mysops->fs_read_inodes = fs_read_inodes;
			mysops->fs_dir_operations = 0;
			mysops->fs_readdir = 0;

#ifdef _DEBUG_
			fprintf(stdout, "NAME %s 0x%lx 0x%lx\n", mysops->name, mysops->fs_sops, mysops->fs_read_inodes);
#endif
						
			memset(key, '\0', KEYSIZE);
			snprintf(key, KEYSIZE - 1, "%lx", (unsigned long)mysops->fs_sops);
			hash_insert(myvfs, key, KEYSIZE, mysops);
		}
		
		zeppoo_read_memory(next, &next, sizeof(next));
	}
}

void zeppoo_get_vfs_md5sum(pTable *myvfs){
	zepvfs.vGetVfsMd5sum(myvfs);
}

void get_vfs_md5sum_kgeneric(pTable *myvfs){
	char md5dump[BUFSYSFINGER];
	pItem *tmp;
	pSops *tmpsops;

	tmp = myvfs->first;
	while(tmp != NULL){
		tmpsops = (pSops *)tmp->el->value;
		if(tmpsops->fs_readdir != 0){
			zeppoo_read_memory(tmpsops->fs_read_inodes, md5dump, sizeof(md5dump));
			memset(tmpsops->md5sum_read_inodes, '\0', sizeof(tmpsops->md5sum_read_inodes));
			dumpmd5(md5dump, sizeof(md5dump), tmpsops->md5sum_read_inodes);

			zeppoo_read_memory(tmpsops->fs_readdir, md5dump, sizeof(md5dump));
			memset(tmpsops->md5sum_readdir, '\0', sizeof(tmpsops->md5sum_readdir));
			dumpmd5(md5dump, sizeof(md5dump), tmpsops->md5sum_readdir);
		}
		tmp = tmp->next;
	}
}

void zeppoo_get_ext3(pSops *ext3fs){
	zepvfs.vGetExt3(ext3fs);
}

void get_ext3_k26(pSops *ext3fs){
	ext3dirop_sym[0].start = ext3fs->fs_read_inodes;
	ext3fs->fs_dir_operations = zeppoo_walk_tree(ext3dirop_sym);
	zeppoo_read_memory(ext3fs->fs_dir_operations+24, &ext3fs->fs_readdir, sizeof(ext3fs->fs_readdir));
}
