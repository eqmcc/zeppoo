/******************************************************************************/
/* binaries.c  -- see http://www.zeppoo.net                                   */
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

void free_binfmt(pBinfmt *tmp){
	if(tmp->md5sum_loadbinary != NULL)
		free(tmp->md5sum_loadbinary);
	if(tmp->md5sum_loadshlib != NULL)
		free(tmp->md5sum_loadshlib);
	if(tmp->md5sum_coredump != NULL)
		free(tmp->md5sum_coredump);
	if(tmp->name != NULL)
		free(tmp->name);
	free(tmp);
}


void zeppoo_init_binaries(void){
	if(zepversion.kernel >= KERNEL26)
		init_binaries_k26();
	else
		init_binaries_k24();
}

void zeppoo_init_binaries_trace(int mode){
	if(mode == 0)
		init_binaries_mem();
	else
		init_binaries_ptrace();
}

void init_binaries_k26(void){
	zepbin.vGetBinfmt = get_binfmt_k26;
	zepbin.vGetBinfmts = get_binfmts_k26;
	zepbin.vGetBinfmtMd5sum = get_binfmt_md5sum_kgeneric;
	zepbin.vGetBinfmtsMd5sum = get_binfmts_md5sum_kgeneric;
	zepbin.vResolveBinfmts = resolve_binfmts_kgeneric;
}

void init_binaries_k24(void){


}

void init_binaries_mem(void){


}

void init_binaries_ptrace(void){
	zepbin.vAttach = ptrace_attach;
	zepbin.vDetach = ptrace_detach;
	zepbin.vRead = ptrace_read;
//	zepbin.vWrite = ptrace_write;
}


void zeppoo_binary_attach(struct binary *bin){
	zepbin.vAttach(bin);
}

void zeppoo_binary_detach(struct binary *bin){
	zepbin.vDetach(bin);
}

void zeppoo_binary_read(struct binary *bin, unsigned long addr, void *buf, size_t size){
	zepbin.vRead(bin, addr, buf, size);
}

void zeppoo_locate_linkmap(struct binary *bin){
	Elf32_Ehdr              *ehdr = (Elf32_Ehdr *)malloc(sizeof(Elf32_Ehdr));
	Elf32_Phdr              *phdr = (Elf32_Phdr *)malloc(sizeof(Elf32_Phdr));
	Elf32_Dyn               *dyn = (Elf32_Dyn *)malloc(sizeof(Elf32_Dyn));

	struct elf_format *elf = (struct elf_format *)bin->format;
	unsigned long  phdr_addr, dyn_addr, map_addr;

	memset(&elf->lm, '\0', sizeof(struct link_map));
	zeppoo_binary_read(bin, 0x08048000, ehdr, sizeof(Elf32_Ehdr));
		
	phdr_addr = 0x08048000 + ehdr->e_phoff;
	zeppoo_binary_read(bin, phdr_addr, phdr, sizeof(Elf32_Phdr));

#ifdef _DEBUG_
	fprintf(stdout,"Program Header 0x%x\n", (unsigned int)phdr_addr);
#endif
	
	while(phdr->p_type != PT_DYNAMIC)
		zeppoo_binary_read(bin, phdr_addr += sizeof(Elf32_Phdr), phdr, sizeof(Elf32_Phdr));


	 zeppoo_binary_read(bin, phdr->p_vaddr, dyn, sizeof(Elf32_Dyn));
	 dyn_addr = phdr->p_vaddr;

	 elf->got = 0x0;
	 elf->rel_plt = 0x0;
	 elf->rel_plt_size = 0;

	 do {
		 zeppoo_binary_read(bin, dyn_addr += sizeof(Elf32_Dyn), dyn, sizeof(Elf32_Dyn));
		 if(dyn->d_tag == DT_PLTGOT && !elf->got) 
			 elf->got = dyn->d_un.d_ptr;
				
		 else if(dyn->d_tag == DT_JMPREL && !elf->rel_plt) 
			 elf->rel_plt = dyn->d_un.d_ptr;
		
		 else if(dyn->d_tag == DT_PLTRELSZ && !elf->rel_plt_size)
			 elf->rel_plt_size = dyn->d_un.d_val;
	 }while(!elf->got || !elf->rel_plt || !elf->rel_plt_size);

	zeppoo_binary_read(bin, elf->got+4, &map_addr, 4);
	zeppoo_binary_read(bin, map_addr, &elf->lm, sizeof(struct link_map));

#ifdef _DEBUG_
	fprintf(stdout, "GOT 0x%lx\n", elf->got);
	fprintf(stdout, "REL_PLT 0x%lx\n", elf->rel_plt);
	fprintf(stdout, "REL_PLT_SIZE %d\n", elf->rel_plt_size);
#endif
	
	free(phdr);
	free(ehdr);
	free(dyn);
}

void zeppoo_resolv_tables(struct binary *bin){
	struct elf_format *elf = (struct elf_format *)bin->format;
	Elf32_Dyn *dyn = (Elf32_Dyn *)malloc(sizeof(Elf32_Dyn));
	unsigned long addr;

	addr = (unsigned long) elf->lm.l_ld;

	zeppoo_binary_read(bin , addr, dyn, sizeof(Elf32_Dyn));

	while(dyn->d_tag){
		switch(dyn->d_tag){
			case DT_HASH:
				zeppoo_binary_read(bin, dyn->d_un.d_ptr + elf->lm.l_addr+4, &elf->nchains, sizeof(elf->nchains));				
				break;

			case DT_STRTAB:
				elf->strtab = dyn->d_un.d_ptr;
				break;
		
			case DT_SYMTAB:
				elf->symtab = dyn->d_un.d_ptr;
				break;

			default:
				break;
		}
		addr += sizeof(Elf32_Dyn);
		zeppoo_binary_read(bin, addr, dyn, sizeof(Elf32_Dyn));
	}

#ifdef _DEBUG_
	fprintf(stdout,"NCHAINS %d\n", elf->nchains);
	fprintf(stdout, "STRTAB 0x%lx\n", elf->strtab);
	fprintf(stdout, "SYMTAB 0x%lx\n", elf->symtab);
#endif
	free(dyn);
}

unsigned long zeppoo_find_sym_in_tables(struct binary *bin, char *sym_name){
	struct elf_format *elf = (struct elf_format *)bin->format;
	Elf32_Sym *sym = (Elf32_Sym *)malloc(sizeof(Elf32_Sym));
	Elf32_Rel *rel = (Elf32_Rel *)malloc(sizeof(Elf32_Rel));
	int i;
	unsigned long addr;
	char symbol[128];

	i = addr = 0;

	while(i < elf->nchains && !addr){
		zeppoo_binary_read(bin,elf->rel_plt + (i++ * sizeof(Elf32_Rel)),rel,sizeof(Elf32_Rel));
		zeppoo_binary_read(bin,elf->symtab + (ELF32_R_SYM(rel->r_info) * sizeof(Elf32_Sym)),sym,sizeof(Elf32_Sym));
		
		memset(symbol, '\0', sizeof(symbol));
		zeppoo_binary_read(bin, elf->strtab + sym->st_name, symbol, sizeof(symbol));
		printf("symbol %s\n", symbol);	
		if(!strcmp(sym_name, symbol)){
			printf("ADDR 0x%x 0x%x\n", elf->lm.l_addr + sym->st_value, rel->r_offset);
			addr = elf->lm.l_addr + sym->st_value;
		}
		i++;
	}

	free(sym);
	return addr;
}

void ptrace_attach(struct binary *bin){
#ifdef _DEBUG_
	fprintf(stdout, "[+] Attach to %d\n", bin->pid);
#endif
	if(ptrace(PTRACE_ATTACH, bin->pid, 0, 0) == -1){
		perror("ptrace attach");
		exit(-1);
	}
	waitpid(bin->pid, &bin->status, 0);
}

void ptrace_detach(struct binary *bin){
#ifdef _DEBUG_
        fprintf(stdout, "[+] Detach to %d\n", bin->pid);
#endif
	if(ptrace(PTRACE_DETACH, bin->pid, 0, 0) == -1){
		perror("ptrace detach");
		exit(-1);
	}

	waitpid(bin->pid, &bin->status, 0);
}

void ptrace_read(struct binary *bin, unsigned long addr, void *buf, size_t size){
	int i , count;
	long word;
	
	int *ptr = (int *) buf;

	count = i = 0;
	while (count < size)
	{
		word = ptrace(PTRACE_PEEKTEXT, bin->pid, addr+count, NULL);
		count += 4;
		ptr[i++] = word;
	}
						
}

void zeppoo_get_binfmt(pTask *mytask){
	zepbin.vGetBinfmt(mytask);
}

void get_binfmt_k26(pTask *mytask){
	if(mytask->mybin_fmt.format != 0){
		zeppoo_read_memory(mytask->mybin_fmt.format, &mytask->mybin_fmt.next, LENADDR);
		zeppoo_read_memory(mytask->mybin_fmt.format+LENADDR, &mytask->mybin_fmt.module, LENADDR);
		zeppoo_read_memory(mytask->mybin_fmt.format+LENADDR*2, &mytask->mybin_fmt.load_binary, LENADDR);
		zeppoo_read_memory(mytask->mybin_fmt.format+LENADDR*3, &mytask->mybin_fmt.load_shlib, LENADDR);
		zeppoo_read_memory(mytask->mybin_fmt.format+LENADDR*4, &mytask->mybin_fmt.core_dump, LENADDR);
	}
	mytask->mybin_fmt.md5sum_loadbinary = NULL;
	mytask->mybin_fmt.md5sum_loadshlib = NULL;
	mytask->mybin_fmt.md5sum_coredump = NULL;
	mytask->mybin_fmt.name = NULL;
}

void zeppoo_get_binfmts(pTable *linuxformats){
	zepbin.vGetBinfmts(linuxformats);
}

void get_binfmts_k26(pTable *linuxformats){
	char key[KEYSIZE];
        pTask ptask;
        unsigned long next;
        pBinfmt *mybinfmt;

        zeppoo_init_taskInfo();
        if(!zeppoo_get_task(1, &ptask)){
                mybinfmt = malloc(sizeof(pBinfmt));
                if(mybinfmt == NULL)
                        zeppoo_fatal("malloc error");
		memset(mybinfmt, '\0', sizeof(pBinfmt));
		
                mybinfmt->format = ptask.mybin_fmt.format;
                mybinfmt->next = ptask.mybin_fmt.next;
                mybinfmt->module = ptask.mybin_fmt.module;
                mybinfmt->load_binary = ptask.mybin_fmt.load_binary;
                mybinfmt->load_shlib = ptask.mybin_fmt.load_shlib;
                mybinfmt->core_dump = ptask.mybin_fmt.core_dump;
        }
        
	memset(key, '\0', KEYSIZE);
        snprintf(key, KEYSIZE - 1, "%lx", (unsigned long)mybinfmt->format);
        hash_insert(linuxformats, key, KEYSIZE, mybinfmt);

        next = mybinfmt->next;
        while(next != 0){
                mybinfmt = malloc(sizeof(pBinfmt));
                if(mybinfmt == NULL)
                        zeppoo_fatal("malloc error");
		memset(mybinfmt, '\0', sizeof(pBinfmt));

                mybinfmt->format = next;
                zeppoo_read_memory(mybinfmt->format, &mybinfmt->next, LENADDR);
                zeppoo_read_memory(mybinfmt->format+LENADDR, &mybinfmt->module, LENADDR);
                zeppoo_read_memory(mybinfmt->format+LENADDR*2, &mybinfmt->load_binary, LENADDR);
                zeppoo_read_memory(mybinfmt->format+LENADDR*3, &mybinfmt->load_shlib, LENADDR);
                zeppoo_read_memory(mybinfmt->format+LENADDR*4, &mybinfmt->core_dump, LENADDR);
                memset(key, '\0', KEYSIZE);
#ifdef _AMD64_
		snprintf(key, KEYSIZE - 1, "%Lx", (long long)mybinfmt->format);
#else
		snprintf(key, KEYSIZE - 1, "%lx", (unsigned long)mybinfmt->format);
#endif     
		hash_insert(linuxformats, key, KEYSIZE, mybinfmt);
                next = mybinfmt->next;
        }
}

void zeppoo_get_binfmt_md5sum(pBinfmt *mybin){
	zepbin.vGetBinfmtMd5sum(mybin);
}

void get_binfmt_md5sum_kgeneric(pBinfmt *mybin){
	char md5dump[BUFBINFINGER];

	mybin->md5sum_loadbinary = NULL;
	mybin->md5sum_loadshlib = NULL;
	mybin->md5sum_coredump = NULL;

	mybin->md5sum_loadbinary = (char *)malloc(BUFBINFINGER);
	if(mybin->md5sum_loadbinary == NULL)
		zeppoo_fatal("malloc error");
	memset(mybin->md5sum_loadbinary, '\0', BUFBINFINGER);
		
	mybin->md5sum_loadshlib = (char *)malloc(BUFBINFINGER);
	if(mybin->md5sum_loadshlib == NULL)
		zeppoo_fatal("malloc error");
	memset(mybin->md5sum_loadshlib, '\0', BUFBINFINGER);
		
	mybin->md5sum_coredump = (char *)malloc(BUFBINFINGER);
	if(mybin->md5sum_coredump == NULL)
		zeppoo_fatal("malloc error");
	memset(mybin->md5sum_coredump, '\0', BUFBINFINGER);
		
		
	if(mybin->load_binary != 0){
		zeppoo_read_memory(mybin->load_binary, md5dump, sizeof(md5dump));
		dumpmd5(md5dump, sizeof(md5dump), mybin->md5sum_loadbinary);
	}
	else
		memcpy(mybin->md5sum_loadbinary, "00000000000000000000000000000000", BUFBINFINGER);
		
	if(mybin->load_shlib != 0){
		zeppoo_read_memory(mybin->load_shlib, md5dump, sizeof(md5dump));
		dumpmd5(md5dump, sizeof(md5dump), mybin->md5sum_loadshlib);
	}
	else
		memcpy(mybin->md5sum_loadshlib, "00000000000000000000000000000000", BUFBINFINGER);
		
	if(mybin->core_dump != 0){
		zeppoo_read_memory(mybin->core_dump, md5dump, sizeof(md5dump));
		dumpmd5(md5dump, sizeof(md5dump), mybin->md5sum_coredump);
	}
	else
	memcpy(mybin->md5sum_coredump, "00000000000000000000000000000000", BUFBINFINGER);	
}

void zeppoo_get_binfmts_md5sum(pTable *mybin){
	zepbin.vGetBinfmtsMd5sum(mybin);
}

void get_binfmts_md5sum_kgeneric(pTable *mybin){
	pItem *tmp;
	pBinfmt * tmpbinfmt;

	tmp = mybin->first;
	while(tmp != NULL){
		tmpbinfmt = (pBinfmt *)tmp->el->value;
		
		zeppoo_get_binfmt_md5sum(tmpbinfmt);
		
		tmp = tmp->next;
	}
}

int zeppoo_resolve_binfmts(pTable *linuxformats, char *file){
	return zepbin.vResolveBinfmts(linuxformats, file);
}

int resolve_binfmts_kgeneric(pTable *linuxformats, char *file){
	pItem *tmp;
	pBinfmt *tmpbinfmt;

	tmp = linuxformats->first;
	while(tmp != NULL){
		tmpbinfmt = (pBinfmt *)tmp->el->value;
		tmpbinfmt->name = malloc(sizeof(pNameBinfmt));
		if(tmpbinfmt->name == NULL)
			zeppoo_fatal("malloc error");
		memset(tmpbinfmt->name, '\0', sizeof(pNameBinfmt));
		
		resolve(file, tmpbinfmt->format, tmpbinfmt->name->name_format, sizeof(tmpbinfmt->name->name_format));
		resolve(file, tmpbinfmt->next, tmpbinfmt->name->name_next, sizeof(tmpbinfmt->name->name_next));
		resolve(file, tmpbinfmt->module, tmpbinfmt->name->name_module, sizeof(tmpbinfmt->name->name_module));
		resolve(file, tmpbinfmt->load_binary, tmpbinfmt->name->name_load_binary, sizeof(tmpbinfmt->name->name_load_binary));
		resolve(file, tmpbinfmt->load_shlib, tmpbinfmt->name->name_load_shlib, sizeof(tmpbinfmt->name->name_load_shlib));
		resolve(file, tmpbinfmt->core_dump, tmpbinfmt->name->name_core_dump, sizeof(tmpbinfmt->name->name_core_dump));
		tmp = tmp->next;
	}
	return 0;
}

