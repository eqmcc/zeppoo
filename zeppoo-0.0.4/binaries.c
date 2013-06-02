/******************************************************************************/
/* binaries.h  -- see http://www.zeppoo.net                                   */
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

#include "binaries.h"

void simpleViewBinfmt(pTable *linuxformats){
        pItem *tmp;
        pBinfmt *tmpbinfmt;
        
        tmp = linuxformats->first;
        while(tmp != NULL){
                tmpbinfmt = (pBinfmt *)tmp->el->value;
#ifdef _AMD64_
		printf("format : %s => 0x%.16Lx\n", tmpbinfmt->name->name_format, (long long)tmpbinfmt->format);
		printf("\t=> next : %s => 0x%.16Lx\n", tmpbinfmt->name->name_next, (long long)tmpbinfmt->next);
		printf("\t=> module : %s => 0x%.16Lx\n", tmpbinfmt->name->name_module, (long long)tmpbinfmt->module);
		printf("\t=> load_binary : %s => 0x%.16Lx\n", tmpbinfmt->name->name_load_binary, (long long)tmpbinfmt->load_binary);
		printf("\t=> load_shlib : %s => 0x%.16Lx\n", tmpbinfmt->name->name_load_shlib, (long long)tmpbinfmt->load_shlib);
		printf("\t=> core_dump : %s => 0x%.16Lx\n", tmpbinfmt->name->name_core_dump, (long long)tmpbinfmt->core_dump);
#else
                printf("format : %s => 0x%.8lx\n", tmpbinfmt->name->name_format, (unsigned long)tmpbinfmt->format);
                printf("\t=> next : %s => 0x%.8lx\n", tmpbinfmt->name->name_next, (unsigned long)tmpbinfmt->next);
                printf("\t=> module : %s => 0x%.8lx\n", tmpbinfmt->name->name_module, (unsigned long)tmpbinfmt->module);
                printf("\t=> load_binary : %s => 0x%.8lx\n", tmpbinfmt->name->name_load_binary, (unsigned long)tmpbinfmt->load_binary);
                printf("\t=> load_shlib : %s => 0x%.8lx\n", tmpbinfmt->name->name_load_shlib, (unsigned long)tmpbinfmt->load_shlib);
                printf("\t=> core_dump : %s => 0x%.8lx\n", tmpbinfmt->name->name_core_dump, (unsigned long)tmpbinfmt->core_dump);
#endif		
                tmp = tmp->next;
        }
        printf("\n");
}

void getBinfmt(pTable *linuxformats, char *file){
        zeppoo_get_binfmts(linuxformats);
	zeppoo_get_binfmts_md5sum(linuxformats);
	zeppoo_resolve_binfmts(linuxformats, file);
}

void viewBinfmt(char *file){
        pTable *linuxformats = NULL;

        linuxformats = hash_new((void *)free_binfmt);

        getBinfmt(linuxformats, file);
	printf("[*] Binaries\n");
	simpleViewBinfmt(linuxformats);

        hash_delete(linuxformats);
}

void writeBinfmt(FILE *output, char *file){
        pTable *linuxformats = NULL;
        pItem *tmp;
        pBinfmt *tmpbinfmt;

        linuxformats = hash_new((void *)free_binfmt);
        getBinfmt(linuxformats, file);

	printf("\t[+] Begin : Generating Binaries Fingerprints\n");
	
        tmp = linuxformats->first;
        while(tmp != NULL){
                tmpbinfmt = (pBinfmt *)tmp->el->value;

#ifdef _AMD64_
		fprintf(output,"%s 0x%.16Lx ", tmpbinfmt->name->name_format, (long long)tmpbinfmt->format);
		fprintf(output,"%s 0x%.16Lx ", tmpbinfmt->name->name_next, (long long)tmpbinfmt->next);
		fprintf(output,"%s 0x%.16Lx ", tmpbinfmt->name->name_module, (long long)tmpbinfmt->module);
		fprintf(output,"%s 0x%.16Lx %s ", tmpbinfmt->name->name_load_binary, (long long)tmpbinfmt->load_binary, tmpbinfmt->md5sum_loadbinary);
		fprintf(output,"%s 0x%.16Lx %s ", tmpbinfmt->name->name_load_shlib, (long long)tmpbinfmt->load_shlib, tmpbinfmt->md5sum_loadshlib);
		fprintf(output,"%s 0x%.16Lx %s\n", tmpbinfmt->name->name_core_dump, (long long)tmpbinfmt->core_dump, tmpbinfmt->md5sum_coredump);
#else
                fprintf(output,"%s 0x%.8lx ", tmpbinfmt->name->name_format, (unsigned long)tmpbinfmt->format);
                fprintf(output,"%s 0x%.8lx ", tmpbinfmt->name->name_next, (unsigned long)tmpbinfmt->next);
                fprintf(output,"%s 0x%.8lx ", tmpbinfmt->name->name_module, (unsigned long)tmpbinfmt->module);
                fprintf(output,"%s 0x%.8lx %s ", tmpbinfmt->name->name_load_binary, (unsigned long)tmpbinfmt->load_binary, tmpbinfmt->md5sum_loadbinary);
                fprintf(output,"%s 0x%.8lx %s ", tmpbinfmt->name->name_load_shlib, (unsigned long)tmpbinfmt->load_shlib, tmpbinfmt->md5sum_loadshlib);
                fprintf(output,"%s 0x%.8lx %s\n", tmpbinfmt->name->name_core_dump, (unsigned long)tmpbinfmt->core_dump, tmpbinfmt->md5sum_coredump);
#endif
                tmp = tmp->next;
        }
        printf("\t[+] End : Generating Binaries Fingerprints\n\n");
        
	hash_delete(linuxformats);
}

void copyBinfmt(pBinfmt *source, pBinfmt *dest){
        dest->format = source->format;
        dest->next = source->next;
        dest->module = source->module;
        dest->load_binary = source->load_binary;
        dest->load_shlib = source->load_shlib;
        dest->core_dump = source->core_dump;

        memcpy(dest->name->name_format, source->name->name_format, sizeof(dest->name->name_format) - 1);
        memcpy(dest->name->name_next, source->name->name_next, sizeof(dest->name->name_next) - 1);
        memcpy(dest->name->name_module, source->name->name_module, sizeof(dest->name->name_module) - 1);
        memcpy(dest->name->name_load_binary, source->name->name_load_binary, sizeof(dest->name->name_load_binary) - 1);
        memcpy(dest->name->name_load_shlib, source->name->name_load_shlib, sizeof(dest->name->name_load_shlib) - 1);
        memcpy(dest->name->name_core_dump, source->name->name_core_dump, sizeof(dest->name->name_core_dump) - 1);
}

void getBinfmtFinger(unsigned long *value, char *name, char *md5, size_t size){
        char *champ;

        champ = strtok(NULL, " ");
        memcpy(name, champ, size - 1);
        champ = strtok(NULL, " ");
        *value = strtoul(champ, NULL, 16);

        if(md5 != NULL){
                champ = strtok(NULL, " ");
                memcpy(md5, champ, BUFBINFINGER);
        }
}

void getBinfmtFingerprints(FILE *input, pTable *linuxformats){
        char key[KEYSIZE];
        char line[256];
        char *champ;
        pBinfmt *tmpbinfmt;

        fgets(line, 256, input);
        while(strcmp(line, "[END BINFMT]\n")){
                tmpbinfmt = (pBinfmt *)malloc(sizeof(pBinfmt));
		if(tmpbinfmt == NULL)
			zeppoo_fatal("malloc error");
		memset(tmpbinfmt, '\0', sizeof(pBinfmt));
		
		tmpbinfmt->name = (pNameBinfmt *)malloc(sizeof(pNameBinfmt));
                if(tmpbinfmt->name == NULL)
                        zeppoo_fatal("malloc error");
		memset(tmpbinfmt->name, '\0', sizeof(pNameBinfmt));
		
                champ = strtok(line, " ");
                memcpy(tmpbinfmt->name->name_format, champ, sizeof(tmpbinfmt->name->name_format) - 1);
                champ = strtok(NULL, " ");
                tmpbinfmt->format = strtoul(champ, NULL, 16);
		
                tmpbinfmt->md5sum_loadbinary = (char *)malloc(BUFBINFINGER);
		if(tmpbinfmt->md5sum_loadbinary == NULL)
			zeppoo_fatal("malloc error");
		memset(tmpbinfmt->md5sum_loadbinary, '\0', BUFBINFINGER);

		tmpbinfmt->md5sum_loadshlib = (char *)malloc(BUFBINFINGER);
		if(tmpbinfmt->md5sum_loadshlib == NULL)
			zeppoo_fatal("malloc error");
		memset(tmpbinfmt->md5sum_loadshlib, '\0', BUFBINFINGER);
		
		tmpbinfmt->md5sum_coredump = (char *)malloc(BUFBINFINGER);
			if(tmpbinfmt->md5sum_coredump == NULL)
				zeppoo_fatal("malloc error");
	
		memset(tmpbinfmt->md5sum_coredump, '\0', BUFBINFINGER);
		
		getBinfmtFinger(&tmpbinfmt->next, tmpbinfmt->name->name_next, NULL, sizeof(tmpbinfmt->name->name_next));

                getBinfmtFinger(&tmpbinfmt->module, tmpbinfmt->name->name_module,NULL, sizeof(tmpbinfmt->name->name_module));

		getBinfmtFinger(&tmpbinfmt->load_binary, tmpbinfmt->name->name_load_binary,  tmpbinfmt->md5sum_loadbinary, sizeof(tmpbinfmt->name->name_load_binary));
		getBinfmtFinger(&tmpbinfmt->load_shlib, tmpbinfmt->name->name_load_shlib, tmpbinfmt->md5sum_loadshlib, sizeof(tmpbinfmt->name->name_load_shlib));
                getBinfmtFinger(&tmpbinfmt->core_dump, tmpbinfmt->name->name_core_dump, tmpbinfmt->md5sum_coredump, sizeof(tmpbinfmt->name->name_core_dump));

                tmpbinfmt->md5sum_coredump[strlen(tmpbinfmt->md5sum_coredump) - 1] = '\0';
		memset(key, '\0', KEYSIZE);
                snprintf(key, KEYSIZE - 1, "%lx", (unsigned long)tmpbinfmt->format);
                hash_insert(linuxformats, key, KEYSIZE, tmpbinfmt);

                fgets(line, 256, input);
        }
}

pBinfmt *checkBinfmtTask(pTask *tmptask, pTable *linuxformats){
        pItem *tmp;
        pBinfmt *tmpbinfmt;
        pBinfmt *hijackbinfmt;

        int format, hijack, ret;

        format = hijack = ret = 0;

        tmp = linuxformats->first;
        while(tmp != NULL && format == 0){
                tmpbinfmt = (pBinfmt *)tmp->el->value;
                if(tmptask->mybin_fmt.format == tmpbinfmt->format){
                        format = 1;
                        if(tmptask->mybin_fmt.next != tmpbinfmt->next)
                                hijack++;
                        if(tmptask->mybin_fmt.module != tmpbinfmt->module)
                                hijack++;
                        if(tmptask->mybin_fmt.load_binary != tmpbinfmt->load_binary || strcmp(tmpbinfmt->md5sum_loadbinary, tmptask->mybin_fmt.md5sum_loadbinary))
                                hijack++;
			if(tmptask->mybin_fmt.load_shlib != tmpbinfmt->load_shlib || strcmp(tmpbinfmt->md5sum_loadshlib, tmptask->mybin_fmt.md5sum_loadshlib))
                                hijack++;
                        if((tmptask->mybin_fmt.core_dump != tmpbinfmt->core_dump) || strcmp(tmpbinfmt->md5sum_coredump, tmptask->mybin_fmt.md5sum_coredump))
                                hijack++;
                }
                tmp = tmp->next;
        }
	
        if(format == 1 && hijack == 0)
                hijackbinfmt = NULL;
        else{
                hijackbinfmt = (pBinfmt *)malloc(sizeof(pBinfmt));
        	if(hijackbinfmt == NULL)
			zeppoo_fatal("malloc error");
		memset(hijackbinfmt, '\0', sizeof(pBinfmt));

		hijackbinfmt->md5sum_loadbinary = NULL;
		hijackbinfmt->md5sum_loadshlib = NULL;
		hijackbinfmt->md5sum_coredump = NULL;
		
		hijackbinfmt->name = (pNameBinfmt *)malloc(sizeof(pNameBinfmt));
                if(hijackbinfmt->name == NULL)
                        zeppoo_fatal("malloc error");
		memset(hijackbinfmt->name, '\0', sizeof(pNameBinfmt));

                copyBinfmt(tmpbinfmt, hijackbinfmt);
		
                return hijackbinfmt;
        }

        return hijackbinfmt;
}

void checkBinfmt(pTable *linuxformats, pTable *check){
        char key[KEYSIZE];
        pItem *tmp;
        pTask *tmptask;
        pTable *tasksmemory;

        pBinfmt *hijackbinfmt;

        tasksmemory = hash_new((void *)free_task);
        zeppoo_init_taskInfo();
        zeppoo_get_tasks(tasksmemory);

        tmp = tasksmemory->first;
        while(tmp != NULL){
                tmptask = (pTask *)tmp->el->value;
		
		zeppoo_get_binfmt_md5sum(&tmptask->mybin_fmt);
		
                memset(key, '\0', KEYSIZE);
                snprintf(key, KEYSIZE - 1, "%lx", (unsigned long)tmptask->mybin_fmt.format);
                if(tmptask->mybin_fmt.format != 0 && hash_get(check, key, KEYSIZE) == NULL){
                        if((hijackbinfmt = checkBinfmtTask(tmptask, linuxformats)) != NULL){
                                memset(key, '\0', KEYSIZE);
                                snprintf(key, KEYSIZE - 1, "%lx", (unsigned long)hijackbinfmt->format);
                                hash_insert(check, key, KEYSIZE, hijackbinfmt);
                        }
                }
                tmp = tmp->next;
        }

        hash_delete(tasksmemory);
}

void viewHijackBinfmt(FILE *input, char *file){
        pTable *linuxformats = NULL;
        pTable *linuxformatscheck = NULL;

        linuxformats = hash_new((void *)free_binfmt);
        linuxformatscheck = hash_new((void *)free_binfmt);

        getBinfmtFingerprints(input, linuxformats);
	
	printf("-------------------------------------------------------------------------------\n");
	printf("[+] Begin : Binaries Format\n\n");
	
        checkBinfmt(linuxformats, linuxformatscheck);

        if(linuxformatscheck->first != NULL){
                printf("LIST OF HIJACK BINFMT\n");
                simpleViewBinfmt(linuxformatscheck);
                printf("\n");
        }
        else
                printf("NO HIJACK BINFMT\n\n");

        printf("[+] End : Binaries Format\n");
        printf("-------------------------------------------------------------------------------\n\n");
        hash_delete(linuxformats);
	hash_delete(linuxformatscheck);
}
