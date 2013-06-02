/******************************************************************************/
/* tasks.c  -- see http://www.zeppoo.net                                      */
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

void free_task(pTask *tmp){
	if(tmp->mybin_fmt.md5sum_loadbinary != NULL)
		free(tmp->mybin_fmt.md5sum_loadbinary);
	if(tmp->mybin_fmt.md5sum_loadshlib != NULL)
		free(tmp->mybin_fmt.md5sum_loadshlib);
	if(tmp->mybin_fmt.md5sum_coredump != NULL)
		free(tmp->mybin_fmt.md5sum_coredump);
	if(tmp->mybin_fmt.name != NULL)
		free(tmp->mybin_fmt.name);
	
	free(tmp);
}

void zeppoo_init_tasks(void){
	if(zepversion.kernel >= KERNEL26)
		init_tasks_k26();
	else
		init_tasks_k24();
}

void init_tasks_k26(void){
	zeptasks.vInitTaskInfo = init_taskInfo_k26;
	zeptasks.vGetTasks = get_tasks_k26;

	if(zepversion.arc == 0){
		zeptasks.offset_list = 0;
		if(zepversion.kernel >= 2.618000)
			zeptasks.offset_list = 8;
	
		zeptasks.offset_pid = 4;
                zeptasks.offset_uid = 16;
	}
	else if(zepversion.arc == 1){
		zeptasks.offset_list = -4;
		zeptasks.offset_pid = -4;
		zeptasks.offset_uid = 16;
	}

	if(zepversion.kernel <= 2.617000)
		zeptasks.offset_uid = 32;
}

void init_tasks_k24(void){

}

void zeppoo_init_taskInfo(void){
	zeptasks.vInitTaskInfo();
}

void zeppoo_get_tasks(pTable *mytasks){
	zeptasks.vGetTasks(mytasks);
}

/* Find offset to the next process */
int find_offset_next_k26(char *buffer, size_t size){
        int i,offset,find1 = 0,find2 = 0;
	unsigned long first_addr,second_addr;
	int diffaddr, jmpfiveaddr;

	if(zepversion.arc == 0){
		diffaddr = 0x10;
		jmpfiveaddr = 0x14;
	}
	else if(zepversion.arc == 1){
		diffaddr = 0x20;
		jmpfiveaddr = 0x28;
	}
	
#ifdef _DEBUG_
	printf("DIFFADDR %d\n", diffaddr);
	printf("JMPFIVEADDR %d\n", jmpfiveaddr);
#endif

        for(i=0x20;i<size;i+=LENADDR){
                second_addr = first_addr;
                first_addr = *(unsigned long *)(buffer+i);

                if((first_addr == second_addr) && (first_addr > zepglob.kernel_start)){
			find2 = find1;
                        find1 = i;

                        if((find1-find2) == diffaddr){
#ifdef _DEBUG_                          
                                printf("[+] POS = 0x%x\n",find2+jmpfiveaddr);
#endif
                                offset = find2+jmpfiveaddr;
                                return offset;	              
			}
                }
        }
        return 0;
}

int find_offset_name_k26(char *buffer, size_t size){
	char *p;

	p = (char *)memmem(buffer, size, "\x73\x77\x61\x70\x70\x65\x72", 7);
	
	return (int)p - (int)buffer;
}

int find_offset_list_k26(char *buffer, size_t size){
	int i, count, offset;
	unsigned long first_addr, second_addr;
	count = 0;
	offset = -1;
	second_addr = -1;
	
	for(i=0;i<size && offset == -1;i+=LENADDR){
		first_addr = *(unsigned long *)(buffer+i);
		if(first_addr == second_addr)
			count++;
		if(count == 2){
			offset = i;
		}
		if(!zeppoo_valid_addr(first_addr))
			second_addr = first_addr;
	}
	
	offset += zeptasks.offset_list;
	return offset;
}

int find_offset_binfmt_k26(char *buffer, size_t size){
	int i, j, offset;
	unsigned long first_addr, second_addr;

	offset = first_addr = second_addr = -1;
	
	for(i=0, j=0;i<size && j != 3; i+=LENADDR){
		second_addr = first_addr;
		
		first_addr = *(unsigned long *)(buffer + i);
		if(first_addr == second_addr){
			j++;
			offset = i;
		}
	}
	return offset+LENADDR;
}

int find_offset_pid_k26(char *buffer, size_t size){
	int i, offset;
	unsigned long first_addr, second_addr;
	
	
	offset = first_addr = second_addr = -1;

	for(i=0;i<size && offset == -1;i+=LENADDR){
		first_addr = *(unsigned long *)(buffer + i);
		
		if(zepversion.arc == 1){
#ifdef _AMD64_
			if(first_addr == 0x100000001)
				second_addr = first_addr;
#endif
			if(second_addr != -1 && first_addr == 0x1)
				offset = i;
		}
		else{	
			if(first_addr == 0x1)
				second_addr = first_addr;
		
			if(first_addr == second_addr)
				offset = i;
		}
	}

	offset += zeptasks.offset_pid;
	return offset;
}

int find_offset_uid_k26(char *buffer, size_t size){
	unsigned long first_addr, second_addr;
	int i, offset, count;

	offset = -1;
	count = 0;
#ifdef _AMD64_
	i = 4;
#else
	i = 0;
#endif
	for(;i<size && offset == -1;i+=LENADDR){
		if(first_addr != 0)
			second_addr = first_addr;
                
		first_addr = *(unsigned long *)(buffer + i);
		if(first_addr == second_addr){
#ifdef _DEBUG_
			printf("EGAL %d %d\n", i, count);
#endif			
			count++;
		}
		if(count == 6){
#ifdef _DEBUG_			
			printf("COUNT %d\n", i);
#endif
			offset = i;
		}
	}

	offset += zeptasks.offset_uid;
	return offset;
}

void init_taskInfo_k26(void){
	char buffer[1024];
	unsigned long list_addr, current_addr;

	int fd;
	struct offsets kernelland_offsets;
		
	zeptaskinfo.init_task = zeppoo_find_init_task();
#ifdef _DEBUG_
#ifdef _AMD64_
	printf("[+] GETTASKS INIT TASK @ 0x%Lx\n", (long long)zeptaskinfo.init_task);
#else
	printf("[+] GETTASKS INIT TASK @ 0x%.lx\n", zeptaskinfo.init_task);
#endif
#endif

	if(zepversion.uselkm){
		if((fd = open("/sys/kernel/security/zepprotect/offsets", O_RDONLY)) == -1){
			fprintf(stderr, "Unable to get informations with lkm, check if zepprotect is load\n");
			exit(-1); 
		}

		memset(&kernelland_offsets, '\0', sizeof(kernelland_offsets));
		read(fd, &kernelland_offsets, sizeof(kernelland_offsets));

		close(fd);


		zeptaskinfo.offset_name = kernelland_offsets.name;
		zeptaskinfo.offset_list = kernelland_offsets.list;
		zeptaskinfo.offset_binfmt = kernelland_offsets.binfmt;
		zeptaskinfo.offset_pid = kernelland_offsets.pid;
		zeptaskinfo.offset_uid = kernelland_offsets.uid;
	
		zeppoo_fread_memory(zeptaskinfo.init_task+zeptaskinfo.offset_list, &list_addr, LENADDR);
		zeppoo_fread_memory(list_addr, buffer, 256);
		zeptaskinfo.offset_next = find_offset_next_k26(buffer, 256);
		zeppoo_fread_memory(list_addr + zeptaskinfo.offset_next, &current_addr, LENADDR);
		
#ifdef _DEBUG_  
		printf("[+] OFFSET NAME %d\n", zeptaskinfo.offset_name);
		printf("[+] OFFSET LIST %d\n", zeptaskinfo.offset_list);
#ifdef _AMD64_
		printf("LIST_ADDR 0x%Lx\n", (long long)list_addr);
#else
		printf("LIST_ADDR 0x%.8lx\n", list_addr);
#endif
		printf("[+] OFFSET NEXT %d\n", zeptaskinfo.offset_next);
#ifdef _AMD64_
		printf("CURRENT_ADDR 0x%Lx\n", (long long)current_addr);
#else
		printf("CURRENT_ADDR 0x%.8lx\n", current_addr);
#endif
		printf("[+] OFFSET BINFMT %d\n", zeptaskinfo.offset_binfmt);
		printf("[+] OFFSET PID %d\n", zeptaskinfo.offset_pid);	
		printf("[+] OFFSET UID %d\n", zeptaskinfo.offset_uid);
#endif
			
		
	}
	else{
	zeppoo_fread_memory(zeptaskinfo.init_task, buffer, 1024);
        zeptaskinfo.offset_name = find_offset_name_k26(buffer, 1024);
#ifdef _DEBUG_  
        printf("[+] OFFSET NAME %d\n", zeptaskinfo.offset_name);
#endif

        zeppoo_fread_memory(zeptaskinfo.init_task+40, buffer, 200);
        zeptaskinfo.offset_list = find_offset_list_k26(buffer, 200) + 20;
#ifdef _DEBUG_
        printf("[+] OFFSET LIST %d\n", zeptaskinfo.offset_list);
#endif

        zeppoo_fread_memory(zeptaskinfo.init_task+zeptaskinfo.offset_list, &list_addr, LENADDR);
        zeppoo_fread_memory(list_addr, buffer, 256);
#ifdef _DEBUG_
#ifdef _AMD64_
	printf("LIST_ADDR 0x%Lx\n", (long long)list_addr);
#else	
	printf("LIST_ADDR 0x%.8lx\n", list_addr);
#endif
#endif
        
	zeptaskinfo.offset_next = find_offset_next_k26(buffer, 256);
#ifdef _DEBUG_
        printf("[+] OFFSET NEXT %d\n", zeptaskinfo.offset_next);
#endif

	zeppoo_fread_memory(list_addr + zeptaskinfo.offset_next, &current_addr, LENADDR);

#ifdef _DEBUG_
#ifdef _AMD64_
	printf("CURRENT_ADDR 0x%Lx\n", (long long)current_addr);
#else
	printf("CURRENT_ADDR 0x%.8lx\n", current_addr);
#endif
#endif
			
	zeppoo_fread_memory(current_addr + zeptaskinfo.offset_list, buffer, 100);
	
	zeptaskinfo.offset_binfmt = find_offset_binfmt_k26(buffer, 100);
	zeptaskinfo.offset_binfmt += zeptaskinfo.offset_list;
#ifdef _DEBUG_
	printf("[+] OFFSET BINFMT %d\n", zeptaskinfo.offset_binfmt);
#endif

	zeppoo_fread_memory(current_addr + zeptaskinfo.offset_list, buffer, 200);
	zeptaskinfo.offset_pid = find_offset_pid_k26(buffer, 200);
        zeptaskinfo.offset_pid += zeptaskinfo.offset_list;
#ifdef _DEBUG_
        printf("[+] OFFSET PID %d\n", zeptaskinfo.offset_pid);
#endif

        zeppoo_fread_memory(current_addr+zeptaskinfo.offset_pid, buffer, 500);
        zeptaskinfo.offset_uid = find_offset_uid_k26(buffer, 500);
        zeptaskinfo.offset_uid += zeptaskinfo.offset_pid;
#ifdef _DEBUG_
        printf("[+] OFFSET UID %d\n", zeptaskinfo.offset_uid);
#endif
	}

	zeptaskinfo.first_addr = current_addr;
}

void get_tasks_k26(pTable *mytasks){
        char name[16];
        char key[KEYSIZE];
        unsigned long bin_fmt, list_addr, current_addr;
        int pid, uid, gid;
        pTask *current_task;

	  
        memset(key, '\0', KEYSIZE);

	current_addr = zeptaskinfo.first_addr;
	do{
                zeppoo_fread_memory(current_addr + zeptaskinfo.offset_name, name, 16);
                zeppoo_fread_memory(current_addr + zeptaskinfo.offset_binfmt, &bin_fmt, LENADDR);
		zeppoo_fread_memory(current_addr + zeptaskinfo.offset_pid, &pid, 4);
                zeppoo_fread_memory(current_addr + zeptaskinfo.offset_uid, &uid, 4);
                /* +16 to get egid */
		zeppoo_fread_memory(current_addr + zeptaskinfo.offset_uid+16, &gid, 4);

                current_task = malloc(sizeof(pTask));
		if(current_task == NULL)
			zeppoo_fatal("malloc error");
           	memset(current_task, '\0', sizeof(pTask));
		
		
		snprintf(key, KEYSIZE - 1, "%d",pid);
		memset(current_task->name, '\0', sizeof(current_task->name));
                memcpy(current_task->name, name, sizeof(current_task->name));
		
		current_task->mybin_fmt.format = bin_fmt;
		current_task->pid = pid;
                current_task->uid = uid;
                current_task->gid = gid;
                current_task->addr = current_addr;
		current_task->mybin_fmt.md5sum_loadbinary = NULL;
		current_task->mybin_fmt.md5sum_loadshlib = NULL;
		current_task->mybin_fmt.md5sum_coredump = NULL;
		current_task->mybin_fmt.name = NULL;
		
		zeppoo_get_binfmt(current_task);
		
		hash_insert(mytasks, key, KEYSIZE, current_task);

                memset(key, '\0', KEYSIZE);
                zeppoo_fread_memory(current_addr + zeptaskinfo.offset_list, &list_addr, LENADDR);
                zeppoo_fread_memory(list_addr + zeptaskinfo.offset_next, &current_addr, LENADDR);
        }while(current_addr != zeptaskinfo.init_task);	
}

int zeppoo_get_task(int pid, pTask *rtask){
	char key[KEYSIZE];
	
	pTable *tasks;
	pElement *htask;
	pTask *tmptask;
	int ret = -1;


	memset(key, '\0', KEYSIZE);
	tasks = hash_new((void *)free_task);
	zeppoo_get_tasks(tasks);

	snprintf(key, KEYSIZE - 1, "%d", pid);
	htask =  (pElement *)hash_get(tasks, key, KEYSIZE);

	if(htask != NULL){
		tmptask = (pTask *)htask->value;
		memcpy(rtask->name, tmptask->name, sizeof(rtask->name));
		rtask->pid = tmptask->pid;
		rtask->uid = tmptask->uid;
		rtask->gid = tmptask->gid;
		rtask->addr = tmptask->addr;
		rtask->mybin_fmt.format = tmptask->mybin_fmt.format;
		zeppoo_get_binfmt(rtask);
		ret = 0;
	}

	hash_delete(tasks);
	return ret;
}
