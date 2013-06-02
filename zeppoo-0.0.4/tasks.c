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

#include "tasks.h"

void getTasksMemory(pTable *mytasks){
	zeppoo_init_taskInfo();
	zeppoo_get_tasks(mytasks);
}

/* Functions to get tasks by /proc */

int getOther(char *buffer, char *other, size_t lenbuffer, size_t lenother){
	char *ptr, *ptr2;
	size_t len;

	memset(other, '\0', lenother);
	
	if((ptr = strstr(buffer,"\t")) != NULL){
        	ptr++;                                  
		if((ptr2 = strstr(buffer,"\n")) != NULL){	
			len = (int)ptr2 - (int)ptr;
			if(len < lenother){
				strncpy(other, ptr, len);
				other[lenother - 1] = '\0';
				return 0;
			}
		}
	}
	return -1;
}

int getUidGid(char *buffer, char *id, size_t lenbuffer, size_t lenid){
	char tmp[255];
	char *ptr,*ptr2;
	size_t len;

	memset(id, '\0', lenid);

	if((ptr = strstr(buffer,"\t")) != NULL){
		ptr++;
						
		if((ptr2 = strstr(buffer,"\n")) != NULL){
			len = (int)ptr2 - (int)ptr;
			if(len < sizeof(tmp)){
				strncpy(tmp, ptr, len);
				tmp[sizeof(tmp) - 1] = '\0';

				if((ptr = strstr(tmp, "\t")) != NULL){
					len = (int)ptr - (int)tmp;

					if(len < lenid){
						strncpy(id, tmp, len);
						id[lenid - 1] = '\0';
						return 0;
					}
					
				}
			}
		}
	}
	return -1;
}

/* Get ALL Tasks by /proc */
int getInfo(char *file, pTable *mytasks, int rec) {
	FILE *output;
	char buffer[255];
	char name[16];
	char id[6];
	char key[KEYSIZE];

	pTask *current_task;

	memset(key, '\0', KEYSIZE);
	
	if((output = fopen(file, "r")) == NULL){
		return -1;
	}
	else {
		while(fgets(buffer, 255, output) != NULL){
			if(!strncmp(buffer, "Name:", 5)){
				getOther(buffer, name, sizeof(buffer), sizeof(name));
				current_task = malloc(sizeof(pTask));
				if(current_task == NULL)
					zeppoo_fatal("malloc error");
				memset(current_task, '\0', sizeof(pTask));

				memcpy(current_task->name, name, sizeof(current_task->name) - 1);
				current_task->name[sizeof(current_task->name) - 1] = '\0';

				current_task->rec = rec;
			}
			else if(!strncmp(buffer, "Pid:", 4)){
				getOther(buffer, id, sizeof(buffer), sizeof(id));
				current_task->pid = atoi(id);
			}
			else if(!strncmp(buffer, "Uid:", 4)){
				getUidGid(buffer, id, sizeof(buffer), sizeof(id));
				current_task->uid = atoi(id);
			}
			else if(!strncmp(buffer, "Gid:", 4)){
				getUidGid(buffer, id, sizeof(buffer), sizeof(id));
				current_task->gid = atoi(id);
			}
					
			memset(buffer, '\0', 255);
		}
		current_task->mybin_fmt.md5sum_loadbinary = NULL;
		current_task->mybin_fmt.md5sum_loadshlib = NULL;
		current_task->mybin_fmt.md5sum_coredump = NULL;
		current_task->mybin_fmt.name = NULL;
		
		snprintf(key, KEYSIZE - 1, "%d", current_task->pid);
		current_task->addr = 0;
		hash_insert(mytasks, key, KEYSIZE, current_task);
		memset(key, '\0', KEYSIZE);
	}
	fclose(output);
	return 0;
}

int getTasksProc(pTable *mytasks){
	DIR * dir, *rdir;
	struct dirent * entry, *rentry;
	char file[20];
	char directory[64];
	char rfile[64];

	if((dir = opendir("/proc")) == NULL){
		perror("opendir /proc :");
		return -1;
	}
	else{
		while((entry = readdir (dir)) != NULL){
			if(isdigit(entry->d_name[0]) != 0){
				memset(file, '\0', 20);
				snprintf(file, sizeof(file) - 1, "/proc/%s/status",entry->d_name);
				getInfo(file, mytasks, 0);

				snprintf(directory, sizeof(directory) - 1, "/proc/%s/task",entry->d_name);
				if((rdir = opendir(directory)) != NULL){
					while((rentry = readdir(rdir)) != NULL){
						if((isdigit(rentry->d_name[0]) != 0) && strcmp(entry->d_name,rentry->d_name)){
							snprintf(rfile, sizeof(rfile) - 1, "%s/%s/status",directory,rentry->d_name);
							getInfo(rfile, mytasks, 1);
						}
					}
					closedir(rdir);
				}
			}
		}
	}
	closedir(dir);
	return 0;
}


int getTasksProcForce(pTable *mytasks){
	int i;
	DIR * rdir;
	struct dirent * rentry;
	char file[20];
	char directory[64];
	char rfile[64];
	
	i = 1;
	while(i < 65535){
		memset(file, '\0', 20);
		snprintf(file, sizeof(file) - 1, "/proc/%d/status",i);
		
		if(getInfo(file, mytasks, 0) != -1){
			snprintf(directory, sizeof(directory) - 1, "/proc/%d/task",i);
			if((rdir = opendir(directory)) != NULL){
				while((rentry = readdir(rdir)) != NULL){
					if(((isdigit(rentry->d_name[0]) != 0)) && (atoi(rentry->d_name) != i)){
						snprintf(rfile, sizeof(rfile) - 1, "%s/%s/status",directory,rentry->d_name);
						getInfo(rfile, mytasks, 1);
					}
				}
				closedir(rdir);
			}
		}
		i ++;
	}
	
	printf("\n");
	return 0;
}


int getTasksPS(pTable *mytasks){ 
	FILE *output;
	char line[512];
	char key[KEYSIZE];
	int i = 0;
	char *p;
	pTask *current_task;

	memset(key, '\0', KEYSIZE);
	
	if((output = popen("/bin/ps -eo user,pid,uid,gid,state,fname", "r")) == NULL){
		perror("popen :");
		return -1;
	}
	else{
		fgets(line, 512, output);
		while(fgets(line, 512, output) != NULL){
			i = 0;
			p = (char *)strtok(line, " ");
			while(p != NULL){
				switch (i) {
					case (0) :
						current_task = malloc(sizeof(pTask));
						if(current_task == NULL)
							zeppoo_fatal("malloc error");
						memset(current_task, '\0', sizeof(pTask));
						break;
					case (1) :
						current_task->pid = atoi(p);
						break;
					case (2) :
						current_task->uid = atoi(p);
						break;
					case (3) :
						current_task->gid = atoi(p);
						break;
					case(5) :
						snprintf(current_task->name,sizeof(current_task->name) - 1,"%s",p);
						snprintf(key, KEYSIZE - 1, "%d", current_task->pid); 
						current_task->addr = 0;      
						current_task->mybin_fmt.md5sum_loadbinary = NULL;
						current_task->mybin_fmt.md5sum_loadshlib = NULL;
						current_task->mybin_fmt.md5sum_coredump = NULL;
						current_task->mybin_fmt.name = NULL;
						hash_insert(mytasks, key, KEYSIZE, current_task);
						memset(key, '\0', KEYSIZE);
						break;
				}

				p = (char *)strtok(NULL, " ");
				i++;
			}
				
		}
	}
	pclose(output);
	return 0;
}


int getTasksKill(pTable *mytasks){
	char key[KEYSIZE];
	int i;
	pTask *current_task;

	memset(key, '\0', KEYSIZE);
	
	for(i=1; i<65535;i++){
		if(kill(i,0) == 0){
			current_task = malloc(sizeof(pTask));
			if(current_task == NULL)
				zeppoo_fatal("malloc error");
			memset(current_task, '\0', sizeof(pTask));

			current_task->pid = i;
			current_task->addr = 0;
			current_task->mybin_fmt.md5sum_loadbinary = NULL;
			current_task->mybin_fmt.md5sum_loadshlib = NULL;
			current_task->mybin_fmt.md5sum_coredump = NULL;
			current_task->mybin_fmt.name = NULL;
			
			snprintf(key, KEYSIZE - 1, "%d", current_task->pid);
			hash_insert(mytasks, key, KEYSIZE, current_task); 
			memset(key, '\0', KEYSIZE);
		}
	}
	return 0;
}

void checkTasks(pTable *ref, pTable *cmp, pTable *check){
	char key[KEYSIZE];
	pItem *tmpRef;
	pTask *taskRef;
	pTask *taskCheck;
	pElement *tmp;

	tmpRef = ref->first;
	while(tmpRef != NULL){
		taskRef = (pTask *)tmpRef->el->value;
		memset(key, '\0', KEYSIZE);
		snprintf(key, KEYSIZE - 1, "%d", taskRef->pid);

		tmp = (pElement *)hash_get(cmp, key, KEYSIZE);
		if(tmp == NULL && taskRef->rec == 0){
			taskCheck = malloc(sizeof(pTask));
			if(taskCheck == NULL)
				zeppoo_fatal("malloc error");
			memset(taskCheck, '\0', sizeof(pTask));

			memcpy(taskCheck->name, taskRef->name, sizeof(taskCheck->name));
			taskCheck->pid = taskRef->pid;
			taskCheck->uid = taskRef->uid;
			taskCheck->gid = taskRef->gid;
			taskCheck->rec = taskRef->rec;
			taskCheck->addr = taskRef->addr;

			hash_insert(check, key, KEYSIZE, taskCheck);
		}
		tmpRef = tmpRef->next;
	}
}

void simpleViewTasks(pTable *mytasks){
        pItem *tmp;
        pTask *tmptask;

	printf("PID\t     UID\t      GID\t\t    NAME\t ADDR");
	
        tmp = mytasks->first;
        while(tmp != NULL){
                tmptask = (pTask *)tmp->el->value;
#ifdef _AMD64_
		printf("\n%d\t%8d\t %8d\t %15s @ 0x%.16Lx", tmptask->pid, tmptask->uid, tmptask->gid, tmptask->name, (long long)tmptask->addr);
#else
                printf("\n%d\t%8d\t %8d\t %15s @ 0x%.8lx", tmptask->pid, tmptask->uid, tmptask->gid, tmptask->name, (unsigned long)tmptask->addr);
#endif		
		tmp = tmp->next;
        }
        printf("\n");
}

void viewCheckTasks(pTable *mytasks){
        pItem *tmp;

	printf("-------------------------------------------------------------------------------\n");
	printf("[+] Begin : Task\n\n");
        
	tmp = mytasks->first;
        if(tmp != NULL){
                printf("LIST OF HIDDEN TASKS\n");
                simpleViewTasks(mytasks);
		printf("\n");
        }
        else{
                printf("NO HIDDEN TASK\n\n");
        }
	
	printf("[+] End : Task\n");
	printf("-------------------------------------------------------------------------------\n\n");
}

void viewTasksMemory(void){
	pTable *tasksmemory;
	tasksmemory = hash_new((void *)free_task);

	getTasksMemory(tasksmemory);
	simpleViewTasks(tasksmemory);	
	
	hash_delete(tasksmemory);
}

void viewTaskMemory(int pid){
	pTask ptask;
	
	zeppoo_init_taskInfo();
	if(!zeppoo_get_task(pid, &ptask)){
		printf("\nPID\t UID\t GID\t NAME\t\t ADDR");
#if _AMD64_
		printf("\n%d\t %d\t %d\t %-15s @ 0x%.16Lx\n", ptask.pid, ptask.uid, ptask.gid, ptask.name, (long long)ptask.addr);
#else 
		printf("\n%d\t %d\t %d\t %-15s @ 0x%.8lx\n", ptask.pid, ptask.uid, ptask.gid, ptask.name, (unsigned long)ptask.addr);
#endif
	}
	else
		printf("Task %d not found !\n", pid);
}

void viewHiddenTasks(void){
	pTable *tasksmemory;
	pTable *tasksproc;
	pTable *tasksprocforce;
	pTable *tasksps;
	pTable *taskskill;
	pTable *taskscheck;
	
	tasksmemory = hash_new((void *)free_task);
	tasksproc = hash_new((void *)free_task);
	tasksprocforce = hash_new((void *)free_task);
    	tasksps = hash_new((void *)free_task);
	taskskill = hash_new((void *)free_task);
	taskscheck = hash_new((void *)free_task);
	
	getTasksMemory(tasksmemory);
	getTasksProc(tasksproc);
	getTasksProcForce(tasksprocforce);
	getTasksPS(tasksps);
	getTasksKill(taskskill);
		
	checkTasks(tasksproc, tasksps, taskscheck);
	checkTasks(tasksprocforce, tasksproc, taskscheck);
	checkTasks(tasksmemory, tasksproc, taskscheck);
	checkTasks(taskskill, tasksproc, taskscheck);
	viewCheckTasks(taskscheck);
	
	hash_delete(tasksmemory);
	hash_delete(tasksproc);
	hash_delete(tasksprocforce);
	hash_delete(tasksps);
	hash_delete(taskskill);
	hash_delete(taskscheck);
}
