/******************************************************************************/
/* main.c  -- see http://www.zeppoo.net                                       */
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "libzeppoo/zeppoo.h"
#include "tasks.h"
#include "syscalls.h"
#include "idt.h"
#include "symbols.h"
#include "vfs.h"
#include "binaries.h"
#include "fingerprints.h"

#define REDPATCH "\xb8\x01\x00\x00\x00\xc3"

void help(char *name){
	printf("HELP :\n");
	printf("-z FP\t\t check the system !\n"); 
	printf("-p\t\t display tasks in memory\n");
	printf("-s\t\t display syscalls\n");
	printf("-i\t\t display idt\n");
	//printf("-v\t\t display vfs\n");
	printf("-f FILE\t generate a fingerprint(syscalls, idt)\n");
	printf("-c OPTIONS\t check tasks, networks, fingerprints\n");
	printf("-d DEVICE\t use device(/dev/mem, /dev/kmem)\n");
	printf("-m\t\t more quick/portable\n");
	printf("-k\t\t use zepprotect\n");
	printf("-r\t\t patch the kernel(must be used for REDHAT, UBUNTU and the option -d /dev/mem -m)\n");
	printf("-t SYSTEMMAP\t specify System.map\n");
	printf("-V\t\t version\n");
	exit(0);
}

int main(int argc, char *argv[]){
	char *devicearg, *taskarg, *maparg, *fingerarg, *allarg;
	struct utsname info;
	char systemmap[255];
	char patch[sizeof(REDPATCH)];
	char save[sizeof(REDPATCH)];
	char c;
	int task,syscall,idt,symbol,vfs,network,finger,check,device,ommap,map,uselkm,redpatch,all;
	int mode = 0;
	unsigned long devmem_is_allowed = 0;
	
	task = syscall = idt = vfs = symbol = network = finger = check = device = ommap = map = uselkm = redpatch = all = 0;
	
	devicearg = taskarg = maparg = fingerarg = allarg = NULL;
	
	if(getuid() != 0){
		fprintf(stderr, "You must be root !!\n");
		exit(-1);
	}
	
	while((c = getopt(argc, argv, "hz:Vp::svxnf:ict:d:mkr")) != -1){
		switch(c){		
			case 'h' :
				help(argv[0]);
				break;
			case 'z' :
				all++;
				allarg = optarg;
				break;
			case 'V' :
				printf("VERSION %s\n", VERSION);
				exit(0);
				break;
			case 'p':
				task++;
				if(optarg != NULL)
					taskarg = optarg+1;
				break;
			case 's' :
				syscall++;
				break;
			case 'i' :
				idt++;
				break;
			case 'x' :
				symbol++;
				break;
			case 'v' :
				vfs++;
				maparg = optarg;
				break;
			case 'n' :
				network++;
				break;
			case 't' :
				map++;
				maparg = optarg;
				break;
			case 'f' :
				finger++;
				fingerarg = optarg;
				break;
			case 'c' :
				check++;
				break;
			case 'd' :
				device++;
				devicearg = optarg;
				break;
			case 'm' :
				ommap++;
				break;
			case 'k' :
				uselkm++;
				break;
			case 'r' :
				redpatch++;
				break;
		}
	}

	if(task || syscall || idt || symbol || vfs || network || finger || check || uselkm || all){
		memset(systemmap, '\0', sizeof(systemmap));
		if(!maparg){
			uname(&info);
			snprintf(systemmap, sizeof(systemmap), "%s-%s", DEFAULTSYSTEMMAP, info.release);	
		}
		else
			snprintf(systemmap, sizeof(systemmap), "%s", maparg);
	
		/* Be Warning, this option can be do a kernel panic !!! */
		if(redpatch){
			devmem_is_allowed = rresolve(systemmap, "devmem_is_allowed");
			mode = 1;
		}
		
		zeppoo_init_version(uselkm);
		zeppoo_init();
	
		if(devicearg)
			zeppoo_init_memory(devicearg, mode, ommap);
		else
			zeppoo_init_memory("/dev/kmem", mode, ommap);

	
		zeppoo_open_memory();

		if(devmem_is_allowed){
			fprintf(stdout, "!!!! PATCH THE KERNEL @ 0x%lx !!!!\n", devmem_is_allowed);
			memcpy(patch, REDPATCH, sizeof(REDPATCH));
			zeppoo_read_memory(devmem_is_allowed, save, sizeof(save));
			zeppoo_write_memory(devmem_is_allowed, patch, sizeof(patch));
		}	
					
		zeppoo_init_tasks();
		zeppoo_init_symb();
		zeppoo_init_syscalls();
		zeppoo_init_idt();
		zeppoo_init_vfs();
		zeppoo_init_binaries();

		if(all){
			viewHiddenTasks();
			checkFingerprints(allarg, systemmap);
		}
		else if(check){
			if(task)
				viewHiddenTasks();
			else if(finger)
				checkFingerprints(fingerarg, systemmap);
		}
		else if(finger){
			doFingerprints(fingerarg, systemmap);
		}
		else if(task){
			if(taskarg != NULL)
				viewTaskMemory(atoi(taskarg));
			else
				viewTasksMemory();
		}
		else if(syscall){
			viewSyscallsMemory(systemmap);
		}
		else if(idt){
			viewIdtMemory(systemmap);
		}
		else if(symbol){
			viewBinfmt(systemmap);
		}
		else if(vfs){
			viewVFS(systemmap);
		}
		else if(network){
		}
	
		if(redpatch && devmem_is_allowed){
			if(devmem_is_allowed){
				fprintf(stdout, "!!!! UNPATCH THE KERNEL @ 0x%lx !!!!\n", devmem_is_allowed);	 
				zeppoo_write_memory(devmem_is_allowed, save, sizeof(save));
			}
		}

		zeppoo_close_memory();
	}
	else{
		printf("Help : -h\n");
	}

	return 0;
}
