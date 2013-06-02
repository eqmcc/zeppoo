/******************************************************************************/
/* zeppoo.h  -- see http://www.zeppoo.net                                     */
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

#ifndef ZEPPOO_H
#define ZEPPOO_H

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <asm/unistd.h>
#include <sys/utsname.h>
#include <limits.h>
#include <sys/wait.h>
#include <elf.h>
#include <link.h>
#include <sys/ptrace.h>

/******************* GLOBAL **************************/

#ifdef _AMD64_
#define LENADDR	8
#else
#define LENADDR	4
#endif

/* I386 */
#define KERNEL_I386_START       0xc0000000      
#define KERNEL_I386_END         0xc1000000

#define PAGE_I386_OFFSET        0xc0000000
#define PAGE_I386_MAX           0xffffffff

/* AMD64 */
#define KERNEL_AMD64_START      0xffffffff80000000
#define KERNEL_AMD64_END        0xffffffff81000000

#define PAGE_AMD64_OFFSET       0xffff810000000000
#define PAGE_AMD64_MAX          0xffffffffffffffff

#define DEFAULTSYSTEMMAP		"/boot/System.map"
#define VERSION				"0.0.4"

/* Get NR_syscalls with the last kernel */
#define _NR_syscalls 318

struct global {
	unsigned long kernel_start;
	unsigned long kernel_end;
	unsigned long page_offset;
	unsigned long page_max;
};

struct global zepglob;
	
struct {
	unsigned short limit;
	unsigned long base;
} __attribute__((packed)) idtr;

struct {
	unsigned short off1;
	unsigned short sel;
	unsigned char none,flags;
	unsigned short off2;
} __attribute__ ((packed)) idt;

void zeppoo_init(void);
void get_opcodes(unsigned long, unsigned long *);
int resolve(char *, unsigned long, char *, int);
unsigned long rresolve(char *, char *);
int zeppoo_valid_addr(unsigned long);
void zeppoo_fatal(const char *, ...);
int zeppoo_search_jmp(unsigned long);


/******************* HASH ****************************/

#define KEYSIZE                 10

struct Element{
	unsigned long key;
	void *value;
};

struct Item {
	struct Element *el;
	struct Item *next;
};

struct Table {
	struct Item *first, *last, *current;
	void (*free_value)(void *);
};

typedef struct Element pElement;
typedef struct Item pItem;
typedef struct Table pTable;

unsigned long fnv_32a_buf(const void *, size_t,  unsigned long);

pTable *hash_new(void (*)(void *));
void hash_delete(pTable *);

void hash_insert(pTable *, const void *, size_t, void *);
void hash_remove(pTable *, const void *, size_t);

pElement *hash_get(pTable *, const void *, size_t);

/******************* MD5 ****************************/

struct MD5Context {
	unsigned long buf[ 4 ];
	unsigned long bits[ 2 ];
	unsigned char in[ 64 ];
};

void MD5Init( struct MD5Context * context );
void MD5Update( struct MD5Context * context, unsigned char const * buf, unsigned len );
void MD5Final( unsigned char digest[ 16 ], struct MD5Context * context );
void MD5Transform( unsigned long buf[ 4 ], const unsigned char in[ 64 ] );
void dumpmd5( char * pass, int value, unsigned char md5buffer[ BUFSIZ ] );

/******************* VERSION ************************/

#define KERNEL26		2.600000
#define KERNEL24		2.400000

struct Version {
	float kernel;
	char archi[6];
	int arc;
	int uselkm;
};

typedef struct Version pVersion;

pVersion zepversion;

void zeppoo_init_version();

/****************** MEMORY **************************/

struct memory {
	void (*vOpen)(void);
	void (*vClose)(void);
	int (*vRead)(unsigned long, void *, int);
	int (*vWrite)(unsigned long, void *, int);
};

struct memory zepmem;

int mem;
void *ptr;
int valmmap;
int fdmode;
int protmode;
int flagsmode;

void zeppoo_init_memory(char *, int, int);

void zeppoo_open_memory();
void zeppoo_close_memory();
int zeppoo_read_memory(unsigned long, void *, int);
int zeppoo_fread_memory(unsigned long, void *, int);
int zeppoo_write_memory(unsigned long, void *, int);
int zeppoo_fwrite_memory(unsigned long, void *, int);

/******************* KMEM *************************/

void init_kmem_k24(void);
void init_kmem_k26(void);

void openkmem_k24();
void openkmem_k26();
void closekmem();
int readkmem(unsigned long, void *, int);
int writekmem(unsigned long, void *, int);

/******************* MEM ************************/

struct page_offset{
        unsigned long realmask;
	unsigned long mask;
	unsigned long rmask;
};

void init_mem_k24(void);
void init_mem_k26(void);
void openmem();
void closemem();
int readmem(unsigned long, void *, int);
int writemem(unsigned long, void *, int);

/****************** TASKS ***********************/

#define BUFBINFINGER 64

typedef struct Binfmt pBinfmt;
typedef struct NameBinfmt pNameBinfmt;

struct Binfmt{
	unsigned long format;
	unsigned long next;
	unsigned long module;
	unsigned long load_binary;
	unsigned long load_shlib;
	unsigned long core_dump;
	
	char *md5sum_loadbinary;
	char *md5sum_loadshlib;
	char *md5sum_coredump;

	pNameBinfmt *name;
};

struct NameBinfmt{
	char name_format[64];
	char name_next[64];
	char name_module[64];
	char name_load_binary[64];
	char name_load_shlib[64];
	char name_core_dump[64];
};

struct task {
	void (*vInitTaskInfo)(void);
	void (*vGetTasks)(pTable *);
	
	int offset_list;
        int offset_pid;
	int offset_uid;
};

struct task zeptasks;

struct offsets {
	int name;
	int list;
	int binfmt;
	int pid;
	int uid;
};

struct TaskInfo{
	unsigned long init_task;
	unsigned long first_addr;
	int offset_name;
	int offset_list;
	int offset_next;
	int offset_pid;
	int offset_uid;
	int offset_binfmt;
};

typedef struct TaskInfo pTaskInfo;

pTaskInfo zeptaskinfo;

struct Task{
	char name[16];
	int pid;
	int uid;
	int gid;
	int rec;
	unsigned long addr;
	pBinfmt mybin_fmt;
};

typedef struct Task pTask;

void zeppoo_init_tasks(void);
void init_tasks_k26(void);
void init_tasks_k24(void);

void free_task(pTask *);

int find_offset_next_k26(char *, size_t);
int find_offset_name_k26(char *, size_t);
int find_offset_list_k26(char *, size_t);
int find_offset_binfmt_k26(char *, size_t);
int find_offset_pid_k26(char *, size_t);
int find_offset_uid_k26(char *, size_t);

void zeppoo_init_taskInfo(void);
void zeppoo_get_tasks(pTable *);
int zeppoo_get_task(int, pTask *);

void init_taskInfo_k26(void);
void get_tasks_k26(pTable *);

/********************* SYSCALLS *********************/

#define BUFSYSFINGER 64

typedef struct Syscall pSyscall;

struct syscalls {
	unsigned long (*vGetSyscallTable)(void);
	unsigned long (*vGetSyscall)(int num);
	int (*vGetSyscalls)(pTable *);
	void (*vGetSyscallMd5sum)(pSyscall *, char *, size_t);
	int (*vResolveSyscalls)(pTable *, char *);
	void (*vGetSyscallsOpcodes)(pTable *);

	unsigned long system_call;
	unsigned long sys_call_table;
};

struct syscalls zepsyscalls;

struct Syscall{
	int pos;
	unsigned long addr;
	char name[64];
};

void free_syscall(pSyscall *);

void zeppoo_init_syscalls(void);
void init_syscalls_kgeneric(void);

unsigned long zeppoo_get_syscalltable(void);
unsigned long zeppoo_get_syscall(int);
int zeppoo_get_syscalls(pTable *);
void zeppoo_get_syscall_md5sum(pSyscall *, char *, size_t);
int zeppoo_resolve_syscalls(pTable *, char *);

unsigned long get_syscalltable_i386(void);
unsigned long get_syscalltable_amd64(void);
unsigned long get_syscall_kgeneric(int);
int get_syscalls_kgeneric(pTable *);
void get_syscall_md5sum_kgeneric(pSyscall *, char *, size_t);
int resolve_syscalls_kgeneric(pTable *, char *);
	
/******************** IDT ****************************/

#define BUFIDTFINGER 64

typedef struct DescIdt pDescIdt;

struct idt {
	int (*vGetIdt)(pTable *);
	int (*vResolveIdt)(pTable *, char *);
	void (*vGetIdtMd5sum)(pDescIdt *, char *, size_t);
};

struct idt zepidt;

struct DescIdt {
	int pos;
	unsigned long stub_addr;
	char name[64];
};

void free_didt(pDescIdt *);

void zeppoo_init_idt(void);
void init_idt_kgeneric(void);

int zeppoo_get_idt(pTable *);
int zeppoo_resolve_idt(pTable *, char *);
void zeppoo_get_idt_md5sum(pDescIdt *, char *, size_t);

int get_idt_kgeneric(pTable *);
int resolve_idt_kgeneric(pTable *, char *);
void get_idt_md5sum_kgeneric(pDescIdt *, char *, size_t);

/****************** SYMBOLS *********************/

#define PROC_ROOT_INO			0x01
#define PROC_ROOT_NOTHING		0x00
#define PROC_ROOT_NAMELEN		0x05
#define PROC_ROOT_MODE			0x6d

typedef struct SymbolInfo pSymbolInfo;
typedef struct KernelSym pKernelSym;
typedef struct KernelSyms pKernelSyms;

struct symbol {
	unsigned long (*vFindInitTask)(void); 
	unsigned long (*vLookupRoot)(void);
	
	int proc_root_operations;
	int proc_root_readdir;
	char get_tgid_list;				
};

struct symbol zepsymb;

typedef struct Symbol pSymbol;

struct SymbolInfo{
        unsigned long system_call;
        unsigned long sys_call_table;
};

pSymbolInfo zepsymbolinfo;

struct KernelSym{
	char *caller;
	char *callee;
	int number;
	int r;
	unsigned char prefix;
	unsigned long start;
	unsigned long address;
	unsigned long naddress;
	
	int resolved;
	
	int hijack;
};

struct KernelSyms{
	char *name;
	int pos;
	int hijack;
	pKernelSym *ksym;
};

struct Symbol{
	unsigned long addr;
	char name[64];
};

void zeppoo_init_symb(void);
void init_symb_k26(void);
void init_symb_k24(void);

unsigned long zeppoo_lookup_root(void);
unsigned long zeppoo_find_init_task(void);

unsigned long lookup_root_k26(void);
unsigned long find_init_task_k26(void);

unsigned long zeppoo_walk_tree(pKernelSym *);
unsigned long zeppoo_walk_krstab(char *, void *, int);
void zeppoo_resolve_listsymbols(pKernelSyms []);
int zeppoo_get_symbols(FILE *file);

/**************** BINARIES *****************/

struct binary {
	int pid;
	int status;
	
	int fd;
	unsigned long base;
	char path[256];
	char image[1024];
	size_t imageSize;

	void *format;
};

struct elf_format {
	Elf32_Ehdr elfHeader;
	struct link_map lm;
	unsigned long got;
	unsigned long rel_plt;
	unsigned long strtab;
	unsigned long symtab;

	int rel_plt_size;
	int nchains;
};

struct binaries {
	void (*vAttach)(struct binary *);
	void (*vDetach)(struct binary *);
	void (*vRead)(struct binary *, unsigned long, void *, size_t);
//	void (*vWrite)(void);	


	void (*vGetBinfmt)(pTask *);
	void (*vGetBinfmts)(pTable *);
	void (*vGetBinfmtMd5sum)(pBinfmt *);
	void (*vGetBinfmtsMd5sum)(pTable *);
	int (*vResolveBinfmts)(pTable *, char *);
};


struct binaries zepbin;

void free_binfmt(pBinfmt *);

void zeppoo_init_binaries(void);
void zeppoo_init_binaries_trace(int);

void init_binaries_mem(void);
void init_binaries_ptrace(void);
void init_binaries_k26(void);
void init_binaries_k24(void);

void zeppoo_binary_attach(struct binary *);
void zeppoo_binary_detach(struct binary *);
void zeppoo_binary_read(struct binary *, unsigned long, void *, size_t);
void zeppoo_locate_linkmap(struct binary *);
void zeppoo_resolv_tables(struct binary *);
unsigned long zeppoo_find_sym_in_tables(struct binary *, char *);

void ptrace_attach(struct binary *);
void ptrace_detach(struct binary *);
void ptrace_read(struct binary *, unsigned long, void *, size_t);


void zeppoo_get_binfmt(pTask *);
void zeppoo_get_binfmts(pTable *);
void zeppoo_get_binfmts_md5sum(pTable *);
void zeppoo_get_binfmt_md5sum(pBinfmt *);
int zeppoo_resolve_binfmts(pTable *, char *);

void get_binfmt_k26(pTask *);
void get_binfmts_k26(pTable *);
void get_binfmts_md5sum_kgeneric(pTable *);
void get_binfmt_md5sum_kgeneric(pBinfmt *);
int resolve_binfmts_kgeneric(pTable *, char *);

/****************** VFS *********************/

struct Sops{
	char name[64];
	unsigned long fs_sops;
	unsigned long fs_read_inodes;

	unsigned long fs_dir_operations;
	unsigned long fs_readdir;
		
	char md5sum_read_inodes[BUFIDTFINGER];
	char md5sum_readdir[BUFIDTFINGER];
};

typedef struct Sops pSops;

struct vfs {
	void (*vGetVfs)(pTable *, char *);
	void (*vGetVfsMd5sum)(pTable *);
	void (*vGetExt3)(pSops *);
};

struct vfs zepvfs;

void free_sops(pSops *);

void zeppoo_init_vfs(void);
void init_vfs_k26(void);
void init_vfs_k24(void);

void zeppoo_get_vfs(pTable *, char *);
void zeppoo_get_vfs_md5sum(pTable *);
void zeppoo_get_ext3(pSops *);

void get_vfs_k26(pTable *, char *);
void get_vfs_md5sum_kgeneric(pTable *);
void get_ext3_k26(pSops *);

#endif
