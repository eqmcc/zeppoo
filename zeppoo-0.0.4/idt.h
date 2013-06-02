/******************************************************************************/
/* idt.h  -- see http://www.zeppoo.net                                        */
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

#ifndef IDT_H
#define IDT_H

#include <stdio.h>
#include "libzeppoo/zeppoo.h"

void getIdtMemory(pTable *, char *);
void getIdtFingerprints(FILE *, pTable *);
void simpleViewIdt(pTable *);
void viewIdtMemory(char *);
void writeIdtMemory(FILE *, char *);
void viewHijackIdt(FILE *, char *);

#endif
