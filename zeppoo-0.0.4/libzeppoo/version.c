/******************************************************************************/
/* version.c  -- see http://www.zeppoo.net                                    */
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

float deletedot(char *chaine, size_t size){
	int i,j;
	float vkern;
	char kernel[size];
	i = j = 0;

	if((strstr(chaine, "."))){
		while(chaine[i] != '.' && i < size){
			kernel[j] = chaine[i];
			j++;
			i++;
		}
		kernel[j] = '.';
		j++;
		while(chaine[i] != '\0' && i < size){
			if(chaine[i] != '.'){
				kernel[j] = chaine[i];
				j++;
			}
		
			i++;
		}
		kernel[j] = '\0';
		vkern = atof(kernel);
	}
	return vkern;
}	

void zeppoo_init_version(int uselkm){
	struct utsname info;

	uname(&info);
	printf("Kernel : %s\n", info.release);

	zepversion.kernel = deletedot(info.release, strlen(info.release));

#ifdef _DEBUG_
	printf("Kernel : %f\n", zepversion.kernel);
#endif

	memcpy(zepversion.archi, info.machine, sizeof(zepversion.archi));	
	if(strstr(zepversion.archi, "i")){
#ifdef _DEBUG_
		printf("proc : i386\n");
#endif
		zepversion.arc = 0;
	}
	else if(strstr(zepversion.archi, "x86_64")){
#ifdef _DEBUG_
		printf("proc : x86_64\n");
#endif
		zepversion.arc = 1;
	}
	else{
		printf("Architecture not supported\n");
		exit(-1);
	}

	zepversion.uselkm = uselkm;
}
