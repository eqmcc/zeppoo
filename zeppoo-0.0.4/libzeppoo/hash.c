/******************************************************************************/
/* hash.c  -- see http://www.zeppoo.net                                       */
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
/*      								      */
/* HASH BASED ON LIBCX 							      */
/* http://www.capflam.org/?page_id=4 					      */
/******************************************************************************/

#include "zeppoo.h"

unsigned long fnv_32a_buf(const void *buf, size_t size, unsigned long hval){
	unsigned char *bp = (unsigned char *)buf;
	unsigned char *be = bp + size;
  

	while (bp < be){
      		hval ^= (unsigned long)*bp++; 
      		hval += (hval<<1) + (hval<<4) + (hval<<7) + (hval<<8) + (hval<<24);
    	}
  	return hval;
}

pTable *hash_new(void (*free_value)(void *)){
	pTable     *zhtable;

	zhtable = (pTable *)malloc(sizeof(struct Table));
	if(zhtable == NULL)
		zeppoo_fatal("malloc error");
	
	zhtable->first = zhtable->last = zhtable->current = NULL;
	zhtable->free_value = free_value;
	
	return zhtable;
}

void hash_delete(pTable *zhtable){
	pItem *tmp1, *tmp2;
	
	if (zhtable == NULL)
		return;
	
	tmp1 = zhtable->first;
	while(tmp1){
		tmp2 = tmp1->next;
		if (tmp1->el != NULL){
			zhtable->free_value(tmp1->el->value);
			free(tmp1->el);
		}
		free(tmp1);
		tmp1 = tmp2;
	}
	free(zhtable);
}

void hash_insert(pTable *zhtable, const void *key, size_t size, void *value){
	unsigned long hash_key;
	pElement *zhash;
	pItem *item;	 
	
	if (zhtable == NULL || key == NULL ||  value == NULL || !size)
		return;
	
	hash_key = fnv_32a_buf(key, size, 0);

	for(item = zhtable->first; item != NULL; item = item->next){
		zhash = item->el;
		if (zhash->key == hash_key)
			return;
	}

	zhash = (pElement *)malloc(sizeof(struct Element));
	if(zhash == NULL)
		zeppoo_fatal("malloc error");
	
	zhash->key = hash_key;
	zhash->value = value;

	if(zhash != NULL){
		item = (pItem *)malloc(sizeof(struct Item));
		if(item == NULL)
			zeppoo_fatal("malloc error");
		
		item->el = zhash;

		if(zhtable->first == NULL){
			zhtable->first = item;
			zhtable->current = zhtable->first;
		}
		else
			zhtable->last->next = item;

		item->next = NULL;
		zhtable->last = item;
	}
}

void hash_remove(pTable *zhtable, const void *key, size_t size){
	unsigned long hash_key;
	pElement *zhash;
	pItem *prev, *item;
	
	if(zhtable == NULL || key == NULL || !size)
		return;


	hash_key = fnv_32a_buf(key, size, 0);
	
	prev = zhtable->first;

	for(item = zhtable->first; item != NULL; item = item->next){
		zhash = item->el;

		if(zhash->key == hash_key){
			if(zhash != NULL){
				zhtable->free_value(zhash->value);
				free(zhash);
			}

			if(item == zhtable->first){
				zhtable->first = item->next;
				if(item == zhtable->current)
					zhtable->current = zhtable->first;
				
				free(item);
			}
			else if(item == zhtable->last){
				zhtable->last = prev;
				if(item == zhtable->current)
					zhtable->current = zhtable->last;

				free(item);
				prev->next = NULL;
			}
			else{
				prev->next = item->next;
				if(item == zhtable->current)
					zhtable->current = prev->next;

				free(item);
			}
		}

		prev = item;
	}
	
}

pElement *hash_get(pTable *zhtable, const void *key, size_t size){
	unsigned long hash_key;
	pElement *zhash;
	pItem *item;
	
	if (zhtable == NULL || key == NULL || !size)
		return NULL;

	hash_key = fnv_32a_buf(key, size, 0);

	for(item = zhtable->first; item != NULL; item = item->next){
		zhash = item->el;
		if (zhash->key == hash_key)
			return zhash;
		
	}
	return NULL;
}
