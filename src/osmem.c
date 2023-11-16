// SPDX-License-Identifier: BSD-3-Clause
#include <unistd.h>
#include <syscall.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "block_meta.h"
#include "osmem.h"
#define META_SIZE sizeof(struct block_meta)
#define MMAP_THRESHOLD (128 * 1024)
#define ALIGNMENT 8 // must be a power of 2

#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))
#define SIZE_T_SIZE ALIGN(sizeof(size_t))

int global_base2;
struct block_meta *global_base;
void coalesce_blocks(void)
{
	struct block_meta *curr = global_base;
	//sefule te plimbi in lista si ori aduni blocurile intre ele
	//ori nu faci nimic
	while (curr != NULL && curr->next != NULL) {
		if (curr->status == STATUS_FREE && curr->next->status == STATUS_FREE) {
			curr->size += curr->next->size;
			curr->next = curr->next->next;
			if (curr->next != NULL)
				curr->next->prev = curr;
		} else {
			curr = curr->next;
		}
	}
}

struct block_meta *split_block(struct block_meta *bloc, size_t size)
{
	//printf("AMI INTRAT IN SPLIT\n");
	size_t perfect_size = ALIGN(size + META_SIZE);

	if (bloc == NULL)
		return NULL;
	if (bloc->size - perfect_size < META_SIZE + 1)//aparent daca pun +1 merge si split last
		//printf("crapa 1\n");
		return NULL;

	//printf("REAL SPLIT %lu  %lu si perf_size %lu\n", size, bloc->size, perfect_size);
	//se supara aici
	struct block_meta *new_bloc = (struct block_meta *)((char *)bloc + perfect_size); // merg dincolo de payload

	new_bloc->size = abs(bloc->size - perfect_size); // ce ramane??
	bloc->size = perfect_size;
	//printf("din split size bloc si newbl: %lu %lu\n", bloc->size, new_bloc->size); // ok??!
	new_bloc->status = STATUS_FREE;
	// printf("ajung oare aiic?\n");
	new_bloc->next = bloc->next;
	new_bloc->prev = bloc;
	bloc->next = new_bloc;
	if (new_bloc->next != NULL)
		new_bloc->next->prev = new_bloc;
	return bloc;
}

void sterg_bloc(struct block_meta **head, struct block_meta *nod)
{	//sda vibes
	if (*head == NULL || nod == NULL)
		return;
	if (*head == nod) {
		nod->prev = NULL;
		*head = nod->next;
	}
	if (nod->next != NULL)
		nod->next->prev = nod->prev;
	if (nod->prev != NULL)
		nod->prev->next = nod->next;
}
struct block_meta *request_space(struct block_meta *last, size_t size)
{
	struct block_meta *bloc = sbrk(0);

	void *req = sbrk(size);

	DIE((void *)bloc != req, "sbrk failed");
	if (req == (void *)-1)
		return NULL;
	if (last == NULL) {// e primul
		bloc->next = NULL;
		bloc->prev = NULL;
	} else { // sigur ma opresc pe ultimul daca apelez find_free
		bloc->prev = last;
		bloc->next = last->next;
		last->next = bloc;
	}
	bloc->size = size;
	bloc->status = STATUS_ALLOC;
	return bloc;
}
struct block_meta *request_space_mmap(struct block_meta *last, size_t size)
{
	struct block_meta *nou = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	DIE(nou == MAP_FAILED, "mmap failed");
	if (nou == NULL)
		return NULL;
	if (last == NULL) {
		nou->next = NULL;
		nou->prev = NULL;
	} else {
		nou->prev = last;
		nou->next = last->next;
		last->next = nou;
	}
	nou->size = size;
	nou->status = STATUS_MAPPED;
	return nou;
}

struct block_meta *find_free_bloc(struct block_meta **last, size_t size)
{
	struct block_meta *curr = global_base;

	while (curr && (curr->status != STATUS_FREE || curr->size - META_SIZE < size)) {
		*last = curr;
		curr = curr->next;
	}
	//printf("cine e curr : %p\n", curr);
	if (curr == NULL)
		return NULL;
	if (curr->status == STATUS_FREE && curr->size - META_SIZE >= size)
		return curr;
	return NULL;
}
struct block_meta *expand_block(struct block_meta *block, size_t new_size)
{
	//printf("sun in expand\n");
	if (block == NULL || block->status != STATUS_FREE)
		return NULL;
	//printf("\nHEELLOOOOOOO\n");
	size_t additional_size = ALIGN(new_size - block->size + META_SIZE);

	void *c = (void *)((char *)block + block->size);

	c = sbrk(additional_size);
	//  if (c != (void *)((char *)block + block->size))
	// printf("CHESTII DIFERITE??? block : %p si %p req %ld\n",
	// block, c, (long)(c) - (long)((void *)((char *)block + block->size)));

	block->size += additional_size;
	block->status = STATUS_ALLOC;
	return block;
}
void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;

	struct block_meta *current;

	size_t block_size = ALIGN(size + META_SIZE);

	//printf("\n LUNGIME %lu  %lu**\n",size, block_size);

	if (global_base2 == 0) {
		//am inversa infurile si daca nu am facut never prealloc
		//printf("pas 1\n");
		if (size < MMAP_THRESHOLD)  {
			//prealloc
			size_t prealloc_size = 128 * 1024;

			current = request_space(NULL, prealloc_size);

			if (current == NULL)
				return NULL;
			global_base2 = 1;
			global_base = current;

			//verific daca incape sizeul asta in bloc prealocat
			//printf("size in prealloc %d %d\n", size, block_size);
			//printf("CEEE prealloc %lu si size %lu\n", current->size, block_size);
			struct block_meta *verif = global_base;
			//split_block(verif,block_size);
			//current = verif;
			current = split_block(verif, size);
			if (current == NULL) // nu mere la split

				// TE DUCI DUPA PREALLOC
				if (verif->size >= block_size) {
					verif->next = NULL;
					verif->prev = NULL;
					verif->size = block_size;
					verif->status = STATUS_ALLOC;
					global_base = verif;
					return (void *)(verif + 1);
				}

			return (void *)(current + 1);
		} else {
			//printf("pas2\n");
			if (global_base == NULL) {
				current = request_space_mmap(NULL, block_size);
				if (current == NULL)
					return NULL;
				// printf("inceput de lista\n");
				global_base = current;
			} else {
				struct block_meta *last = global_base;

				coalesce_blocks();
				current = find_free_bloc(&last, size);

			if (current == NULL) {
				if (last->status == STATUS_FREE) {
					// printf("\n INAINTE DE EXPAND %lu din last si %lu size\n", last->size, size);
					current = expand_block(last, size);
					if (current != NULL)
						return (void *)(current + 1);
				}
				current = request_space_mmap(last, block_size);
				if (current == NULL)
					return NULL;
				} else {
					current->status = STATUS_MAPPED;
				}
			}
			return (void *)(current + 1);
		}
	} else {  // globalbas2 nu e null
		// printf("AM PREALOCAT SUNT PE ELSE %lu %lu\n", size, block_size);
		if (size < MMAP_THRESHOLD) {
			struct block_meta *last = global_base;

			coalesce_blocks();
			current = find_free_bloc(&last, size);
			if (current == NULL) {
				if (last->status == STATUS_FREE) {
				//printf("\n INAINTE DE EXPAND %lu din last si %lu size\n", last->size, size);
					current = expand_block(last, size);
					if (current != NULL)
						return (void *)(current + 1);
				}
				current = request_space(last, block_size);
				//printf("adresa cureent brk: %p\n", current);
				if (current == NULL)

					return NULL;
			} else {
				current->status = STATUS_ALLOC;
				struct block_meta *copie = split_block(current, size);
				//if (copie == NULL)
				//return (void *)(current + 1);
			}
			//printf("sizeul lui current cu brk si status: %d %d\n", current->size, current->status);
			//current = split_block(current,block_size);
			return (void *)(current + 1);
		}
		size_t perfect_size = ALIGN(size + META_SIZE);
		//void *newptr = mmap(NULL, perfect_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (global_base == NULL) {
			current = request_space_mmap(NULL, perfect_size);
			if (current == NULL)
				return NULL;
			//printf("inceput de lista\n");
			global_base = current;
		} else {
			struct block_meta *last = global_base;

			coalesce_blocks();
			current = find_free_bloc(&last, size);
			if (current == NULL) {
				if (last->status == STATUS_FREE) {
					// printf("\n INAINTE DE EXPAND %lu din last si %lu size\n", last->size, size);
					current = expand_block(last, size);
					if (current != NULL)
						return (void *)(current + 1);
				}
				current = request_space_mmap(last, perfect_size);
				if (current == NULL)
					return NULL;
			} else {
				current->status = STATUS_MAPPED;
			}
		}
		return (void *)(current + 1);
	}
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	// printf("aaaaa");
	if (global_base == NULL) // nam nimic in lista
		return;
	struct block_meta *last = (struct block_meta *)ptr - 1;

	// deci daca fac cu while imi f**e cumva ultimul bloc ca nu il sterge
	if (last == NULL) // nu lam gasit??
		return;
	// printf("\nlast status free: %d status prealloc %d\n", last->status, global_base->status);
	if (last->status == STATUS_FREE)
		return; // nu dau free la ceva ce e deja free
	if (last->status == STATUS_ALLOC) {
		last->status = STATUS_FREE;
		return;
	}
	if (last->status == STATUS_MAPPED) { // dar trb sa nu pierd lista
		sterg_bloc(&global_base, last);
		int cod = munmap(last, last->size);

		DIE(cod == -1, "munmap");
		return;
	}
	return;
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total_size = nmemb * size;
	size_t perfect_size = ALIGN(total_size + META_SIZE);
	size_t treshold_size = sysconf(_SC_PAGE_SIZE);
	struct block_meta *calloc_block;

	if (perfect_size > treshold_size) {
		// calloc mai hardcore asa
		if (global_base == NULL) {
			calloc_block = request_space_mmap(NULL, perfect_size);
			global_base = calloc_block;
			memset((void *)(calloc_block + 1), 0, total_size);
			return (void *)(calloc_block + 1);
		}
		while (calloc_block->next != NULL)
			calloc_block = calloc_block->next;
		calloc_block = request_space_mmap(calloc_block, perfect_size);
		memset((void *)(calloc_block + 1), 0, total_size);
		return (void *)(calloc_block + 1);
	}
	void *ptr = os_malloc(total_size);

	if (ptr == NULL)
		return NULL;
	if (ptr != NULL)
		memset(ptr, 0, total_size);
	return ptr;
}

void *os_realloc(void *ptr, size_t size)
{
	/* TODO: Implement os_realloc */
	if (ptr == NULL) {
		return os_malloc(size);
	}
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	size_t perfect_size = ALIGN(size + META_SIZE);

	struct block_meta *bloc = (struct block_meta *)ptr - 1;

	size_t bloc_size = bloc->size;

	if (bloc->status == STATUS_FREE)
		return NULL;
	if (bloc_size >= size) {
		struct block_meta *splitted_bloc;

		splitted_bloc = split_block(bloc, size);
		return (void *)(splitted_bloc + 1);
	}
	return NULL;
}
