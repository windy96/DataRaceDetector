#ifndef __SESCAPI_H__
#define __SESCAPI_H__

#include <stdio.h>
#include <stdlib.h>
// is assumed.


//	Invalidation
void	inv_word(void *addr);
void	inv_dword(void *addr);
void	inv_qword(void *addr);
void	inv_range(void *addr, int size);

//	Writeback
void	wb_word(void *addr);
void	wb_dword(void *addr);
void	wb_qword(void *addr);
void	wb_range(void *addr, int size);

//	Writeback & Invalidation
void	wb_inv_word(void *addr);
void	wb_inv_dword(void *addr);
void	wb_inv_qword(void *addr);
void	wb_inv_range(void *addr, int size);

//	Load/Store Bypass
int 	ld_w_bypass(void *addr);
void	st_w_bypass(void *addr, int value);

//	[TODO] Writeback Reserve function is not implemented yet.
//	Still in investigation.
void	wb_reserve(void *addr, int size);

//	[TODO] Writefirst function is not implemented yet.
//	Still in investigation.
void	wr_first(void *addr, int size);

//	Memory Allocation
void *malloc_pmc(size_t size);
void *calloc_pmc(size_t nmemb, size_t size);
void *realloc_pmc(void *ptr, size_t size);
void free_pmc(void *ptr);
int posix_memalign_pmc(void **memptr, size_t alignment, size_t size);

//	PMC Thread Functions
typedef struct pmcthread_barrier
{
	int	cur;
	int	count;
	int polarity;
} pmcthread_barrier_t ;

void pmcthread_barrier_init(pmcthread_barrier_t *bar, int *i, int count);
int pmcthread_barrier_wait(pmcthread_barrier_t *bar);
void sesc_memfence(void *ptr);
int pthread_cond_wait_null(void *cond, void *mutex);


#endif
