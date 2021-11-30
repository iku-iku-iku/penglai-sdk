#ifndef _PENGLAI_ENCLAVE_ELFLOADER
#define _PENGLAI_ENCLAVE_ELFLOADER

#include <linux/elf.h>
#include "penglai-enclave-page.h"

int penglai_enclave_eapp_preprare(
		enclave_mem_t* enclave_mem,  
		void* elf_ptr, 
		unsigned long size, 
		vaddr_t * elf_entry_point, 
		vaddr_t stack_ptr, 
		int stack_size,
		unsigned long *meta_offset,
		unsigned long *meta_blocksize);

int penglai_enclave_elfmemsize(void* elf_ptr, int* size);

int map_untrusted_mem(
		enclave_mem_t* enclave_mem, 
		vaddr_t vaddr, 
		paddr_t paddr, 
		unsigned long size);

int map_kbuffer(
		enclave_mem_t* enclave_mem,
		vaddr_t vaddr,
		paddr_t paddr,
		unsigned long size);
#endif
