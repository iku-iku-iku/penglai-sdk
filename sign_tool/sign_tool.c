#include <stdio.h>
#include <stdlib.h>
// #include <linux/log2.h> linux/log2.h: No such file or directory
#include "math.h"
#include "penglai-enclave.h"
#include "param.h"
#include "penglai-enclave-elfloader.h"
#include "attest.h"
#include "riscv64.h"

#define DEFAULT_CLOCK_DELAY 100000
#define STACK_POINT 0x0000004000000000
#define DEFAULT_UNTRUSTED_PTR   0x0000001000000000
#define ENCLAVE_DEFAULT_KBUFFER_SIZE              0x1000UL
#define ENCLAVE_DEFAULT_KBUFFER         0xffffffe000000000UL
#define MD_SIZE 64
#define MAX_ELF_SIZE 512*1024*1024
#define MAX_STACK_SIZE 64*1024*1024
#define MAX_UNTRUSTED_MEM_SIZE 16*1024*1024

#define PAGE_UP(addr)	(((addr)+((RISCV_PGSIZE)-1))&(~((RISCV_PGSIZE)-1)))
#define PAGE_DOWN(addr)	((addr)&(~((RISCV_PGSIZE)-1)))

void printHex(unsigned char *c, int n)
{
	int i;
	for (i = 0; i < n; i++) {
		printf("0x%02X, ", c[i]);
		if ((i%4) == 3)
		    printf(" ");

		if ((i%16) == 15)
		    printf("\n");
	}
	if ((i%16) != 0)
		printf("\n");
}

unsigned int total_enclave_page(int elf_size, int stack_size)
{
	unsigned int total_pages;
	total_pages = PAGE_UP(elf_size) / RISCV_PGSIZE + PAGE_UP(stack_size) / RISCV_PGSIZE + 15;
	return total_pages;
}

int alloc_umem(unsigned long untrusted_mem_size, unsigned long* untrusted_mem_ptr, enclave_mem_t* enclave_mem)
{
	int ret = 0;
	char* addr = (char*)malloc(untrusted_mem_size + RISCV_PGSIZE);
	if(!addr)
	{
		printf("KERNEL MODULE: can not alloc untrusted mem \n");
		return -1;
	}

    vaddr_t page_addr = (vaddr_t)PAGE_UP((unsigned long)addr);
    memset((void*)page_addr, 0, untrusted_mem_size);
	*untrusted_mem_ptr = page_addr;
	map_untrusted_mem(enclave_mem, DEFAULT_UNTRUSTED_PTR, page_addr, untrusted_mem_size);

	return ret;
}

int alloc_kbuffer(unsigned long kbuffer_size, unsigned long* kbuffer_ptr, enclave_mem_t* enclave_mem)
{
	int ret = 0;
    kbuffer_size = 0x1 << (ilog2(kbuffer_size - 1) + 1);
    char* addr = (char*)malloc(kbuffer_size + RISCV_PGSIZE);
	if(!addr)
	{
		printf("KERNEL MODULE: can not alloc untrusted mem \n");
		return -1;
	}

    vaddr_t page_addr = (vaddr_t)PAGE_UP((unsigned long)addr);
    memset((void*)page_addr, 0, kbuffer_size);
	*kbuffer_ptr = page_addr;
	map_kbuffer(enclave_mem, ENCLAVE_DEFAULT_KBUFFER, page_addr, kbuffer_size);

	return ret;
}

int penglai_enclave_create(struct penglai_enclave_user_param* enclave_param)
{
	void *elf_ptr = (void*)enclave_param->elf_ptr;
	int elf_size = 0;
	if(penglai_enclave_elfmemsize(elf_ptr, &elf_size) < 0)
	{
		printf("KERNEL MODULE: calculate elf_size failed\n");
		return -1;
	}
	printf("[penglai_enclave_create] elf size: %d\n", elf_size);
	
    long stack_size = enclave_param->stack_size;
	long untrusted_mem_size = enclave_param->untrusted_mem_size;
	unsigned long untrusted_mem_ptr = enclave_param->untrusted_mem_ptr;
	unsigned long kbuffer_ptr = ENCLAVE_DEFAULT_KBUFFER;
	unsigned int total_pages = total_enclave_page(elf_size, stack_size);
	unsigned long free_mem, elf_entry;
	unsigned long order = ilog2(total_pages- 1) + 1;

	total_pages = 0x1 << order;
	if((elf_size > MAX_ELF_SIZE) || (stack_size > MAX_STACK_SIZE) || (untrusted_mem_size > MAX_UNTRUSTED_MEM_SIZE)){
        printf("KERNEL MODULE: eapp memory is out of bound \n");
		return -1;
    }
    printf("[penglai_enclave_create] total_pages: %d\n", total_pages);
	
    enclave_mem_t* enclave_mem = malloc(sizeof(enclave_mem_t));
    int size = total_pages * RISCV_PGSIZE;
    char* addr = (char*)malloc(size + RISCV_PGSIZE);
    if(!addr)
	{
		printf("KERNEL MODULE: can not alloc untrusted mem \n");
		return -1;
	}
    vaddr_t page_addr = (vaddr_t)PAGE_UP((unsigned long)addr);
    // memset(addr, 0, size * sizeof(char));
	enclave_mem_int(enclave_mem, page_addr, size, page_addr);
    
    elf_entry = 0;
	if(penglai_enclave_eapp_preprare(enclave_mem, elf_ptr, elf_size,
				&elf_entry, STACK_POINT, stack_size))
	{
		printf("KERNEL MODULE: penglai_enclave_eapp_preprare is failed\n");
	}
	if(elf_entry == 0)
	{
		printf("KERNEL MODULE: elf_entry reset is failed \n");
	}

    untrusted_mem_size = 0x1 << (ilog2(untrusted_mem_size - 1) + 1);
	if((untrusted_mem_ptr == 0) && (untrusted_mem_size > 0))
	{
		alloc_umem(untrusted_mem_size, &untrusted_mem_ptr, enclave_mem);
	}
	alloc_kbuffer(ENCLAVE_DEFAULT_KBUFFER_SIZE, &kbuffer_ptr, enclave_mem);

    unsigned char enclave_hash[HASH_SIZE];
    unsigned char output_hash[HASH_SIZE];
    // uintptr_t nonce = 12345;
    hash_enclave(elf_entry, enclave_mem, (void*)enclave_hash, 0);
	// update_enclave_hash((char *)output_hash, (char *)enclave_hash, nonce);
    printf("[penglai_enclave_create] hash with nonce: \n");
    printHex(enclave_hash, HASH_SIZE);
    // printHex(output_hash, HASH_SIZE);
    
    free(addr);
    return 0;
}


int main(int argc, char* argv[])
{
    printf("hello world\n");
	if(argc <= 1)
    {
        printf("Please input the enclave ELF file name\n");
    }
    struct elf_args* enclaveFile = malloc(sizeof(struct elf_args));
    char * eappfile = argv[1];
    
	printf("sign file: %s\n", eappfile);
    elf_args_init(enclaveFile, eappfile);
    if(!elf_valid(enclaveFile))
    {
        printf("error when initializing enclaveFile\n");
        goto out;
    }
    struct PLenclave* enclave = malloc(sizeof(struct PLenclave)); 
    struct enclave_args* params = malloc(sizeof(struct enclave_args)); 
    PLenclave_init(enclave);
    enclave_param_init(params);
    params->untrusted_mem_size = DEFAULT_UNTRUSTED_SIZE;
    params->untrusted_mem_ptr = 0;
    // if(PLenclave_create(enclave, enclaveFile, params) < 0 )
    // {
    //     printf("host:%d: failed to create enclave\n");
    //     pthread_exit((void*)0);
    // }
    enclave->user_param.elf_ptr = (unsigned long)enclaveFile->ptr;
    enclave->user_param.elf_size = enclaveFile->size;
    enclave->user_param.stack_size = params->stack_size;
    enclave->user_param.untrusted_mem_ptr = params->untrusted_mem_ptr;
    enclave->user_param.untrusted_mem_size = params->untrusted_mem_size;
    enclave->user_param.ocall_buf_size = 0;
    enclave->user_param.resume_type = 0;

    penglai_enclave_create(&enclave->user_param);

    printf("end\n");
    free(enclave);
    free(params);

out:
    elf_args_destroy(enclaveFile);
    free(enclaveFile);
    return 0;
}
