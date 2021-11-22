#include "penglai-enclave-elfloader.h"


int penglai_enclave_load_NOBITS_section(enclave_mem_t* enclave_mem, void * elf_sect_addr, int elf_sect_size)
{
	vaddr_t addr;
	vaddr_t enclave_new_page;
	int size;
	for(addr = (vaddr_t)elf_sect_addr; addr < (vaddr_t)elf_sect_addr + elf_sect_size; addr += RISCV_PGSIZE)
	{
		enclave_new_page = enclave_alloc_page(enclave_mem, addr, ENCLAVE_USER_PAGE);
		if (addr + RISCV_PGSIZE >(vaddr_t) elf_sect_addr + elf_sect_size)
			size = elf_sect_size % RISCV_PGSIZE;
		else
			size = RISCV_PGSIZE;
		memset((void *) enclave_new_page, 0, size);
	}
	return 0;
}

/* elf_prog_infile_addr @ content in elf file
   elf_prog_addr @ virtual addr for program begin addr
   elf_prog_size @ size of prog segment
   */
int penglai_enclave_load_program(enclave_mem_t* enclave_mem, vaddr_t elf_prog_infile_addr, void * elf_prog_addr, int elf_prog_size)
{
	vaddr_t addr;
	vaddr_t enclave_new_page;
	int size;
	for(addr =  (vaddr_t)elf_prog_addr; addr <  (vaddr_t)elf_prog_addr + elf_prog_size; addr += RISCV_PGSIZE)
	{

		enclave_new_page = enclave_alloc_page(enclave_mem, addr, ENCLAVE_USER_PAGE);
		if (addr + RISCV_PGSIZE > (vaddr_t)elf_prog_addr + elf_prog_size)
			size = elf_prog_size % RISCV_PGSIZE;
		else
			size = RISCV_PGSIZE;
		memcpy((void* )enclave_new_page, (void *)(elf_prog_infile_addr + addr - (vaddr_t)elf_prog_addr), size);
	}
	return 0;
}

/* ptr @ user pointer
   hdr @ kernel pointer
   */
int penglai_enclave_loadelf(enclave_mem_t*enclave_mem, void* elf_ptr, unsigned long size, vaddr_t * elf_entry_point)
{
	Elf64_Ehdr elf_hdr;
	Elf64_Phdr elf_prog_hdr;
	Elf64_Shdr elf_sect_hdr;
	int i,  elf_prog_size;
	vaddr_t elf_sect_ptr, elf_prog_ptr, elf_prog_addr, elf_prog_infile_addr;
	memcpy(&elf_hdr, elf_ptr, sizeof(Elf64_Ehdr));
	
	*elf_entry_point = elf_hdr.e_entry;
	elf_sect_ptr = (vaddr_t) elf_ptr + elf_hdr.e_shoff;

	/* Loader section */
	for (i = 0; i < elf_hdr.e_shnum;i++)
	{
		memcpy(&elf_sect_hdr,(void *)elf_sect_ptr,sizeof(Elf64_Shdr));
		
		if (elf_sect_hdr.sh_addr == 0)
		{
			elf_sect_ptr += sizeof(Elf64_Shdr);
			continue;
		}

		/* Load NOBITS section */
		if (elf_sect_hdr.sh_type == SHT_NOBITS)
		{
			vaddr_t elf_sect_addr = elf_sect_hdr.sh_addr;
			int elf_sect_size = elf_sect_hdr.sh_size;
			if (penglai_enclave_load_NOBITS_section(enclave_mem,(void *)elf_sect_addr,elf_sect_size) < 0)
			{
				printf("KERNEL MODULE: penglai enclave load NOBITS  section failed\n");
				return -1;
			}
		}
		elf_sect_ptr += sizeof(Elf64_Shdr);
	}

	/* Load program segment */
	elf_prog_ptr = (vaddr_t) elf_ptr + elf_hdr.e_phoff;

	for(i = 0; i < elf_hdr.e_phnum;i++)
	{
		memcpy(&elf_prog_hdr,(void *)elf_prog_ptr,sizeof(Elf64_Phdr));

		/* Virtual addr for program begin address */
		elf_prog_addr = elf_prog_hdr.p_vaddr;
		elf_prog_size = elf_prog_hdr.p_filesz;
		elf_prog_infile_addr = (vaddr_t) elf_ptr + elf_prog_hdr.p_offset;
		if (penglai_enclave_load_program(enclave_mem, elf_prog_infile_addr, (void *)elf_prog_addr, elf_prog_size) < 0)
		{
			printf("KERNEL MODULE: penglai enclave load program failed\n");
			return -1;
		}
		printf("[Penglai Driver@%s] elf_prog_addr:0x%lx elf_prog_size:0x%x, infile_addr:0x%lx", __func__,
				elf_prog_addr, elf_prog_size, elf_prog_infile_addr);
		elf_prog_ptr += sizeof(Elf64_Phdr);
	}
	return 0;
}

int penglai_enclave_eapp_preprare(enclave_mem_t* enclave_mem,  void* elf_ptr, unsigned long size, vaddr_t * elf_entry_point, vaddr_t stack_ptr, int stack_size)
{
	vaddr_t addr;

	/* Init stack */
	for(addr = stack_ptr - stack_size; addr < stack_ptr; addr += RISCV_PGSIZE)
	{
		enclave_alloc_page(enclave_mem, addr, ENCLAVE_STACK_PAGE);
	}

	/* Load elf file */
	if(penglai_enclave_loadelf(enclave_mem, elf_ptr, size, elf_entry_point) < 0)
	{
		printf("KERNEL MODULE: penglai enclave loadelf failed\n");
	}

	return 0;
}

int penglai_enclave_elfmemsize(void* elf_ptr, int* size)
{
	Elf64_Ehdr elf_hdr;
	Elf64_Phdr elf_prog_hdr;
	Elf64_Shdr elf_sect_hdr;
	int i, elf_prog_size;
	vaddr_t elf_sect_ptr, elf_prog_ptr;
	memcpy(&elf_hdr, elf_ptr, sizeof(Elf64_Ehdr));

	elf_sect_ptr = (vaddr_t) elf_ptr + elf_hdr.e_shoff;

	for (i = 0; i < elf_hdr.e_shnum;i++)
	{
		memcpy(&elf_sect_hdr,(void *)elf_sect_ptr,sizeof(Elf64_Shdr));
		if (elf_sect_hdr.sh_addr == 0)
		{
			elf_sect_ptr += sizeof(Elf64_Shdr);
			continue;
		}

		// Calculate the size of the NOBITS section
		if (elf_sect_hdr.sh_type == SHT_NOBITS)
		{
			int elf_sect_size = elf_sect_hdr.sh_size;
			*size = *size + elf_sect_size;
		}
		elf_sect_ptr += sizeof(Elf64_Shdr);
	}

	// Calculate the size of the PROGBITS segment
	elf_prog_ptr = (vaddr_t) elf_ptr + elf_hdr.e_phoff;

	for(i = 0; i < elf_hdr.e_phnum;i++)
	{
		memcpy(&elf_prog_hdr,(void *)elf_prog_ptr,sizeof(Elf64_Phdr));

		// Virtual addr for program begin address
		elf_prog_size = elf_prog_hdr.p_filesz;
		*size = *size + elf_prog_size;
		elf_prog_ptr += sizeof(Elf64_Phdr);
	}
	return 0;
}
