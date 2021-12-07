#include <stdio.h>
#include <stdlib.h>
// #include <linux/log2.h> linux/log2.h: No such file or directory
#include "math.h"
#include "penglai-enclave.h"
#include "param.h"
#include "penglai-enclave-elfloader.h"
#include "attest.h"
#include "riscv64.h"
#include "util.h"
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <assert.h>
#include "gm/sm2.h"

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

typedef enum _file_path_t
{
    ELF = 0,
    KEY = 1,
    OUTPUT,
    SIG,
    UNSIGNED,
    DUMPFILE
} file_path_t;

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
		printf("SIGN_TOOL: can not alloc untrusted mem \n");
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
		printf("SIGN_TOOL: can not alloc untrusted mem \n");
		return -1;
	}

    vaddr_t page_addr = (vaddr_t)PAGE_UP((unsigned long)addr);
    memset((void*)page_addr, 0, kbuffer_size);
	*kbuffer_ptr = page_addr;
	map_kbuffer(enclave_mem, ENCLAVE_DEFAULT_KBUFFER, page_addr, kbuffer_size);

	return ret;
}

int penglai_enclave_create(struct penglai_enclave_user_param* enclave_param, enclave_css_t* enclave_css, unsigned long* meta_offset_arg)
{
	void *elf_ptr = (void*)enclave_param->elf_ptr;
	int elf_size = 0;
	if(penglai_enclave_elfmemsize(elf_ptr, &elf_size) < 0)
	{
		printf("SIGN_TOOL: calculate elf_size failed\n");
		return -1;
	}
	printf("[penglai_enclave_create] elf size: %d\n", elf_size);
	
    long stack_size = enclave_param->stack_size;
	long untrusted_mem_size = enclave_param->untrusted_mem_size;
	unsigned long untrusted_mem_ptr = enclave_param->untrusted_mem_ptr;
	unsigned long kbuffer_ptr = ENCLAVE_DEFAULT_KBUFFER;
	unsigned int total_pages = total_enclave_page(elf_size, stack_size);
	unsigned long free_mem, elf_entry, meta_offset, meta_blocksize;
	unsigned long order = ilog2(total_pages- 1) + 1;

	total_pages = 0x1 << order;
	if((elf_size > MAX_ELF_SIZE) || (stack_size > MAX_STACK_SIZE) || (untrusted_mem_size > MAX_UNTRUSTED_MEM_SIZE)){
        printf("SIGN_TOOL: eapp memory is out of bound \n");
		return -1;
    }
    printf("[penglai_enclave_create] total_pages: %d\n", total_pages);
	
    enclave_mem_t* enclave_mem = malloc(sizeof(enclave_mem_t));
    int size = total_pages * RISCV_PGSIZE;
    char* addr = (char*)malloc(size + RISCV_PGSIZE);
    if(!addr)
	{
		printf("SIGN_TOOL: can not alloc untrusted mem \n");
		return -1;
	}
    vaddr_t page_addr = (vaddr_t)PAGE_UP((unsigned long)addr);
    // memset(addr, 0, size * sizeof(char));
	enclave_mem_int(enclave_mem, page_addr, size, page_addr);
    
    elf_entry = 0;
	if(penglai_enclave_eapp_preprare(enclave_mem, elf_ptr, elf_size,
				&elf_entry, STACK_POINT, stack_size, &meta_offset, &meta_blocksize))
	{
		printf("SIGN_TOOL: penglai_enclave_eapp_preprare is failed\n");
	}
	if(elf_entry == 0)
	{
		printf("SIGN_TOOL: elf_entry reset is failed \n");
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
    
	memcpy(enclave_css->enclave_hash, enclave_hash, HASH_SIZE);
	*meta_offset_arg = meta_offset;

    free(addr);
    return 0;
}

int update_metadata(const char *path, const enclave_css_t *enclave_css, uint64_t meta_offset)
{
    if(path == NULL || enclave_css == NULL){
		printf("SIGN_TOOL: can not alloc untrusted mem \n");
		return -1;
	};

	FILE *fd = fopen(path, "rb+");
	if(fd == NULL){
		printf("open file failed\n");
		return -1;
	}
	fseek(fd, meta_offset, 0);
	int count = fwrite(enclave_css, sizeof(enclave_css_t),1, fd);
    fclose(fd);
	if(count != 1){
		printf("write byte number is wrong: num: %d\n", count);
		return -1;
	}
	
	return 0;
}

int read_metadata(const char *path, enclave_css_t *enclave_css, uint64_t meta_offset)
{
    if(path == NULL || enclave_css == NULL){
		printf("SIGN_TOOL: can not alloc untrusted mem \n");
		return -1;
	};

	FILE *fd = fopen(path, "rb");
	if(fd == NULL){
		printf("open file failed\n");
		return -1;
	}
	fseek(fd, meta_offset, 0);
	int count = fread(enclave_css, sizeof(enclave_css_t), 1, fd);
    fclose(fd);
	if(count != 1){
		printf("read byte number is wrong: num: %d\n", count);
		return -1;
	}
	
	return 0;
}

static bool cmdline_parse(unsigned int argc, char *argv[], int *mode, const char **path)
{
    assert(mode!=NULL && path != NULL);
    if(argc<2)
    {
        printf("SIGN_TOOL: Lack of parameters.\n");
        return false;
    }
    if(argc == 2 && !strcmp(argv[1], "-help"))
    {
         printf(USAGE_STRING);
         *mode = -1;
         return true;
    }
    
    enum { PAR_REQUIRED, PAR_OPTIONAL, PAR_INVALID };
    typedef struct _param_struct_{
        const char *name;          //options
        char *value;               //keep the path
        int flag;                  //indicate this parameter is required(0), optional(1) or invalid(2)
    }param_struct_t;               //keep the parameter pairs

    param_struct_t params_sign[] = {
        {"-enclave", NULL, PAR_REQUIRED},
        {"-key", NULL, PAR_REQUIRED},
        {"-out", NULL, PAR_REQUIRED},
        {"-sig", NULL, PAR_INVALID},
        {"-unsigned", NULL, PAR_INVALID},
        {"-dumpfile", NULL, PAR_OPTIONAL}};
    param_struct_t params_gendata[] = {
        {"-enclave", NULL, PAR_REQUIRED},
        {"-key", NULL, PAR_INVALID},
        {"-out", NULL, PAR_REQUIRED},
        {"-sig", NULL, PAR_INVALID},
        {"-unsigned", NULL, PAR_INVALID},
        {"-dumpfile", NULL, PAR_INVALID}};
    param_struct_t params_catsig[] = {
        {"-enclave", NULL, PAR_REQUIRED},
        {"-key", NULL, PAR_REQUIRED},
        {"-out", NULL, PAR_REQUIRED},
        {"-sig", NULL, PAR_REQUIRED},
        {"-unsigned", NULL, PAR_REQUIRED},
        {"-dumpfile", NULL, PAR_OPTIONAL}};
    param_struct_t params_dump[] = {
        {"-enclave", NULL, PAR_REQUIRED},
        {"-key", NULL, PAR_INVALID},
        {"-out", NULL, PAR_INVALID},
        {"-sig", NULL, PAR_INVALID},
        {"-unsigned", NULL, PAR_INVALID},
        {"-dumpfile", NULL, PAR_REQUIRED}};

    const char *mode_m[] ={"sign", "gendata","catsig", "dump"};
    param_struct_t *params[] = {params_sign, params_gendata, params_catsig, params_dump};
    
	unsigned int tempidx=0;
    for(; tempidx<sizeof(mode_m)/sizeof(mode_m[0]); tempidx++)
    {
        if(!strcmp(mode_m[tempidx], argv[1]))//match
        {
            break;
        }
    }
    unsigned int tempmode = tempidx;
    if(tempmode>=sizeof(mode_m)/sizeof(mode_m[0]))
    {
        printf("Cannot recognize the command \"%s\".\nCommand \"sign/gendata/catsig\" is required.\n", argv[1]);
        return false;
    }

    unsigned int params_count = (unsigned)(sizeof(params_sign)/sizeof(params_sign[0]));
    for(unsigned int i=2; i<argc; i++)
    {
        unsigned int idx = 0;
        for(; idx<params_count; idx++)
        {
            if(strcmp(argv[i], params[tempmode][idx].name)==0) //match
            {
                if((i<argc-1)&&(strncmp(argv[i+1], "-", 1)))  // assuming pathname doesn't contain "-"
                {
                    if(params[tempmode][idx].value != NULL)
                    {
                        printf("Repeatly specified \"%s\" option.\n", params[tempmode][idx].name);
                        return false;
                    }
                    params[tempmode][idx].value = argv[i+1];
                    i++;
                    break;
                }
                else     //didn't match: 1) no path parameter behind option parameter 2) parameters format error.
                {
                    printf("The File name is not correct for \"%s\" option.\n", params[tempmode][idx].name);
                    return false;
                }
            }
        }
        if(idx == params_count)
        {
            printf("Cannot recognize the option \"%s\".\n", argv[i]);
            return false;
        }
    }

    for(unsigned int i = 0; i < params_count; i++)
    {
        if(params[tempmode][i].flag == PAR_REQUIRED && params[tempmode][i].value == NULL)
        {
            printf("Option \"%s\" is required for the command \"%s\".\n", params[tempmode][i].name, mode_m[tempmode]);
            return false;
        }
        if(params[tempmode][i].flag == PAR_INVALID && params[tempmode][i].value != NULL)
        {
            printf("Option \"%s\" is invalid for the command \"%s\".\n", params[tempmode][i].name, mode_m[tempmode]);
            return false;
        }
    }
    
    for(unsigned int i = 0; i < params_count-1; i++)
    {
        if(params[tempmode][i].value == NULL)
            continue;
        for(unsigned int j=i+1; j < params_count; j++)
        {
            if(params[tempmode][j].value == NULL)
                continue;
            if(strlen(params[tempmode][i].value) == strlen(params[tempmode][j].value) &&
                !strncmp(params[tempmode][i].value, params[tempmode][j].value, strlen(params[tempmode][i].value)))
            {
                printf("Option \"%s\" and option \"%s\" are using the same file path.\n", params[tempmode][i].name, params[tempmode][j].name);
                return false;
            }
        }
    }
    // Set output parameters
    for(unsigned int i = 0; i < params_count; i++)
    {
        path[i] = params[tempmode][i].value;
    }

    *mode = tempmode;
    return true;
}

void generate_key_pair(char* pub_key, char* priv_key){
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_sm2);
    assert(1==EC_KEY_generate_key(ec_key));
    assert(1==EC_KEY_check_key(ec_key));

    BIO * bio = BIO_new_fp(stdout,0);
    assert(1==EC_KEY_print(bio, ec_key, 0));
    BIO_free(bio);

    {
        FILE * f = fopen(pub_key,"w");
        PEM_write_EC_PUBKEY(f, ec_key);
        //PEM_write_bio_EC_PUBKEY(bio, ec_key);
        fclose(f);
    }

    {
        FILE * f = fopen(priv_key,"w");
        PEM_write_ECPrivateKey(f,ec_key, NULL,NULL,0,NULL,NULL);
        //PEM_write_bio_ECPrivateKey(bio,ec_key, NULL,NULL,0,NULL,NULL);
        fclose(f);
    }

    EC_KEY_free(ec_key);

    // BIO * bio_out = BIO_new_fp(stdout,0);
    // EVP_PKEY *key = NULL;
    // OSSL_PARAM params[2];
    // EVP_PKEY_CTX *gctx =
    //     EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    // EVP_PKEY_keygen_init(gctx);

    // params[0] = OSSL_PARAM_construct_utf8_string("group", "SM2", 0);
    // params[1] = OSSL_PARAM_construct_end();
    // EVP_PKEY_CTX_set_params(gctx, params);

    // EVP_PKEY_generate(gctx, &key);

    // EVP_PKEY_print_private(bio_out, key, 0, NULL);

    // EVP_PKEY_free(key);
    // EVP_PKEY_CTX_free(gctx);
}

void get_key_pair(char* pub_key, char* priv_key){
    printf("\nread pri key:\n");
    FILE * f = fopen(priv_key, "r");
    EC_KEY *ec_key = PEM_read_ECPrivateKey(f,NULL,NULL,NULL);
    fclose(f);
    assert(1==EC_KEY_check_key(ec_key));
    BIO * bio = BIO_new_fp(stdout,0);
    EC_KEY_print(bio, ec_key, 0);
    EC_KEY_free(ec_key);

    // printf("read pub key:\n");
    // f = fopen(pub_key, "r");
    // ec_key = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
    // fclose(f);
    // EC_KEY_print(bio, ec_key, 0);
    // EC_KEY_free(ec_key);
}

void parse_pri_key_file(char* priv_key){
    printf("\nread pri key file:\n");
    FILE * f = fopen(priv_key, "r");
    EC_KEY *ec_key = PEM_read_ECPrivateKey(f,NULL,NULL,NULL);
    fclose(f);
    assert(1==EC_KEY_check_key(ec_key));

    BIO * bio = BIO_new(BIO_s_mem());
    EC_KEY_print(bio, ec_key, 0);
    EC_KEY_free(ec_key);

    char *line;
    line = (char*)malloc(1024);
    BIO_get_line(bio, line, 1024);
    printf("line 1:\n");
    printf("%s", line);

    memset(line, 0, 1024);
    BIO_get_line(bio, line, 1024);
    printf("line 2:\n");
    printf("%s", line);
    free(line);

    printf("calcu:\n");
    unsigned char *pri = (unsigned char*)malloc(32);
    long num = BIO_get_mem_data(bio, &line);
    unsigned char b = 0;
    int cur = 0;
    int high_bit = 1;
    int number = 0;
    char byte;
    for(int i = 0; i < num; i++){
        if(cur == 32){
            printf("ERROR: cur = 32\n");
            break;
        }
        if(line[i] == ' ' || line[i] == '\n' || line[i] == ':'){
            if(b != 0){
                pri[cur++] = b;
                b = 0;
            }
            continue;
        }
        number = 0;
        byte = line[i];
        if(byte >= '0' && byte <= '9'){
            number = byte - '0';
        } else if(byte >= 'a' && byte <= 'f'){
            number = byte - 'a' + 10;
        }
        if(high_bit){
            b += number * 16;
            high_bit = 0;
        } else{
            b += number;
            high_bit = 1;
        }
    }
    printHex(pri, 32);
    unsigned char *pub = (unsigned char*)malloc(PUBLIC_KEY_SIZE);
    sm2_make_pubkey(pri, (ecc_point *)pub);
    printf("pub key: \n");
    printHex(pub, PUBLIC_KEY_SIZE);
}

int main(int argc, char* argv[])
{
    printf("hello world\n");

	// const char *path[8] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};
	// int res = -1, mode = -1;
	// //Parse command line
    // if(cmdline_parse(argc, argv, &mode, path) == false)
    // {
    //     printf(USAGE_STRING);
    //     goto clear_return;
    // }
    // if(mode == -1) // User only wants to get the help info
    // {
    //     res = 0;
    //     goto clear_return;
    // }
	// else if(mode == DUMP)
    // {
    //     // dump metadata info
    //     if(dump_enclave_metadata(path[ELF], path[DUMPFILE]) == false)
    //     {
    //         printf("Failed to dump metadata info to file \"%s\".\n.", path[DUMPFILE]);
    //         goto clear_return;
    //     }
    //     printf("Succeed.\n");
    //     res = 0;
    //     goto clear_return;
    // }

	// if(mode == SIGN)
	// {

	// }

	// //Other modes
	// if(parse_key_file(mode, path[KEY], &rsa, &key_type) == false && key_type != NO_KEY)
    // {
    //     goto clear_return;
    // }

    generate_key_pair("pub_key.pem", "pri_key.pem");
    get_key_pair("pub_key.pem", "pri_key.pem");

    parse_pri_key_file("pri_key.pem");
    char *msg = "Helloworld shangqy\n";


    return 0;

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

	enclave_css_t enclave_css;
	unsigned long meta_offset;
    penglai_enclave_create(&enclave->user_param, &enclave_css, &meta_offset);
	elf_args_destroy(enclaveFile);

	// printf("[penglai_enclave_create] old zero metadata:\n");
	// printf("meta offset: %d\n", meta_offset);
	enclave_css_t new_css;
	// memset(&new_css, 0, sizeof(enclave_css_t));
	// read_metadata(eappfile, &new_css, meta_offset);
	// printf("[penglai_enclave_create] new signature: \n");
    // printHex(new_css.signature, SIGNATURE_SIZE);
	// printf("[penglai_enclave_create] new public_key: \n\n\n");
    // printHex(new_css.user_pub_key, PUBLIC_KEY_SIZE);

	unsigned char private_key[PRIVATE_KEY_SIZE];
	parse_key_file(private_key, enclave_css.user_pub_key);
	sign_enclave((struct signature_t *)(enclave_css.signature), enclave_css.enclave_hash, private_key);
	printf("[penglai_enclave_create] signature: \n");
    printHex(enclave_css.signature, SIGNATURE_SIZE);
	// printf("[penglai_enclave_create] private_key: \n");
    // printHex(private_key, PRIVATE_KEY_SIZE);
	printf("[penglai_enclave_create] public_key: \n");
    printHex(enclave_css.user_pub_key, PUBLIC_KEY_SIZE);
	int ret = verify_enclave((struct signature_t *)(enclave_css.signature), enclave_css.enclave_hash, enclave_css.user_pub_key);
	if(ret != 0){
		printf("ERROR: verify enclave_css struct failed!\n");
	}
	// update_metadata("prime_signed", &enclave_css, 0);
	update_metadata(eappfile, &enclave_css, meta_offset);

	printf("\n\n\n[penglai_enclave_create] new zero metadata:\n");
	printf("meta offset: %d\n", meta_offset);
	memset(&new_css, 0, sizeof(enclave_css_t));
	// read_metadata("prime_signed", &new_css, 0);
	read_metadata(eappfile, &new_css, meta_offset);
	printf("[penglai_enclave_create] new signature: \n");
    printHex(new_css.signature, SIGNATURE_SIZE);
	printf("[penglai_enclave_create] new public_key: \n");
    printHex(new_css.user_pub_key, PUBLIC_KEY_SIZE);

    printf("end\n");
    free(enclave);
    free(params);

clear_return:
out:
    elf_args_destroy(enclaveFile);
    free(enclaveFile);
    return 0;
}
