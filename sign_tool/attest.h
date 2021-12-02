#ifndef _ATTEST_H
#define _ATTEST_H

#include "param.h"
#include "penglai-enclave-page.h"

/****************************************************************************
* Definitions for enclave signature
****************************************************************************/
typedef struct _enclave_css_t {        /* 160 bytes */
    unsigned char enclave_hash[HASH_SIZE];          /* (32) */
    unsigned char signature[SIGNATURE_SIZE];        /* (64) */
    unsigned char user_pub_key[PUBLIC_KEY_SIZE];    /* (64) */
} enclave_css_t;

void hash_enclave(unsigned long entry_point, enclave_mem_t* enclave_mem, void* hash, uintptr_t nonce_arg);

int parse_key_file(void* prikey, void* pubkey);

void sign_enclave(struct signature_t* signature, void* hash, void* prikey);

int verify_enclave(struct signature_t* signature, void* hash, void* pubkey);

#endif
