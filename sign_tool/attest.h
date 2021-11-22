#ifndef _ATTEST_H
#define _ATTEST_H

#include "penglai-enclave-page.h"

void hash_enclave(unsigned long entry_point, enclave_mem_t* enclave_mem, void* hash, uintptr_t nonce_arg);

void update_enclave_hash(char *output, void* hash, uintptr_t nonce_arg);

// void sign_enclave(void* signature, void* hash);

// int verify_enclave(void* signature, void* hash);

#endif
