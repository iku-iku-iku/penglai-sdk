#include "parse_key_file.h"
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <string.h>
#include "util.h"
#include "gm/sm2.h"
#include "param.h"
#include "attest.h"

void parse_priv_key_file(const char* priv_key_file, unsigned char* priv_key, unsigned char* pub_key){
    // printf("\nread pri key file:\n");
    // FILE * f = fopen(priv_key_file, "r");
    // EVP_PKEY *pkey = PEM_read_PrivateKey(f,NULL,NULL,NULL);
    // fclose(f);
    // int pri_len;
    // EVP_PKEY_get_raw_private_key(pkey, priv_key, &pri_len);
    // printf("pri_key len: %d\n", pri_len);
    // printHex(priv_key, pri_len);

    
    printf("\nread pri key file:\n");
    FILE * f = fopen(priv_key_file, "r");
    EC_KEY *ec_key = PEM_read_ECPrivateKey(f,NULL,NULL,NULL);
    fclose(f);
    // assert(1==EC_KEY_check_key(ec_key));

    BIO * bio1 = BIO_new_fp(stdout,0);
    assert(1==EC_KEY_print(bio1, ec_key, 0));
    BIO_free(bio1);

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
    long num = BIO_get_mem_data(bio, &line);
    unsigned char b = 0;
    int cur = 0;
    int high_bit = 1;
    int number = 0;
    char byte;
    for(int i = 0; i < num; i++){
        if(cur == PRIVATE_KEY_SIZE){
            break;
        }
        if(line[i] == ' ' || line[i] == '\n' || line[i] == ':'){
            if(b != 0){
                priv_key[cur++] = b;
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
    
    sm2_make_pubkey(priv_key, (ecc_point *)pub_key);
}

void parse_pub_key_file(const char* pub_key_file, unsigned char* pub_key){
    printf("\nread pub key file:\n");
    FILE * f = fopen(pub_key_file, "r");
    EC_KEY *ec_key = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

    BIO * bio1 = BIO_new_fp(stdout,0);
    assert(1==EC_KEY_print(bio1, ec_key, 0));
    BIO_free(bio1);

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
    int skip_z = 0;
    long num = BIO_get_mem_data(bio, &line);
    unsigned char b = 0;
    int cur = 0;
    int high_bit = 1;
    int number = 0;
    char byte;
    for(int i = 0; i < num; i++){
        if(cur == PUBLIC_KEY_SIZE){
            break;
        }
        if(line[i] == ' ' || line[i] == '\n' || line[i] == ':'){
            if(b != 0){
                if(!skip_z){
                    skip_z = 1;
                    /*
                    FIXME: use b != 0 to judge isn't right
                    */
                    b = 0;
                    continue;
                }
                pub_key[cur++] = b;
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
    printHex(pub_key, PUBLIC_KEY_SIZE);
}

void parse_signature_DER(const char* sig_file, unsigned char* signature){
    ECDSA_SIG* ec_sig = ECDSA_SIG_new();

    int file_size = get_file_size(sig_file);
    if(file_size < 0){
        printf("Get file size fail.\n");
    }
    printf("file size %d\n", file_size);
    unsigned char *buf = (unsigned char *)malloc(1024);
    read_file_to_buf(sig_file, buf, file_size, 0);

    const unsigned char *p = buf;
    d2i_ECDSA_SIG(&ec_sig, &p, file_size);
    
    printf("post r  :%s\n", BN_bn2hex(ECDSA_SIG_get0_r(ec_sig)));
    printf("post s  :%s\n", BN_bn2hex(ECDSA_SIG_get0_s(ec_sig)));

    BIO * bio = BIO_new(BIO_s_mem());
    BN_print(bio, ECDSA_SIG_get0_r(ec_sig));
    BN_print(bio, ECDSA_SIG_get0_s(ec_sig));
    BIO_gets(bio, signature, SIGNATURE_SIZE);

    free(buf);
}

void generate_signature_DER(const char* sig_file, unsigned char* sig){
    ECDSA_SIG* ec_sig = ECDSA_SIG_new();

    BIGNUM *r, *s;
    r = BN_new();
    s = BN_new();
    if (NULL == BN_bin2bn(sig, 32, r)) {
        // dumpOpenSslErrors();
    }
    printf("post r  :%s\n", BN_bn2hex(r));

    if (NULL == BN_bin2bn(sig + 32, 32, s)) {
        // dumpOpenSslErrors();
    }
    printf("post s  :%s\n", BN_bn2hex(s));

    ECDSA_SIG_set0(ec_sig, r, s);

    int sig_size = i2d_ECDSA_SIG(ec_sig, NULL);
    unsigned char *sig_bytes = malloc(sig_size);
    unsigned char *p;
    memset(sig_bytes, 6, sig_size);

    p = sig_bytes;
    int new_sig_size = i2d_ECDSA_SIG(ec_sig, &p);

    BIGNUM *num;
    num = BN_new();
    BN_bin2bn(sig_bytes, sig_size, num);
    printf("DER : %s\n", BN_bn2hex(num));
    write_data_to_file(sig_file, "wb", sig_bytes, sig_size, 0);

    free(sig_bytes);
}

/*
    below functions are here for debug openssl
*/
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



void generate_sm2_sig(){
    BIO * bio_out = BIO_new_fp(stdout,0);
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    EVP_PKEY_CTX *gctx =
        EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);

    EVP_PKEY_keygen_init(gctx);

    params[0] = OSSL_PARAM_construct_utf8_string("group", "SM2", 0);
    params[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(gctx, params);

    EVP_PKEY_generate(gctx, &pkey);

    EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
    char *priv_file = "pri-file";
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    {
        FILE * f = fopen(priv_file,"w");
        PEM_write_ECPrivateKey(f,ec_key, NULL,NULL,0,NULL,NULL);
        fclose(f);
    }

    char *msg = "hello sqy";
    int msg_len = strlen(msg);
    unsigned char *sig = malloc(SIGNATURE_SIZE);
    int sig_len = SIGNATURE_SIZE;


    /* obtain an EVP_PKEY using whatever methods... */
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(pctx, "someid", strlen("someid"));
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    //sign
    EVP_DigestSignInit(mctx, NULL, EVP_sm3(), NULL, pkey);
    EVP_DigestSignUpdate(mctx, msg, msg_len);
    EVP_DigestSignFinal(mctx, sig, &sig_len);
    BIGNUM *num = BN_new();
    BN_bin2bn(sig, sig_len, num);
    printf("SIGNATRUE : %s\n", BN_bn2hex(num));
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);

    //verify
    mctx = EVP_MD_CTX_new();
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_CTX_set1_id(pctx, "someid", strlen("someid"));
    EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
    EVP_DigestVerifyInit(mctx, NULL, EVP_sm3(), NULL, pkey);
    EVP_DigestVerifyUpdate(mctx, msg, msg_len);
    int ret = EVP_DigestVerifyFinal(mctx, sig, sig_len);
    if(ret > 0){
        printf("verify successfully\n");
    } else if(ret == 0){
        printf("verify fail\n");
    } else {
        printf("verifying error\n");
    }
    EVP_MD_CTX_free(mctx);
    EVP_PKEY_CTX_free(pctx);

    //plan 2
    printf("\n\n\n --PLAN 2 START\n");
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    memset(sig, 0, sig_len);
    unsigned char *hash = malloc(HASH_SIZE);
    read_file_to_buf("hash-file", hash, HASH_SIZE, 0);
    if((ret = EVP_PKEY_sign_init(pctx)) <= 0){
        printf("sign_init error id: %d\n", ret);
    }
    if ((ret = EVP_PKEY_CTX_set_signature_md(pctx, EVP_sm3())) <= 0){
        printf("set sm3 fail id: %d\n", ret);
    }
    if(EVP_PKEY_sign(pctx, sig, &sig_len, hash, HASH_SIZE) <= 0){
        printf("sign fail\n");
    }
    EVP_PKEY_CTX_free(pctx);

    //verify
    pctx = EVP_PKEY_CTX_new(pkey, NULL);
    if(EVP_PKEY_verify_init(pctx) <= 0){
        printf("verify init fail\n");
    }
    if((ret = EVP_PKEY_verify(pctx, sig, (size_t)sig_len, hash, (size_t)HASH_SIZE)) == 1){
        printf("plan 2 verify successfully\n");
    } else if(ret == 0){
        printf("plan 2 verify fail\n");
    } else {
        printf("plan 2 verify error\n");
    }

    //plan 2 verify with gm lib
    unsigned char *prikey = malloc(PUBLIC_KEY_SIZE);
    unsigned char *pubkey = malloc(PUBLIC_KEY_SIZE);
    parse_priv_key_file(priv_file, prikey, pubkey);
    printf("pri:\n");
    printHex(prikey, PRIVATE_KEY_SIZE);
    printf("pub:\n");
    printHex(pubkey, PUBLIC_KEY_SIZE);
    printf("hash:\n");
    printHex(hash, HASH_SIZE);
    printf("sig:\n");
    printHex(sig, SIGNATURE_SIZE);
    // int pub_len = 0;
    // EVP_PKEY_get_raw_public_key(pkey, pubkey, &pub_len);
    // printf("pub_key len: %d\n", pub_len);
    // printHex(pubkey, PUBLIC_KEY_SIZE);
    if(verify_enclave((struct signature_t*)sig, hash, pubkey) == 0){
        printf("verify gm lib successfully\n");
    } else {
        printf("verify gm lib fail\n");
    }


    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(gctx);
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
