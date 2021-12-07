#include "parse_key_file.h"
#include <openssl/ec.h>
#include <openssl/pem.h>
#include "gm/sm2.h"

void parse_priv_key_file(char* priv_key_file, unsigned char* priv_key, unsigned char* pub_key){
    printf("\nread pri key file:\n");
    FILE * f = fopen(priv_key_file, "r");
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

void parse_pub_key_file(char* pub_key_file, unsigned char* pub_key){
    printf("\nread pub key file:\n");
    FILE * f = fopen(pub_key_file, "r");
    EC_KEY *ec_key = PEM_read_EC_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);

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
        if(cur == 64){
            printf("ERROR: cur = 64\n");
            break;
        }
        if(line[i] == ' ' || line[i] == '\n' || line[i] == ':'){
            if(b != 0){
                if(!skip_z){
                    skip_z = 1;
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
}

/*
    below two functions are here for debug openssl
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
