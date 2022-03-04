##
## Author: Shang Qingyu
## Description:
## 	 compile sign tool need openssl 3.0.0 installation. Now the docker environment
##   doesn't support openssl. So compilation is done in RISC-V qemu. Compile GM in
##   docker.

CC = gcc
CUR_SOURCE = ${wildcard *.c}

SDK_LIB_DIR = $(PENGLAI_SDK)/lib
GM_LIBS = $(SDK_LIB_DIR)/gm/sm2.a $(SDK_LIB_DIR)/gm/miracl.a
GM_LIB_INCLUDE_DIR = $(SDK_LIB_DIR)/gm/include
HOST_LIB = $(SDK_LIB_DIR)/libpenglai-enclave-host.a
HOST_LIB_INCLUDE_DIR = $(SDK_LIB_DIR)/host/include

CFLAGS += -I $(HOST_LIB_INCLUDE_DIR) -I $(GM_LIB_INCLUDE_DIR) -lcrypto -ldl -lpthread

all: penglai_sign

penglai_sign: $(CUR_SOURCE) $(HOST_LIB) $(GM_LIBS)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f *.o penglai_sign
