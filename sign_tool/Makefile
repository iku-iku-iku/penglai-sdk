##
## Author: Shang Qingyu
## Description:
## 	 compile sign tool need openssl 3.0.0 installation. Now the docker environment
##   doesn't support openssl. So compilation is done in RISC-V qemu. Compile GM in
##   docker.

CC=gcc
CUR_SOURCE=${wildcard *.c}
all: SIGN_TOOL

GM:
	make -C gm

SIGN_TOOL: GM
	$(CC) -o penglai_sign -I $(PENGLAI_SDK)/lib/host/include/ $(CUR_SOURCE) libpenglai-signtool_gm.a $(PENGLAI_SDK)/lib/libpenglai-enclave-host.a -lcrypto -ldl -lpthread

clean:
	make -C gm clean
	rm -f *.o sign_tool
