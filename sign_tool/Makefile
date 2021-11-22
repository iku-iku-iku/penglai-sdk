##
## Author: Dong Du
## Description:
## 	The file now assumes the kernel located in ../openeuler-kernel,
##	if you would like to use your own one, please change the path

CC=riscv64-unknown-linux-gnu-gcc
CUR_SOURCE=${wildcard *.c}
all: SIGN_TOOL

GM:
	make -C gm

SIGN_TOOL: GM
	$(CC) -static -o sign_tool -I $(PENGLAI_SDK)/lib/host/include/ sign_tool.c penglai-enclave-elfloader.c penglai-enclave-page.c $(PENGLAI_SDK)/lib/libpenglai-enclave-host.a -lpthread

clean:
	make -C gm clean
	rm -f *.o sign_tool
