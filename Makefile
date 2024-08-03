compile:
	clang -O2 -g -Wall -I/usr/include -I/usr/include/bpf -o beetrace loader.c -lbpf
	clang -O2 -g -target bpf -c controller.c -o controller.o
	clang test.c -o test
