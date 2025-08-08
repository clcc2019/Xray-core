all: tcp_cc_sockops.o

tcp_cc_sockops.o: tcp_cc_sockops.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -c $< -o $@

clean:
	rm -f *.o *_bpfel.* *_bpfeb.*


