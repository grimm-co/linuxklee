
all: bc bc_debug

SRC=main.c

bc:
	$(CC) $(CFLAGS) $(SRC) -o bc

bc_debug:
	$(CC) -DDEBUG -g $(SRC) -o bc_debug

bc_klee:
	clang -I klee_src/include/ -DKLEE -emit-llvm -g -c -O0 -Xclang -disable-O0-optnone main.c -o bc.bc

clean:
	rm -f *.o bc bc_debug bc.bc

.PHONY: bc bc_debug bc_klee
