#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#ifdef KLEE
#include <klee/klee.h>
#endif

#include "pkcs7_parser.h"
#include "misc.h"

#ifdef KLEE
#define FUZZ_BUFFER_SIZE 1024
#elif defined(KLEE_DEBUG)
#define FUZZ_BUFFER_SIZE 1024
#else
#define FUZZ_BUFFER_SIZE (2*1024*1024)
#endif

int main(int argc, char **argv)
{
	struct pkcs7_message * msg;
	char * fuzz_filename;
	int fuzz_length;
	char * fuzz_buffer;

	fuzz_buffer = malloc(FUZZ_BUFFER_SIZE);
	if(!fuzz_buffer) {
		printf("Failed to allocate fuzz buffer\n");
		return 1;
	}
	pr_debug("fuzz_buffer %p\n", fuzz_buffer);

#ifndef KLEE
	if(argc < 2) {
		printf("Usage: pkcs7 filename\n");
		return 1;
	}
	fuzz_filename = argv[1];
#endif

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif

#ifdef __AFL_LOOP
	while (__AFL_LOOP(1000)) {
#endif

		memset(fuzz_buffer, 0, FUZZ_BUFFER_SIZE);

#ifdef KLEE
		unsigned short size;
		klee_make_symbolic(&size, sizeof(short), "size");
		size &= 0x3ff;

		klee_assume(size < FUZZ_BUFFER_SIZE);
		fuzz_length = size;
		if(fuzz_length == 0)
			return 1;

		klee_make_symbolic(fuzz_buffer, FUZZ_BUFFER_SIZE, "buffer");

#else

		fuzz_length = read_file(fuzz_filename, fuzz_buffer, FUZZ_BUFFER_SIZE);
		if(fuzz_length < 0)
#ifdef __AFL_LOOP
			continue;
#else
			return 1;
#endif

#endif

		msg = pkcs7_parse_message(fuzz_buffer, fuzz_length);
		if(!IS_ERR(msg))
			pkcs7_free_message(msg);

#ifdef __AFL_LOOP
	}
#endif

	free(fuzz_buffer);

	return 0;
}

