#include <assert.h>
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

#include "rsa.h"
#include "misc.h"

#ifdef KLEE
#define FUZZ_BUFFER_SIZE 1024
#elif defined(KLEE_DEBUG)
#define FUZZ_BUFFER_SIZE 1024
#else
#define FUZZ_BUFFER_SIZE (50*1024)
#endif

int main(int argc, char **argv)
{
	struct rsa_key key;
	char * fuzz_filename;
	int ret, fuzz_length;
	u8 * fuzz_buffer;

	fuzz_buffer = malloc(FUZZ_BUFFER_SIZE);
	if(!fuzz_buffer) {
		printf("Failed to allocate fuzz buffer\n");
		return 1;
	}
	pr_debug("fuzz_buffer %p\n", fuzz_buffer);

#ifndef KLEE
	if(argc < 2) {
		printf("Usage: rsa filename\n");
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

		memset(&key, 0, sizeof(key));
#ifdef RSA_PUB_KEY
		ret = rsa_parse_priv_key(&key, fuzz_buffer, fuzz_length);
#else
		ret = rsa_parse_pub_key(&key, fuzz_buffer, fuzz_length);
#endif
		pr_debug("Key parsed, ret = %d\n", ret);

		if(!ret) {
			//If parsing succeeded, make sure the key pointers are within the buffer given
			if(key.n) assert(key.n >= fuzz_buffer && (key.n + key.n_sz) <= fuzz_buffer + fuzz_length);
			if(key.e) assert(key.e >= fuzz_buffer && (key.e + key.e_sz) <= fuzz_buffer + fuzz_length);
			if(key.d) assert(key.d >= fuzz_buffer && (key.d + key.d_sz) <= fuzz_buffer + fuzz_length);
			if(key.p) assert(key.p >= fuzz_buffer && (key.p + key.p_sz) <= fuzz_buffer + fuzz_length);
			if(key.q) assert(key.q >= fuzz_buffer && (key.q + key.q_sz) <= fuzz_buffer + fuzz_length);
			if(key.dp) assert(key.dp >= fuzz_buffer && (key.dp + key.dp_sz) <= fuzz_buffer + fuzz_length);
			if(key.dq) assert(key.dq >= fuzz_buffer && (key.dq + key.dq_sz) <= fuzz_buffer + fuzz_length);
			if(key.qinv) assert(key.qinv >= fuzz_buffer && (key.qinv + key.qinv_sz) <= fuzz_buffer + fuzz_length);
		}

#ifdef __AFL_LOOP
	}
#endif

	free(fuzz_buffer);

	return 0;
}

