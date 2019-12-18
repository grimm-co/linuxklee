#include <errno.h>
#include <linux/keyctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define BUFFER_SIZE (1024*1024)

int read_file(char * filename, char *buffer, long length)
{
	FILE *fp;
	long fsize, total = 0, num_read;

	fp = fopen(filename, "rb");
	if (!fp)
		return -1;

	//Get the size
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	if(fsize > length)
		fsize = length;

	while (total < fsize)
	{
		num_read = fread(buffer + total, 1, fsize, fp);
		total += num_read;
	}

	fclose(fp);

	return fsize;
}

int main(int argc, char ** argv)
{
	unsigned char buffer[BUFFER_SIZE];
	int length;

	length = read_file(argv[1], buffer, BUFFER_SIZE);
	if(length < 0) {
		printf("Couldn't read %s\n", argv[1]);
		return 1;
	}

	syscall(__NR_add_key, "asymmetric", NULL, buffer, length, KEY_SPEC_SESSION_KEYRING);
	return 0;
}

