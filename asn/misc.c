#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

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

