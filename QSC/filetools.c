#include "filetools.h"

bool file_exists(const char* filepath)
{
	FILE* fp;
	errno_t err;
	bool res;

	err = fopen_s(&fp, filepath, "r");

	if (fp != NULL && err == 0)
	{
		fclose(fp);
		res = true;
	}
	else
	{
		res = false;
	}

	return res;
}

#if defined(QSC_COMPILER_MSC)
int64_t getline(char** line, size_t* length, FILE* fp)
{
	// check if either line, length or fp are NULL pointers
	if (line == NULL || length == NULL || fp == NULL)
	{
		errno = EINVAL;
		return -1;
	}

	// use a chunk array of 128 bytes as parameter for fgets
	char chunk[128];

	// allocate a block of memory for *line if it is NULL or smaller than the chunk array
	if (*line == NULL || *length < sizeof(chunk))
	{
		*length = sizeof(chunk);

		if ((*line = malloc(*length)) == NULL)
		{
			errno = ENOMEM;
			return -1;
		}
	}

	// empty the string
	(*line)[0] = '\0';

	while (fgets(chunk, sizeof(chunk), fp) != NULL)
	{
		// resize the line buffer if necessary
		size_t lenused = strlen(*line);
		size_t chunkused = strlen(chunk);

		if (*length - lenused < chunkused)
		{
			// Check for overflow
			if (*length > SIZE_MAX / 2)
			{
				errno = EOVERFLOW;
				return -1;
			}
			else
			{
				*length *= 2;
			}

			if ((*line = realloc(*line, *length)) == NULL)
			{
				errno = ENOMEM;
				return -1;
			}
		}

		// copy the chunk to the end of the line buffer
		memcpy(*line + lenused, chunk, chunkused);
		lenused += chunkused;
		(*line)[lenused] = '\0';

		// check if *line contains '\n', if yes, return the *line length
		if ((*line)[lenused - 1] == '\n')
		{
			return lenused;
		}
	}

	return -1;
}
#endif