#include "helper.h"

long int abs_delta_us(struct timeval *a, struct timeval *b)
{
	long int d;
	d = (a->tv_sec - b->tv_sec) * 1000000 + (a->tv_usec - b->tv_usec);
	if (d < 0) d = -d;
	return d;
}


