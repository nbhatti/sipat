#ifndef __HELPER_H
#define __HELPER_H

#define E_INVALID_PARAMETERS   (-1)
#define E_PACKET_NOT_SUPPORTED (-2)
#define E_BROKEN_PACKET        (-3)
#define E_UNSUPPORTED_DATALINK (-4)
#define E_INVALID_DUMP_FILE    (-5)

/* TODO: solve logging! */
#include <stdio.h>
#define ERR(a,args...)	printf("Error: " a,##args)
#define WARN(a,args...)	printf("Warning: " a,##args)
#define PROTO_ERR(a,args...)	printf("protocol error: " a,##args)
#define TRACE_PROTO(a,args...)	printf(a,##args)
#define TRACE_PROTO_DETAIL(a,args...)	printf(a,##args)
#define TRACE(a,args...)	printf(a,##args)

#include <time.h>
#include <sys/time.h>

long int abs_delta_us(struct timeval *a, struct timeval *b);

#endif
