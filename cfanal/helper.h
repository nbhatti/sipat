/* 
Copyright (C) 2005-2011 Tekelec

This file is part of SIP-A&T, set of tools for SIP analysis and testing.

SIP-A&T is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version

SIP-A&T is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 59 Temple
Place, Suite 330, Boston, MA  02111-1307  USA
*/

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
