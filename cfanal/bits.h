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

#ifndef __CF_BITS_H
#define __CF_BITS_H

/* i386: least significant byte first,
   network: most significant byte first */
#define GET_BYTE(data,i) (data[i])
#define GET_WORD(data,i) ((data[i] << 8) | data[i+1])
#define GET_DWORD(data,i) ((data[i] << 24) | (data[i + 1] << 16) | data[i+2] << 8 | data[i+3])

#endif
