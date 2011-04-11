#ifndef __CF_BITS_H
#define __CF_BITS_H

/* i386: least significant byte first,
   network: most significant byte first */
#define GET_BYTE(data,i) (data[i])
#define GET_WORD(data,i) ((data[i] << 8) | data[i+1])
#define GET_DWORD(data,i) ((data[i] << 24) | (data[i + 1] << 16) | data[i+2] << 8 | data[i+3])

#endif
