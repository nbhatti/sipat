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

#include "LinkHandlers.h"
#include "IPHandler.h"
#include "bits.h"

protocol_id_t EthernetHandler::id = "ethernet";

int EthernetHandler::processPacket(struct timeval *ts, unsigned char *data, 
		unsigned int data_len, ProtocolData *parent)
{
	unsigned int i;
	unsigned int proto;

	log->trace("handling ethernet packet\n");

	if (!data) {
		log->error("invalid parameters\n");
		return -1;
	}

	/* verify that the length is enough for ethernet */
	if (data_len < 14) return -1;

	log->trace("handling ethernet v2 packet ...  len: %u, header:", data_len);
	for (i = 0; i < 14; i++) { /* print header only */
		if (i % 16 == 0) log->trace("\n   ");
		log->trace("%02X ", data[i]);
	}
	log->trace("\n");


	proto = GET_WORD(data, 12);

	if (proto == 0x0800) { /* IP */
		if (ip) return ip->processPacket(ts, data + 14, data_len - 18, NULL);
		else return 1; /* found but can't handle */
	}
	else {
		/* handling IPv4 only */
		log->warning("unsupported network protocol: %u\n", proto);
		return 1; /* we understood packet but can not handle nested protocol */
	}
}

int EthernetHandler::initContext(ProtocolHandlerContext *handlers)
{
	ProtocolHandler *h;

	if (ProtocolHandler::initContext(handlers) < 0) return -1;

	/* find ip */
	if (!handlers) return -1;

	for (h = handlers->getFirstHandler(); h; h = handlers->getNextHandler(h)) {
		if (h->identify() == IPHandler::id) {
			ip = h;
			break;
		}
	}

	if (!ip) log->warning("can't find IP protocol handler\n");

	return 0;
}

void EthernetHandler::releaseContext()
{
	ip = NULL;
}

/////////////////////////////////////////////////////////////

protocol_id_t LinuxSLLHandler::id = "linux cooked capture";

int LinuxSLLHandler::processPacket(struct timeval *ts, unsigned char *data, 
		unsigned int data_len, ProtocolData *parent)
{
	unsigned int proto, i;

	if (!data) return -1;

	/* verify that the length is enough for ethernet */
	if (data_len < 16) return -1;

	proto = GET_WORD(data, 14);
	log->trace("handling LINUX_SLL packet ...  len: %u, proto: %u, header:", 
			data_len, proto);
	for (i = 0; i < 16; i++) { /* print header only */
		if (i % 16 == 0) log->trace("\n   ");
		log->trace("%02X ", data[i]);
	}
	log->trace("\n");

	if (proto == 0x0800) { /* IP */
		if (ip) return ip->processPacket(ts, data + 16, data_len - 16, NULL);
		else return 1; /* found but can't handle */
	}
	else {
		/* handling IPv4 only */
		log->trace("unsupported network protocol: %u\n", proto);
		return 1;
	}

	return -1;
}

int LinuxSLLHandler::initContext(ProtocolHandlerContext *handlers)
{
	ProtocolHandler *h;

	if (ProtocolHandler::initContext(handlers) < 0) return -1;

	/* find ip */
	if (!handlers) return -1;

	for (h = handlers->getFirstHandler(); h; h = handlers->getNextHandler(h)) {
		if (h->identify() == IPHandler::id) {
			ip = h;
			break;
		}
	}

	if (!ip) log->warning("can't find IP protocol handler\n");

	return 0;
}

void LinuxSLLHandler::releaseContext()
{
	ip = NULL;
}

