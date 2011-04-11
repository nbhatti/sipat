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

#include "UdpHandler.h"
#include "IPHandler.h"
#include "SIPHandler.h"
#include "DNSHandler.h"
#include "bits.h"

protocol_id_t UdpHandler::id = "udp";

int UdpHandler::processPacket(struct timeval *ts, unsigned char *data, 
		unsigned int data_len, ProtocolData *parent)
{
	IPData *ip;

	if (!data) return -1;

	/* verify that the length is enough for udp */
	if (data_len < 8) return -1;

	/* IP envelope needed! */
	if (!parent) return -1;
	if (parent->identify() != IPHandler::id) return -1;

	ip = (IPData*)parent;
/*	src_ip = ip->src.getIPAddress();
	dst_ip = ip->dst.getIPAddress();
	log->trace("  UDP in context of IP - src: %08x, dst: %08x\n", 
		src_ip, dst_ip);
		}
	} */
	UdpData c(ip->src, GET_WORD(data, 0), ip->dst, GET_WORD(data, 2));

	log->trace("handling UDP packet ...  len: %u, src port: %u, dst port: %u\n", 
			data_len, c.src.port, c.dst.port);

	/* try to decode the protocol here: SIP, DNS, ... */

	//data inside UDP
	data = data + 8;
	data_len -= 8;

	/* try SIP - the protocol is text based and has identification inside ->
	 * try to parse it and see if it works or not */
	if (sip) {
		if (sip->processPacket(ts, data, data_len, &c) == 0) 
			return 0;
	}

	if (dns && (c.dst.port == 53 || c.src.port == 53)) { 
		/* DNS is binary and has no identification - needed to guess according
		 * ports? */
		if (dns->processPacket(ts, data, data_len, &c) == 0) 
			return 0;
	}

	return 0;
}

int UdpHandler::initContext(ProtocolHandlerContext *handlers)
{
	ProtocolHandler *h;

	if (ProtocolHandler::initContext(handlers) < 0) return -1;

	if (!handlers) return -1;

	for (h = handlers->getFirstHandler(); h; h = handlers->getNextHandler(h)) {
		if (h->identify() == SIPHandler::id) sip = h;
		if (h->identify() == DNSHandler::id) dns = h;
		if (sip && dns) break;
	}

	return 0;
}

void UdpHandler::releaseContext()
{
	sip = NULL;
}

//////////////////////////////////////////////////////////////

UdpDestination::UdpDestination(IPAddress &ip_addr, 
		unsigned int port, bool ignore_port):
	IPDestination(ip_addr)
{
	this->port = port;
	ignorePort = ignore_port;
}

Destination *UdpDestination::duplicate()
{
	Destination *d = new UdpDestination(ip_addr, port, ignorePort);
	if (d && name) d->setName(name);
	return d;
}

bool UdpDestination::equals(Destination *d)
{
	if (!d) return false;
	if (d->identify() != identify()) return false;
	if (! (ignorePort || ((UdpDestination*)d)->ignorePort) ) {
		if (port != ((UdpDestination*)d)->port) return false;
	}
	return IPDestination::equals(d);
}

void UdpDestination::printValue(std::ostream &os)
{
	os << "udp:";
	IPDestination::printValue(os);
	if (!ignorePort) os << ":" << port;
}

