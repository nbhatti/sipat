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

#include "IPHandler.h"
#include "UdpHandler.h"
#include "TcpHandler.h"
#include "SCTPHandler.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "bits.h"

#define MF                  1 /* more fragments */
#define DF                  2 /* don't fragment */

bool IPPacketID::operator==(IPPacketID &b)
{
	if (b.id != id) return false;
	if (b.src != src) return false;
	if (b.dst != dst) return false;
	if (b.protocol != protocol) return false;

	return true;
}
		
IPPacketID::IPPacketID(unsigned char *ip_header):
	src(ip_header + 12), dst(ip_header + 16)
{
	id = GET_WORD(ip_header, 4);
	protocol = GET_BYTE(ip_header, 9);
}
		
IPPacketID::IPPacketID(): src(NULL), dst(NULL)
{
	id = 0;
	protocol = 0;
}

IPPacketID::IPPacketID(IPPacketID *id): src(id->src), dst(id->dst)
{
	src = id->src;
	dst = id->dst;
	this->id = id->id;
	protocol = id->protocol;
}

void IPPacketID::printTrace(Log *log, LogLevel ll)
{
	if (log) {
		//log->info("id=%u src=%08x dst=%08x proto=%u", id, src, dst, protocol);
		log->log(ll, "id=%u proto=%u", id, protocol);
	}
}


////////////////////////////////////////////////

FragmentedIPPacket::FragmentedIPPacket(IPPacketID *_id) 
{
	defragmentedLength = 0;
	memset(buffer, 0, MAX_IP_HEADER_LEN); /* clear header */
	defragmentedHeader = buffer;
	defragmentedData = buffer + MAX_IP_HEADER_LEN;

	if (_id) id = *_id;
}

FragmentedIPPacket::~FragmentedIPPacket()
{
	/* currently nothing allocated dynamicaly - change? */
}

bool FragmentedIPPacket::isWholePacket()
{
	if (!defragmentedLength) return false; /* length not set -> at least last fragment not received */

	for (unsigned int i = 0; i < defragmentedLength / 8; i++)
	{
		/* verify all rcv bits */
		if (!received[i]) return false;
	}

	return true;
}
		
void FragmentedIPPacket::setRcvBits(unsigned int offset, unsigned int len)
{
	for (unsigned int i = 0; i < (len + 7) / 8; i++)
	{
		/* verify all rcv bits */
		received[offset + i] = 1;
	}

}

void FragmentedIPPacket::handleFragment(unsigned int offset, 
		unsigned char *data, unsigned int len, 
		unsigned char *header, unsigned int header_len,
		bool mf)
{
	memcpy(defragmentedData + offset * 8, data, len);
	setRcvBits(offset, len);
	if (!mf) { /* last fragment */
		defragmentedLength = len + offset * 8;
	}
	if (offset == 0) {
		/* first fragment - use header */
		memcpy(defragmentedHeader, header, header_len);
	}

}

////////////////////////////////////////////////

Destination *IPDestination::duplicate()
{
	Destination *d = new IPDestination(ip_addr);
	if (d && name) d->setName(name);
	return d;
}

bool IPDestination::equals(Destination *d)
{
	if (!d) return false;
	if (d->identify() != identify()) return false;
	if (ip_addr != ((IPDestination*)d)->ip_addr) return false;
	return true;
}

void IPDestination::printValue(std::ostream &os)
{
	os << (int)ip_addr.addr[0] << ".";
	os << (int)ip_addr.addr[1] << ".";
	os << (int)ip_addr.addr[2] << ".";
	os << (int)ip_addr.addr[3];
}

////////////////////////////////////////////////

protocol_id_t IPHandler::id = "ip";

IPHandler::IPHandler(IPPacketIgnoreType ignore_seen_packets)
{
	first = NULL;
	last = NULL;
	udp = NULL;
	tcp = NULL;
	sctp = NULL;
	ignoreSeenPackets = ignore_seen_packets;
}

IPHandler::~IPHandler()
{
	releaseContext();
}

bool IPHandler::ignorePacket(struct timeval *ts, 
		IPPacketID *id,
		unsigned char *header, 
		unsigned char *data, 
		unsigned int data_len)
{
	ListedIPPacketID *x;
	unsigned int flags;
	bool ignore = false;

	flags = GET_BYTE(data, 6) >> 5;

	switch (ignoreSeenPackets) {
		case DO_NOT_IGNORE:
			break;

		case IGNORE_IP_ID_UNSAFE:
			flags = 0; /* ! */
			/* do the rest as for safe */

		case IGNORE_IP_ID_SAFE:
			/* flags set by prev. case or 0 from the beggining! */

			/* only if packet ID is set to nonzero and can be fragmented !!! */
			if ((id->id != 0) && ((flags & DF) == 0)) {
				x = idList.find(id);
				if (x) ignore = true; /* was seen -> ignore */
				else idList.add(id);
			}
			break;

		case IGNORE_SHORT_INTERVAL_SAME_DATA:
			/* store all data and compare timestamps */
			x = idList.find(id);
			if (x) {
				/* the ID was seen -> compare data and timestamps */
				if (x->findTimedData(ts, data, data_len)) ignore = true;
				else x->addData(ts, data, data_len);
			}
			else {
				x = idList.add(id);
				if (x) x->addData(ts, data, data_len);
			}
			break;
	}

	if (ignore) {
		/* TODO: add trace logs? */
		log->log(LL_DEBUG, "ignoring already seen packet (len: %u) ", data_len);
		x->printTrace(log, LL_DEBUG);
		log->log(LL_DEBUG, " == ");
		id->printTrace(log, LL_DEBUG);
		log->log(LL_DEBUG, "\n");
	}
	return ignore;
}

int IPHandler::processDefragmented(struct timeval *ts, 
		IPPacketID *id,
		unsigned char *header, 
		unsigned char *data, 
		unsigned int data_len, ProtocolData *parent)
{
	unsigned int proto;
	ProtocolHandler *h;

	if (ignorePacket(ts, id, header, data, data_len)) return 1;

	proto = GET_BYTE(header, 9);
	IPData ip(header);

	log->trace("handling reassembled IP packet (len: %u, proto: %u)\n", data_len, proto);
	for (unsigned int i = 0; i < data_len; i++) {
		if (i % 16 == 0) log->trace("\n   ");
		log->trace("%02X ", data[i]);
	}
	log->trace("\n");
	
	log->trace("from: %d.%d.%d.%d\n", 
			GET_BYTE(header, 12), 
			GET_BYTE(header, 13), 
			GET_BYTE(header, 14), 
			GET_BYTE(header, 15));
	log->trace("to: %d.%d.%d.%d\n", 
			GET_BYTE(header, 16), 
			GET_BYTE(header, 17), 
			GET_BYTE(header, 18), 
			GET_BYTE(header, 19));

	switch (proto) 
	{
		case 17 /* UDP */: h = udp; break;
		case 6 /* TCP */: h = tcp; break;
		case 0x84: h = sctp; break;
		default: h = NULL;
	}
	if (h) return h->processPacket(ts, data, data_len, &ip);
	else return 1;

	return 0;
}

int IPHandler::processPacket(struct timeval *ts, 
		unsigned char *data, unsigned int data_len, 
		ProtocolData *parent)
{
	int i;
	unsigned short int hdr_len, version, len, id, proto;
	unsigned char flags;
	unsigned short offset;
	unsigned int src, dst;
	FragmentedIPPacket *f;
	unsigned char *ip_data;
	unsigned int ip_data_len;
	int res = 0;

	log->trace("handling IP\n");

	if (data_len < 20) {
		log->error("invalid IP packet\n");
		return -1;
	}

	hdr_len = (GET_BYTE(data, 0) & 0x0F) * 4;
	version = (GET_BYTE(data, 0) & 0xF0) >> 4;
	len = GET_WORD(data, 2);
	id = GET_WORD(data, 4);
	flags = GET_BYTE(data, 6) >> 5;
	offset = GET_WORD(data, 6) & 0x1FFF;
	proto = GET_BYTE(data, 9);

	if (hdr_len < 20) {
		log->error("invalid header length for IP\n");
		return -1;
	}
	if (version != 4) {
		log->warning("only IPv4 supported for now\n");
		return -1;
	}
	
	log->trace("IP version: %u, header len: %u, len: %u, "
			"id: %u, flags: %u, offset: %u, protocol: %u\n", 
			version, hdr_len, len, 
			id, flags, offset, proto);
	
	log->trace("flags: ");
	if (flags & 2) log->trace("don't fragment");
	if (flags & 1) log->trace("more fragments");
	log->trace("\n");

	log->trace("IP header:");
	for (i = 0; i < hdr_len; i++) {
		if (i % 4 == 0) log->trace("\n   ");
		log->trace("%02X ", data[i]);
	}
	log->trace("\n");

	log->trace("from: %d.%d.%d.%d\n", 
			GET_BYTE(data, 12), 
			GET_BYTE(data, 13), 
			GET_BYTE(data, 14), 
			GET_BYTE(data, 15));
	log->trace("to: %d.%d.%d.%d\n", 
			GET_BYTE(data, 16), 
			GET_BYTE(data, 17), 
			GET_BYTE(data, 18), 
			GET_BYTE(data, 19));

	src = GET_DWORD(data, 12);
	dst = GET_DWORD(data, 16);

	/* handle fragmentation */
	IPPacketID frag_id(data);

	ip_data_len = len - hdr_len;
	ip_data = data + hdr_len;

	f = findFragmentedPacket(&frag_id);
	if (((flags & MF) == 0) && (offset == 0)) { 
		/* current packet is not fragmented */
		if (f) {
			removeFragmentedPacket(f);
			delete f;
		}
		/* like current packet is not fragmented (see RFC 791) */
		return processDefragmented(ts, &frag_id,
				data /* header */, ip_data, ip_data_len, parent);
	}
	else {
		/* fragmented */
		if (!f) {
			/* reassembly not started yet */
			f = new FragmentedIPPacket(&frag_id);
			if (!f) return -1;
			addFragmentedPacket(f);
			/* log->trace("*** adding fragment ***\n"); */
		}
		f->handleFragment(offset, ip_data, ip_data_len, 
				data, hdr_len, flags & MF);
		/* log->trace("*** handling fragment data (offset: %u, len: %u) ***\n", offset * 8, ip_data_len); */

		if (f->isWholePacket()) {
			removeFragmentedPacket(f);
			res = processDefragmented(ts, &frag_id,
					f->defragmentedHeader, 
					f->defragmentedData, f->defragmentedLength,
					parent);
			delete f;
		}
	}
	return res;
}

int IPHandler::initContext(ProtocolHandlerContext *handlers)
{
	ProtocolHandler *h;

	if (ProtocolHandler::initContext(handlers) < 0) return -1;

	/* find ip */
	if (!handlers) return -1;

	for (h = handlers->getFirstHandler(); h; h = handlers->getNextHandler(h)) {
		if (h->identify() == UdpHandler::id) udp = h;
		if (h->identify() == TcpHandler::id) tcp = h;
		if (h->identify() == SCTPHandler::id) sctp = h;
	}

	return 0;
}

void IPHandler::releaseContext()
{
	/* release all unprocessed fragments */
	FragmentedIPPacket *p, *n;

	p = first;
	while (p) {
		n = p->next;
		delete p;
		p = n;
	}
	first = NULL;
	last = NULL;

	/* release nested protocol handlers */
	udp = NULL;
	tcp = NULL;
	sctp = NULL;

	log = NULL;
}

void IPHandler::addFragmentedPacket(FragmentedIPPacket *p)
{
	if (!p) return;

	p->next = NULL;
	p->prev = last;
	if (last) last->next = p;
	else first = p;
	last = p;
	
}

void IPHandler::removeFragmentedPacket(FragmentedIPPacket *p)
{
	if (!p) return;

	if (p->next) p->next->prev = p->prev;
	else last = p->prev;
	if (p->prev) p->prev->next = p->next;
	else first = p->next;

	p->next = NULL;
	p->prev = NULL;
}

FragmentedIPPacket *IPHandler::findFragmentedPacket(IPPacketID *id)
{
	FragmentedIPPacket *p;

	p = first;
	while (p) {
		if (p->id == *id) return p;
		p = p->next;
	}
	return NULL;
}

//////////////////////////////////////////////////////////////////////

ListedIPPacketID *IPPacketIDList::add(IPPacketID *id)
{
	ListedIPPacketID *a = new ListedIPPacketID(id);
	if (a) {
		a->next = first;
		first = a;
	}
	return a;
}

IPPacketIDList::IPPacketIDList()
{
	first = NULL;
}

IPPacketIDList::~IPPacketIDList()
{
	ListedIPPacketID *i = first, *n;
	while (i) {
		n = i->next;
		delete i;
		i = n;
	}
}

ListedIPPacketID *IPPacketIDList::find(IPPacketID *id)
{
	ListedIPPacketID *i = first;
	
	if (!id) return false;
	
	while (i) {
		if (*i == (*id)) return i;
		i = i->next;
	}

	return false;
}
//////////////////////////////////////////////////////////////////////

void ListedIPPacketID::addData(struct timeval *ts, 
		const unsigned char *data, int data_len)
{
	IPPacketData *d = (IPPacketData*)malloc(sizeof(IPPacketData) + data_len);
	if (!d) return; /* error */

	d->data_len = data_len;
	memcpy(d->data, data, data_len);
	memcpy(&d->ts, ts, sizeof(d->ts));
	d->next = this->data;
	this->data = d;
}

static long int abs_delta_us(struct timeval *a, struct timeval *b)
{
	long int d;
	d = (a->tv_sec - b->tv_sec) * 1000000 + (a->tv_usec - b->tv_usec);
	if (d < 0) d = -d;
	return d;
}

bool ListedIPPacketID::findTimedData(struct timeval *ts, 
		const unsigned char *data, int data_len)
{
	IPPacketData *d = this->data;
	while (d) {
		if (d->data_len == data_len) {
			/* the same length */
//			printf("same data len\n");
			if (abs_delta_us(ts, &d->ts) < IGNORE_INTERVAL_US) {
//				printf("time ok\n");
				/* time difference in required interval  */
				if (memcmp(d->data, data, data_len) == 0) {
//					printf("data ok\n");
					/* the same data */
					return true;
				}
//				else printf("data non ok\n");
			}
//			else printf("time non ok\n");
		}
		d = d->next;
	}
	return false;
}


//////////////////////////////////////////////////////////////////////

bool IPAddress::operator==(IPAddress &a)
{
	if (memcmp(addr, a.addr, sizeof(addr)) == 0) return true;
	else return false;
}

void IPAddress::operator=(IPAddress &a)
{
	memcpy(addr, a.addr, sizeof(addr));
}

IPAddress::IPAddress(unsigned char *addr_start)
{
	if (addr_start) memcpy(addr, addr_start, sizeof(addr));
	else memset(addr, 0, sizeof(addr));
}
		
IPAddress::IPAddress()
{
	memset(addr, 0, sizeof(addr));
}
