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

#include "SCTPHandler.h"
#include "IPHandler.h"
#include "SIPHandler.h"
#include "bits.h"
#include "helper.h"

protocol_id_t SCTPHandler::id = "sctp";

int SCTPHandler::processPacket(struct timeval *ts, unsigned char *data, 
		unsigned int data_len, ProtocolData *parent)
{
	IPData *ip;

	if (!data) return -1;
	

	/* verify that the length is enough for SCTP */
	if (data_len < 12) return -1;

	/* IP envelope needed! */
	if (!parent) return -1;
	if (parent->identify() != IPHandler::id) return -1;

	ip = (IPData*)parent;
	SCTPData c(ip->src, GET_WORD(data, 0), ip->dst, GET_WORD(data, 2));

	log->trace("handling SCTP packet ...  len: %u, src port: %u, dst port: %u\n", 
			data_len, c.src.port, c.dst.port);

	bool reverse_dir;
	SCTPConnection *con = cm.findSCTPConnection(&c, reverse_dir);
	if (!con) {
		reverse_dir = false;
		con = cm.addSCTPConnection(&c, this);
		if (!con) return -1; /* can't add new connection */
	}
	return con->processPacket(ts, data, data_len, reverse_dir); /* handle current packet inside SCTP connection context */
}

int SCTPHandler::initContext(ProtocolHandlerContext *handlers)
{
	ProtocolHandler *h;

	if (ProtocolHandler::initContext(handlers) < 0) return -1;

	if (!handlers) return -1;

	for (h = handlers->getFirstHandler(); h; h = handlers->getNextHandler(h)) {
		if (h->identify() == SIPHandler::id) {
			sip = h;
			break;
		}
	}

	return 0;
}

void SCTPHandler::releaseContext()
{
	sip = NULL;
}

#define DOES_NOT_CARRY_SIP	1
#define CARRIES_SIP			2

unsigned int SCTPHandler::processData(unsigned char* data, unsigned int data_len, 
		SCTPData *params, struct timeval *ts, SCTPConnection *c)
{
	if (data_len < 1) return 0; // ignore empty data
	if (!c) return 0; // bug

	unsigned int flags = c->getUserFlags();
	int can_be_sip = 0;

	log->trace("handling ACKNOWLEDGED DATA (%u sec):\n---\n%.*s\n---\n", ts->tv_sec, data_len, data);

	if (!(flags & (DOES_NOT_CARRY_SIP | CARRIES_SIP))) {
		// we don't know if this connection caries SIP
		// starts like SIP? - if yes set connection user flags
		int is = is_sip(data, data_len);
		log->trace("is_sip: %d\n", is);
		switch (is) {
			case -1: 
				flags |= DOES_NOT_CARRY_SIP;
				c->setUserFlags(flags);
				can_be_sip = 0;
				log->trace("NOT SIP\n");
				break;

			case 1: 
				can_be_sip = 1;
//				log->TRACE("can be SIP\n");
				break;

			case 0: /* who knows, but currently it is NOT SIP for sure */
				can_be_sip = 0;
//				log->TRACE("can or can NOT be SIP - who knows\n");
				break;
		}
	}
	if (flags & CARRIES_SIP)  can_be_sip = 1;	// this connection caries SIP or can be SIP, process it as SIP

	unsigned int before = sip->getProcessedBytes();
	unsigned int after;
	unsigned int len;
	unsigned int processed = 0;

	do {
		if (can_be_sip && sip) {
			log->trace("trying SIP\n");
			if (sip->processPacket(ts, data, data_len, params) == 0) {
				after = sip->getProcessedBytes();
				len = after - before;
				//log->TRACE("it IS SIP\n");
				flags |= CARRIES_SIP;
				c->setUserFlags(flags);
			}
			else {
				// clear flags if it is not SIP?
				// but it can be half of SIP message
				break;
			}
		}
		else {
			log->trace("can not be SIP\n");
			//TODO: other protocols like DNS...
			return data_len; // like all processed
			break;
		}
		data = data + len;
		data_len -= len;
		processed += len;
	} while (data_len > 0);

	// some data might be still unprocessed because we have not
	// enough of them - they will be stored within TcpConnection

	return processed;
}

unsigned int SCTPHandler::processSCTPMessage(unsigned char* data, unsigned int data_len, 
		SCTPData *params, struct timeval *ts, SCTPConnection *c)
{
	if (!create_sctp_messages) return 0; //ignore

	if (data_len < 1) return 0; // ignore empty data
	if (!c) return 0; // bug

	MessageFlow *flow = context->getMessageFlow();
	if (flow) {
		SCTPControlMessage *msg = new SCTPControlMessage(data, data_len, 
				flow->knownDestination(&params->src),
				flow->knownDestination(&params->dst), ts);
		if (msg) flow->add(msg);
	}
	return 0;
}

//////////////////////////////////////////////////////////////
		
protocol_id_t SCTPData::identify() { return SCTPHandler::id; }

protocol_id_t SCTPDestination::identify() { return SCTPHandler::id; }

SCTPDestination::SCTPDestination(IPAddress &ip_addr, 
		unsigned int port, bool ignore_port):
	IPDestination(ip_addr)
{
	this->port = port;
	ignorePort = ignore_port;
}

SCTPDestination::SCTPDestination(SCTPDestination *d): IPDestination(d ? &d->ip_addr: NULL)
{
	if (d) this->port = d->port;
	this->ignorePort = false;
}

Destination *SCTPDestination::duplicate()
{
	Destination *d = new SCTPDestination(ip_addr, port, ignorePort);
	if (d && name) d->setName(name);
	return d;
}

bool SCTPDestination::equals(Destination *d)
{
	if (!d) return false;
	if (d->identify() != identify()) return false;
	if (! (ignorePort || ((SCTPDestination*)d)->ignorePort) ) {
		if (port != ((SCTPDestination*)d)->port) return false;
	}
	return IPDestination::equals(d);
}

void SCTPDestination::printValue(std::ostream &os)
{
	os << "sctp:";
	IPDestination::printValue(os);
	if (!ignorePort) os << ":" << port;
}

//////////////////////////////////////////////////////////////////

void SCTPControlMessage::cfprint(std::ostream &os)
{
	char default_color[] = "grey";
	const char *color = default_color;
	//char tmp[256];

	os << "<call";
//	os << " at " << timeStamp.tv_sec << " s " << timeStamp.tv_usec << " us";
	os << " src='";
	if (!src) os << "???";
	else src->printName(os);
	os << "' dst='";
	if (!dst) os << "???";
	else dst->printName(os);
	os << "' desc='SCTP: ";

	// message text
	if (chunk_list) os << chunk_list;
	else os << "???";

	if (prev) {
		long int d = abs_delta_us(&timeStamp, &(prev->timeStamp));
		os << " (+" << d / 1000 << " ms)"; // experimental
	}

	os << "' color='" << color;
/*	if (dst) {
		os << "' line-type='";
		dst->printLineType(os);
	}*/
	os << "'/>";

}

void SCTPControlMessage::txtprint(std::ostream &os)
{
	Message::txtprint(os);
	os << "\nSCTP: ";
	if (chunk_list) os << chunk_list;
	else os << "???";
	os << "\n"; 
}

static void get_chunk_list(char *dst, int bufsize, unsigned char *data, unsigned int data_len) 
{
	// TODO: remove duplicate code (similar used in parent function!)
	int pos = 0;
	char tmp[32];
	*dst = 0;

#define add_str(s)	do { int l = strlen(s); if (bufsize > pos + l + 1) { memcpy(dst + pos, s, l); pos += l;} } while(0)
	int chunk_type, flags;
	unsigned int chunk_length;
	if (data_len > 12) {
		//data inside SCTP
		data = data + 12;
		data_len -= 12;

		while (data_len > 0) {
			// data & data_len point to first chunk
			chunk_type = GET_BYTE(data, 0);
			flags = GET_BYTE(data, 1);
			chunk_length = GET_WORD(data, 2);

			if (pos > 0) add_str(", ");

			switch (chunk_type) {
				case 0: add_str("DATA"); break;
				case 1: add_str("INIT"); break;
				case 2: add_str("INIT ACK"); break;
				case 3: add_str("SACK"); break;
				case 4: add_str("HB"); break;
				case 5: add_str("HB ACK"); break;
				case 6: add_str("ABORT"); break;
				case 7: add_str("SHUTDOWN"); break;
				case 8: add_str("SHUTDOWN ACK"); break;
				case 9: add_str("ERROR"); break;
				case 10: add_str("COOKIE ECHO"); break;
				case 11: add_str("COOKIE ACK"); break;
				case 12: add_str("ECNE"); break;
				case 13: add_str("CWR"); break;
				case 14: add_str("SHUTDOWN COMPLETE"); break;
				case 15: add_str("SHUTDOWN COMPLETE"); break;
				default: 
					sprintf(tmp, "%d", chunk_type);
					add_str(tmp);
			}

			if (chunk_length % 4 != 0) chunk_length += 4 - (chunk_length % 4);
			if (data_len < chunk_length) data_len = 0;
			else {
				data_len -= chunk_length;
				data += chunk_length;
			}
		}
	}
	dst[pos] = 0;
}

SCTPControlMessage::SCTPControlMessage(unsigned char *data, unsigned int data_len, 
		Destination *src, Destination *dst, struct timeval *ts): Message(src, dst, ts)
{
	char tmp[1024];
	get_chunk_list(tmp, sizeof(tmp), data, data_len);
	chunk_list = strdup(tmp);
}


SCTPControlMessage::~SCTPControlMessage() 
{
	if (chunk_list) free(chunk_list);
}
