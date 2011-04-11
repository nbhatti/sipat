#include "TcpHandler.h"
#include "IPHandler.h"
#include "SIPHandler.h"
#include "DNSHandler.h"
#include "bits.h"

#define TRACE	trace

protocol_id_t TcpHandler::id = "tcp";

int TcpHandler::processPacket(struct timeval *ts, unsigned char *data, 
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
	log->trace("  TCP in context of IP - src: %08x, dst: %08x\n", 
		src_ip, dst_ip);
		}
	} */

	TcpData c(ip->src, GET_WORD(data, 0), ip->dst, GET_WORD(data, 2));

	log->trace("handling TCP packet ...  len: %u, src port: %u, dst port: %u\n", 
			data_len, c.src.port, c.dst.port);
//	log->TRACE("0: %u, 2: %u\n", GET_WORD(data, 0), GET_WORD(data, 2));

	/* try to decode the protocol here: SIP, DNS, ... */

	bool reverse_dir;
	TcpConnection *con = cm.findTcpConnection(&c, reverse_dir);
	if (!con) {
		reverse_dir = false;
		con = cm.addTcpConnection(&c, this);
		if (!con) return -1; /* can't add new connection */
	}
	return con->processPacket(ts, data, data_len, reverse_dir); /* handle current packet inside TCP connection context */
}

int TcpHandler::initContext(ProtocolHandlerContext *handlers)
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

void TcpHandler::releaseContext()
{
	sip = NULL;

	// clear all connections
	cm.cleanup();
}

#define DOES_NOT_CARRY_SIP	1
#define CARRIES_SIP			2

unsigned int TcpHandler::processData(unsigned char* data, unsigned int data_len, 
		TcpData *params, struct timeval *ts, TcpConnection *c)
{
	if (data_len < 1) return 0; // ignore empty data
	if (!c) return 0; // bug

	unsigned int flags = c->getUserFlags();
	int can_be_sip = 0;

	log->TRACE("handling ACKNOWLEDGED DATA (%u sec):\n---\n%.*s\n---\n", ts->tv_sec, data_len, data);

	if (!(flags & (DOES_NOT_CARRY_SIP | CARRIES_SIP))) {
		// we don't know if this connection caries SIP
		// starts like SIP? - if yes set connection user flags
		int is = is_sip(data, data_len);
		switch (is) {
			case -1: 
				flags |= DOES_NOT_CARRY_SIP;
				c->setUserFlags(flags);
				can_be_sip = 0;
//				log->TRACE("NOT SIP\n");
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
//			log->TRACE("trying SIP\n");
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

# if 0
	//TODO: add DNS handling

	if (dns && (params->dst.port == 53 || params->src.port == 53)) { 
		/* DNS is binary and has no identification - needed to guess according
		 * ports? */
		if (dns->processPacket(ts, data, data_len, params) == 0) return;
	}
#endif

	return processed;
}

//////////////////////////////////////////////////////////////

protocol_id_t TcpData::identify() 
{ 
	return TcpHandler::id; 
}

//////////////////////////////////////////////////////////////

TcpDestination::TcpDestination(IPAddress &ip_addr, 
		unsigned int port, bool ignore_port):
	IPDestination(ip_addr)
{
	this->port = port;
	ignorePort = ignore_port;
}
		
TcpDestination::TcpDestination(TcpDestination *d): IPDestination(d ? &d->ip_addr: NULL)
{
	if (d) this->port = d->port;
	this->ignorePort = false;
}

Destination *TcpDestination::duplicate()
{
	Destination *d = new TcpDestination(ip_addr, port, ignorePort);
	if (d && name) d->setName(name);
	return d;
}

bool TcpDestination::equals(Destination *d)
{
	if (!d) return false;
	if (d->identify() != identify()) return false;
	if (! (ignorePort || ((TcpDestination*)d)->ignorePort) ) {
		if (port != ((TcpDestination*)d)->port) return false;
	}
	return IPDestination::equals(d);
}

void TcpDestination::printValue(std::ostream &os)
{
	os << "tcp:";
	IPDestination::printValue(os);
	if (!ignorePort) os << ":" << port;
}

protocol_id_t TcpDestination::identify() 
{ 
	return TcpHandler::id; 
}
