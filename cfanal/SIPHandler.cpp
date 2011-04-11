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

#include "SIPHandler.h"
#include "UdpHandler.h"
#include "TcpHandler.h"
#include "SCTPHandler.h"
#include "helper.h"

#include <string.h>

/* debuging */
#include <iostream>
using namespace std;

protocol_id_t SIPHandler::id = "sip";

class OSIPInitializer
{
	protected:
		bool initialized;
		osip_t *osip;

	public:
		bool isInitialized() { return initialized; }
		OSIPInitializer() { 
			osip = NULL;
			if (osip_init(&osip) != 0) initialized = false;
			else initialized = true;
		}
};

static OSIPInitializer osip;

static const unsigned char *findBody(const unsigned char *data, unsigned int data_len)
{
	unsigned int i;
	enum states { start, cr, crlf, crlfcr, crlfcrlf } s = start;
	for (i = 0; i < data_len; i++) {
		//printf("in state %d handling %X\n", s, data[i]);
		switch (s) {
			case start: 
				if (data[i] == '\r') s = cr;
				if (data[i] == '\n') s = crlf; // hack for LFLF
				break;

			case cr:
				if (data[i] == '\n') s = crlf;
				else {
					if (data[i] == '\r') s = cr;
					else s = start;
				}
				break;

			case crlf:
				if (data[i] == '\r') s = crlfcr;
				else {
					if (data[i] == '\n') {
						s = crlfcrlf; // hack for LFLF
						return data + i + 1;
					}
					else s = start;
				}
				break;

			case crlfcr:
				if (data[i] == '\n') {
					s = crlfcrlf;
					return data + i + 1; // doesn't matter if exists
				}
				else {
					if (data[i] == '\r') s = cr;
					else s = start;
				}
				break;
			
			case crlfcrlf:
				return data + i; //if exists...

			
		}
	}
	return NULL;
}

int SIPHandler::processPacket(struct timeval *ts, unsigned char *data, 
		unsigned int data_len, ProtocolData *parent)
{
	Destination *dst = NULL, *src = NULL;

	if (!data) return -1;
	if (!osip.isInitialized()) {
		log->error("osip library is NOT initialized - can't handle SIP\n");
		return -1;
	}

	MessageFlow *flow = context->getMessageFlow();
	if (!flow) {
		log->error("no destination message flow\n");
		return -1;
	}

	log->trace("handling SIP packet\n");

	// debugging!!!
/*	if (parent) {
		if (parent->identify() == UdpHandler::id) {
			u = (UdpData*)parent;
			cout << "message from: "; 
			u->src.cfprintValue(cout);
			cout << " to: ";
			u->dst.cfprintValue(cout);
			cout << "\n";
		
			printf("%u bytes:\n%.*s\n", data_len, data_len, data);
		}
	}*/

	/* try to parse as SIP, if OK return 0 */
	osip_message_t *msg = NULL;

	if (osip_message_init(&msg) == 0) {
		if (osip_message_parse(msg, (const char*)data, data_len) < 0) {
			osip_message_free(msg);
			msg = NULL;
		}
	}
	if (!msg) {
		log->trace("invalid SIP message (%u bytes):\n%.*s\n", data_len, data_len, data);
		return -1; /* not SIP */
	}
	log->trace(" ... SIP message parsed\n");

	// compute really caried bytes (because of TCP)
	const unsigned char *body_start = findBody(data, data_len);
	if (!body_start) {
		log->error("invalid SIP message (no EOH) but parsed by osip\n");
	}
	else {
		// set data_len to data which were really parsed
		char *clen = NULL;
		int content_len = 0;
		if (msg->content_length) clen = msg->content_length->value;
		if (clen) content_len = atoi(clen);
		data_len = content_len + (body_start - data);
	}
	processedBytes += data_len;

	if (!createMessages) {
		/* processed here but should not be processed more */
		osip_message_free(msg);
		return 0; 	
	}

	// ignore OPTIONS requests and responses if configured to do so
	if (ignoreOPTIONS) {
		char *m = NULL;
		if (msg->cseq) m = osip_cseq_get_method(msg->cseq);
		if (m && (strcmp(m, "OPTIONS") == 0)) {
			osip_message_free(msg);
			return 0; 	
		}
	}
	
	if (parent) {
		if (parent->identify() == UdpHandler::id) {
			/* SIP over UDP */
			UdpData *u = (UdpData*)parent;
			src = flow->knownDestination(&u->src);
			dst = flow->knownDestination(&u->dst);
			/*log->trace("  SIP over UDP+IP: - src: %08x:%u, dst: %08x:%u\n", 
					u->ip->src, u->src_port,
					u->ip->dst, u->dst_port);
			*/
		}
		if (parent->identify() == TcpHandler::id) {
			/* SIP over TCP */
			TcpData *t = (TcpData*)parent;
			src = flow->knownDestination(&t->src);
			dst = flow->knownDestination(&t->dst);
			/*log->trace("  SIP over TCP+IP: - src: %08x:%u, dst: %08x:%u\n", 
					t->ip->src, t->src_port,
					t->ip->dst, t->dst_port);
			*/
		}
		if (parent->identify() == SCTPHandler::id) {
			/* SIP over SCTP */
			SCTPData *t = (SCTPData*)parent;
			src = flow->knownDestination(&t->src);
			dst = flow->knownDestination(&t->dst);
			/*log->trace("  SIP over TCP+IP: - src: %08x:%u, dst: %08x:%u\n", 
					t->ip->src, t->src_port,
					t->ip->dst, t->dst_port);
			*/
		}
		
	}

	const char *tx_id = SIPTransaction::getTransactionID(msg);
	if (!tx_id) {
		static const char *strange = "???";
		tx_id = strange;
		log->error("invalid SIP message received over %s (%u bytes) - no Via:\n%.*s\n", 
				parent->identify(), data_len, data_len, data);
	}
	SIPTransaction *tx = tm.find(tx_id);
	if (!tx) tx = tm.add(tx_id);

	SIPMessage *m = new SIPMessage(ts, src, dst, msg, tx, 
			(const char *)data, data_len);
	if (!m) {
		osip_message_free(msg);
		return -1;
	}
	flow->add(m);
	return 0; // handled this amount of data
}

int SIPHandler::initContext(ProtocolHandlerContext *handlers)
{
	if (ProtocolHandler::initContext(handlers) < 0) return -1;

	return 0;
}

void SIPHandler::releaseContext()
{
	ProtocolHandler::releaseContext();
}

////////////////////////////////////////////////////////////////////////////////////////

SIPMessage::SIPMessage(struct timeval *ts,
		Destination *src,
		Destination *dst, 
		osip_message_t *sip_message,
		SIPTransaction *tx,
		const char *txt_msg,
		unsigned int txt_msg_len): Message(src, dst, ts)
{
	msg = sip_message;
	transaction = tx;
	if (txt_msg && (txt_msg_len > 0)) {
		messageText = (char *)malloc(txt_msg_len);
		if (messageText) {
			memcpy(messageText, txt_msg, txt_msg_len);
			messageTextLen = txt_msg_len;
		}
		else messageTextLen = 0; /* error here */
	}
	else {
		messageText = NULL;
		messageTextLen = 0;
	}
}

SIPMessage::~SIPMessage()
{
	if (msg) osip_message_free(msg);
	if (messageText) free(messageText);
}

/* static long int abs_delta_us(struct timeval *a, struct timeval *b)
{
	long int d;
	d = (a->tv_sec - b->tv_sec) * 1000000 + (a->tv_usec - b->tv_usec);
	if (d < 0) d = -d;
	return d;
} */

void SIPMessage::cfprint(std::ostream &os)
{
	char default_color[] = "black";
	const char *color = default_color;
	//char tmp[256];

	os << "<call";
//	os << " at " << timeStamp.tv_sec << " s " << timeStamp.tv_usec << " us";
	os << " src='";
	if (src) src->printName(os);
	else os << "???";
	os << "' dst='";
	if (dst) dst->printName(os);
	else os << "???";
	os << "' desc='";

	// message text
	if (MSG_IS_REQUEST(msg)) {
		os << osip_message_get_method(msg);
	}
	else {
		os << osip_message_get_status_code(msg);
	}
#if 0		
	os << " (" << msg->cseq->number << ")";

	osip_header_t *h;
	int i;
	char *c;
	for (i = 0; i < osip_list_size(&msg->headers); i++) {
		h = (osip_header_t*)osip_list_get(&msg->headers, i);
		if (!h) continue;
		c = osip_header_get_name(h);
		if (strcasecmp(c, "RSeq") == 0) {
				os << ", RSeq " << osip_header_get_value(h);
		}
		else if (strcasecmp(c, "RAck") == 0) {
				os << ", RAck " << atoi(osip_header_get_value(h));
		}
	}
#endif
	if (transaction) {
		if (transaction->cfPrintParams.color) 
			color = transaction->cfPrintParams.color;
	}

#if 0
	if (prev) {
		long int d = abs_delta_us(&timeStamp, &(prev->timeStamp));
		os << " (+" << d / 1000 << " ms)"; // experimental
	}
	
	os << " (" << messageTextLen << " B)"; // experimental
#endif


	os << "' color='";
	os << color;
	if (dst) {
		os << "' line-type='";
		dst->printLineType(os);
	}
	os << "'/>";

/*	src->snprint(tmp, sizeof(tmp));
	printf("   src: %s\n", tmp); 
	dst->snprint(tmp, sizeof(tmp));
	printf("   dst: %s\n", tmp); */
}

void SIPMessage::txtprint(std::ostream &os)
{
	Message::txtprint(os);

	if (messageText) {
		os << "\n";
		os.write(messageText, messageTextLen);
		os << "\n";
	}
}

////////////////////////////////////////////////////////////////////////////////////////

const char *SIPTransaction::colors[] = {
	"black", "blue", "red", "magenta", 
	"orange", "green", "gold", "brown", "gray",
	NULL
};

/* static char *branchToVia(const char *branch)
{
	const char *magic = "z9hG4bK";
	if (strstr(branch, magic) == branch) 
		return strdup(branch + strlen(magic));
	return strdup(branch);
} */

const char *SIPTransaction::getTransactionID(osip_message_t *msg)
{
	/*TODO: not only SIP 2.0 transaction IDs */
	static char strange1[] = "?";
	static char strange2[] = "??";
	static char branch[] = "branch";
	static Log *log = NULL;
	
	char *id = strange1;
#ifdef older_osip
	if (msg->vias) {
		osip_via_t *via = (osip_via_t*)osip_list_get(msg->vias, 0);
#else
		osip_via_t *via = (osip_via_t*)osip_list_get(&msg->vias, 0);
#endif
		if (via) {
			osip_generic_param_t *bp = NULL;
			if (osip_via_param_get_byname(via, branch, &bp) == 0) {
				if (bp) {
					char *branch = osip_generic_param_get_value(bp);
					if (!branch) return strange2;
					return branch;
					/* if (branch) id = branchToVia(branch); */
				}
			}
		}
#ifdef older_osip
	}
#endif
	else {
		if (!log) log = LogManager::getDefaultLog(NULL);
		if (log) log->error("no Vias in the message\n");
		return NULL;
	}
	return id;
	
}

////////////////////////////////////////////////////////////////////////////////////////


SIPTransactionManager::~SIPTransactionManager()
{
	SIPTransaction *n, *t = first;
	while (t) {
		n = t->next;
		delete t;
		t = n;
	}
}

SIPTransaction *SIPTransactionManager::find(const char *transaction_id)
{
	if (!transaction_id) {
		/* no transaction ID (stateless msg?) */
		return NULL;
	}

	SIPTransaction *t = first;
	while (t) {
		if (strcmp(transaction_id, t->id) == 0) return t; 
		t = t->next;
	}
	return NULL;
}

SIPTransaction *SIPTransactionManager::add(const char *transaction_id)
{
	//if (!transaction_id) return NULL;
	SIPTransaction *tx = new SIPTransaction(transaction_id);
	if (tx) {
		tx->next = NULL;
		tx->prev = last;
		if (last) last->next = tx;
		else first = tx;
		last = tx;

		tx->cfPrintParams.color = SIPTransaction::colors[currentColorIndex];
		if (SIPTransaction::colors[currentColorIndex]) {
			/* only if current wasn't the last - this would be a bug */
			if (!SIPTransaction::colors[++currentColorIndex])
				currentColorIndex = 0;
		}
	}
	return tx;
}

SIPTransaction::SIPTransaction(const char *transaction_id)
{
	static Log *log = NULL;

	if (transaction_id) {
		id = strdup(transaction_id);
		if (!id) {
			if (!log) log = LogManager::getDefaultLog(NULL);
			if (log) log->error("can't allocate memory\n");
		}
	}
	else id = NULL;
}

//////////////////////////////////////////////////////////////////////////////////////

int is_sip(unsigned char *data, unsigned int data_len)
{
	static const char *sip_version = "SIP/2.0";
	static unsigned int sip_version_len = 7;

	// is it SIP response?
	if (data_len >= sip_version_len) {
		if (strncmp((const char *)data, sip_version, sip_version_len) == 0) return 1; //it seems to be reply
		// else definitly not SIP reply
	}

	// try to handle it as a request
	unsigned int j = 0; // position in sip_version

	for (unsigned int i = 0; i < data_len; i++) {
		if (j == sip_version_len) {
			if (data[i] == '\r') return 1; //version followed by CR - high probability to be SIP
			if (data[i] == '\n') return 1; //it can be 'invalid message' with LF instead of CRLF (netcat sent)
			//printf("neni SIP (%c) \n", data[i]);
			return -1; // definitly not SIP
		}

		// definitly not SIP
		if (data[i] == '\r') {
			return -1;
		}
		if (data[i] == '\n') {
			return -1;
		}
		if (data[i] < ' ') {
			//printf("obsahuje %c, neni SIP\n", data[i]);
			return -1;
		}

		if (data[i] != sip_version[j]) {
			i -= j;
			j = 0;
			continue;
		}
		else j++;
	}
	

	return 0; /* who knows, but now we don't have enough info */
}

