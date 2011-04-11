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

#include "DNSHandler.h"
#include "UdpHandler.h"
#include "bits.h"

#include <string.h>
#include <stdlib.h>

#define MAX_NAME_LENGTH	255

/* debuging */
#include <iostream>
#include <sstream>
using namespace std;

protocol_id_t DNSHandler::id = "dns";

unsigned int str2qtype(const char *s)
{
	if (strcmp(s, "A") == 0) return 1;
	if (strcmp(s, "NS") == 0) return TYPE_NS;
	if (strcmp(s, "CNAME") == 0) return 5;
	if (strcmp(s, "PTR") == 0) return 12;
	if (strcmp(s, "SRV") == 0) return TYPE_SRV;
	if (strcmp(s, "NAPTR") == 0) return TYPE_NAPTR;
	return 0;
}

const char *qtype2str(unsigned int qtype)
{
	switch (qtype) {
		/* type */
		case 1: return "A"; break;
		case TYPE_NS: return "NS"; break;
		case 3: return "MD"; break;
		case 4: return "MF"; break;
		case 5: return "CNAME"; break;
		case 6: return "SOA"; break;
		case 7: return "MB"; break;
		case 8: return "MG"; break;
		case 9: return "MR"; break;
		case 10: return "NULL"; break;
		case 11: return "WKS"; break;
		case 12: return "PTR"; break;
		case 13: return "HINFO"; break;
		case 14: return "MINFO"; break;
		case 15: return "MX"; break;
		case 16: return "TXT"; break;
		case TYPE_SRV: return "SRV"; break;
		case TYPE_NAPTR: return "NAPTR"; break;

		/* qtype */
		case 252: return "AXFR"; break;
		case 253: return "MAILB"; break;
		case 254: return "MAILA"; break;
		case 255: return "*"; break;
	}
	return "?";
}



int readName(unsigned int &offset, 
				unsigned char *data,
				char *dst, unsigned int dst_len)
{
	unsigned int len, tlen, x;
	tlen = 0;

//	printf(" qname: ");
	len = GET_BYTE(data, offset);
	offset += 1;
	while (len > 0) {
		if (len > 63) {
			if (len & 0xC0) {
				/* this is a compression - see RFC 1035 */
				//log->warning("needed compression implementation\n");
				x = GET_WORD(data, offset - 1) & 0x3FFF;
//				printf("  [offset 0x%x] ", x);
				offset += 1;
//				dst[tlen] = 0;
//				printf("\n");
				return readName(x, data, dst + tlen, dst_len - tlen);
				//return -1;
			}
			else {
				//?TODO: log->warning("unsupported non-compression extension\n");
				return -1;
			}
		}
//		printf("%.*s", len, data + offset);
		if (tlen + len + 2 > dst_len) {
			//?TODO: log->warning("truncated domain name length\n");
			dst[tlen] = 0;
			return 1;
		}
		memcpy(dst + tlen, data + offset, len);
		tlen += len;
		offset += len;
		len = GET_BYTE(data, offset);
		offset += 1;
		if (len > 0) {
			dst[tlen++] = '.';
//			printf(".");
		}
		else dst[tlen++] = 0;

	}
	
//	printf("\n");
	return 0;
}

#if 0
DNSResourceRecord *DNSHandler::readResourceRecord(unsigned int &offset, 
				unsigned char *data)
{
	unsigned int type, rr_class, ttl, rdlength;
	unsigned char tmp[MAX_NAME_LENGTH + 1];
	unsigned char tmp2[MAX_NAME_LENGTH + 1];
	unsigned char *rdata;

	readName(offset, data, tmp, sizeof(tmp));
	type = GET_WORD(data, offset);
	rr_class = GET_WORD(data, offset + 2);
	ttl = GET_DWORD(data, offset + 4);
	rdlength = GET_WORD(data, offset + 8);
	offset += 10;
//	printf(" NAME: %s, type: %Xh, class: %Xh, ttl: %d, rdlength: %d\n", 
//				tmp, type, rr_class, ttl, rdlength);

	rdata = data + offset;
	offset += rdlength;

	if (type == TYPE_NS) {
//		printf("\nIt is NS ... trying to guess rdata as name\n");
		unsigned int x = offset - rdlength;
//		printf(" ... %xh\n", GET_WORD(data, x));
		readName(x, data, tmp2, sizeof(tmp2));
		rdata = tmp2;
		rdlength = strlen((char *)tmp2);
//		printf("name: %.*s\n", rdlength, rdata);
	}
/*	if (type == TYPE_SRV) {
		unsigned int priority, weight, port;
		priority = GET_WORD(rdata, 0);
		weight = GET_WORD(rdata, 2);
		port = GET_WORD(rdata, 4);
		unsigned int x = 6;
		readName(x, rdata, tmp2, sizeof(tmp2));
		printf("SRV: priority:%u, weight: %u, port: %u, name: %s\n", 
				priority, weight, port, tmp2);
	}*/

	DNSResourceRecord *r = new DNSResourceRecord((char*)tmp, type, 
			rr_class, ttl, rdata, rdlength);
	if (r) {
		r->updateData(data, this);
	}
	else log->error("can't allocate memory for DNSResourceRecord\n");

	return r;
}
#endif

DNSHandler::DNSHandler(bool create_messages, bool ignore_ser_wd, bool ignore_ptr)
{
	this->createMessages = create_messages;
	ignoreSERWatchdog = ignore_ser_wd;
	ignorePTR = ignore_ptr;
}

DNSMessage *DNSHandler::parseDNS(struct timeval *ts, 
		Destination *src, Destination *dst,
		unsigned char *data, unsigned int data_len)
{
	unsigned short id;
	unsigned short flags;
	unsigned int qdcount, ancount, nscount, arcount;
	unsigned int i, offset;
	char tmp[MAX_NAME_LENGTH + 1];

	id = GET_WORD(data, 0);
	flags = GET_WORD(data, 2);
//	opcode = GET_WORD(data, 1) & 30;
	log->trace(" ID: %Xh (%u)\n", id, id);
	log->trace(" flags: %Xh\n", flags);
	log->trace(" QR: %X, OPCODE: %Xh, RD: %X\n", (flags & 0x8000) >> 15, 
			(flags & 0x7100) >> 11, (flags & 0x0100) >> 8);
	log->trace(" RCODE: %Xh\n", flags & 0x0F);

	qdcount = GET_WORD(data, 4);
	ancount = GET_WORD(data, 6);
	nscount = GET_WORD(data, 8);
	arcount = GET_WORD(data, 10);

	log->trace(" qdcount: %d, ancount: %d, nscount: %d, arcount: %d\n", 
		qdcount, ancount, nscount, arcount);

	offset = 12;
	
	DNSMessage *msg = new DNSMessage(ts, src, dst, id, flags);

//	printf("\nDNS query ID: %Xh, flags: %Xh\n", id, flags);
//	printf(" qdcount: %d, ancount: %d, nscount: %d, arcount: %d\n", 
//		qdcount, ancount, nscount, arcount);

	/* question section */
//	printf("question: \n");
	for (i = 0; i < qdcount; i++) {
		unsigned int qtype, qclass;

		readName(offset, data, tmp, sizeof(tmp));
		qtype = GET_WORD(data, offset);
		qclass = GET_WORD(data, offset + 2);
//		printf(" QNAME: %s, qtype: %Xh, qclass: %Xh\n", tmp, qtype, qclass);
		offset += 4;

		DNSQuestion *q = new DNSQuestion((char *)tmp, qtype, qclass);
		if (q) msg->addQuestion(q);
		else log->error("can't allocate memory for DNSQuestion\n");

	}

	/* answer section */
	for (i = 0; i < ancount; i++) {
		DNSResourceRecord *r = new DNSResourceRecord(data, offset);
		if (r) msg->addAnswer(r);
	}
	
	/* authority section */
	for (i = 0; i < nscount; i++) {
		DNSResourceRecord *r = new DNSResourceRecord(data, offset);
		if (r) {
			msg->addAuthority(r);
		}
	}
	
	/* additional section */
	for (i = 0; i < arcount; i++) {
		DNSResourceRecord *r = new DNSResourceRecord(data, offset);
		if (r) {
			msg->addAdditional(r);
		}
	}

	return msg;
}

int DNSHandler::processPacket(struct timeval *ts, unsigned char *data, 
		unsigned int data_len, ProtocolData *parent)
{
	UdpData *u;
	Destination *dst = NULL, *src = NULL;

	if (!data) return -1;

	if (!createMessages) return 0; /* don't care */

	MessageFlow *flow = context->getMessageFlow();
	if (!flow) {
		log->error("no destination message flow\n");
		return -1;
	}

	log->trace("handling DNS packet\n");

	if (parent) {
		if (parent->identify() == UdpHandler::id) {
			u = (UdpData*)parent;
/*			cout << "\nDNS message from: "; 
			u->src.printValue(cout);
			cout << " to: ";
			u->dst.printValue(cout);
			cout << "\n";*/
		
			//printf("%u bytes:\n%.*s\n", data_len, data_len, data);

			src = flow->knownDestination(&u->src);
			dst = flow->knownDestination(&u->dst);
			/*log->trace("  SIP over UDP+IP: - src: %08x:%u, dst: %08x:%u\n", 
					u->ip->src, u->src_port,
					u->ip->dst, u->dst_port);
			*/
		}
	}

	DNSMessage *msg = parseDNS(ts, src, dst, data, data_len);
	bool ignore = false;

	if (ignoreSERWatchdog) {
		/* ignore SER watchdog (SRV _sip._udp) queries */
		if (msg->isSerWatchdog()) ignore = true;
	}

	if (ignorePTR) {
		if (msg->isPTR()) ignore = true;
	}

	if (ignore) {
		/* ignore query */

		/* decrement usage counters of destinations to
		 * avoid displaying them if are not used by anybody
		 * else */
		if (src) src->decUsed();
		if (dst) dst->decUsed();

		delete msg;
		return 0; /* successfully processed */
	}

	if (msg) {
		flow->add(msg);
	}

	return 0;

}

////////////////////////////////////////////////////////////////////

DNSMessage::DNSMessage(struct timeval *ts,
				Destination *src, Destination *dst, 
				unsigned int id, unsigned int flags): Message(src, dst, ts)
{
	this->id = id;
	this->flags = flags;
	questionSection = NULL;
	lastQuestion = NULL;
	answerSection = NULL;
	lastAnswer = NULL;
	additionalSection = NULL;
	lastAdditional = NULL;
	authoritySection = NULL;
	lastAuthority = NULL;
}

DNSMessage::~DNSMessage()
{
	DNSQuestion *q = questionSection, *nq;
	while (q) {
		nq = q->next;
		delete q;
		q = nq;
	}
}

void DNSMessage::addQuestion(DNSQuestion *q)
{
	if (lastQuestion) lastQuestion->next = q;
	else questionSection = q;
	q->next = NULL;
	lastQuestion = q;
}

void DNSMessage::addAnswer(DNSResourceRecord *r)
{
	if (lastAnswer) lastAnswer->next = r;
	else answerSection = r;
	r->next = NULL;
	lastAnswer = r;
}

void DNSMessage::addAuthority(DNSResourceRecord *r)
{
	if (lastAuthority) lastAuthority->next = r;
	else authoritySection = r;
	r->next = NULL;
	lastAuthority = r;
}

void DNSMessage::addAdditional(DNSResourceRecord *r)
{
	if (lastAdditional) lastAdditional->next = r;
	else additionalSection = r;
	r->next = NULL;
	lastAdditional = r;
}

void DNSMessage::cfprint(std::ostream &os)
{
	char default_color[] = "black";
	const char *color = default_color;
	//char tmp[256];

	os << "<call";
//	os << " at " << timeStamp.tv_sec << " s " << timeStamp.tv_usec << " us";
	os << " src='";
	src->printName(os);
	os << "' dst='";
	dst->printName(os);
	os << "' desc='";

	// message text
	if (IS_DNS_REPLY(flags)) {
		os << "DNS R";
	}
	else {
		os << "DNS Q";
	}
	
	char tmp[64];
	sprintf(tmp, "0x%X", id);
	os << " " << tmp;

	DNSQuestion *q = questionSection;
	if (!IS_DNS_REPLY(flags)) {
		if (q) os << ": ";
		while (q) {
			printType(q->qtype, os);
			os << " ";// << q->qname;
			printName(q->qname, os);
			q = q->next;
		}
	}

	os << "' color='" << color;
	if (dst) {
		os << "' line-type='";
		dst->printLineType(os);
	}
	os << "'/>";

/*	if (transaction) {
		if (transaction->cfPrintParams.color) 
			color = transaction->cfPrintParams.color;
	}
	os << "' color='";
	os << color;
	os << "'/>"; */
}

bool DNSMessage::queriesName(const char *name)
{
	DNSQuestion *q = questionSection;
	while (q) {
		if (strcmp(name, q->qname) == 0) return true;
		q = q->next;
	}
	return false;
}

void DNSMessage::txtprint(std::ostream &os)
{
	Message::txtprint(os);
	char tmp[64];
	sprintf(tmp, "0x%X", id);

	os << "\n";
	if (IS_DNS_REPLY(flags)) {
		os << "DNS reply\n";
	}
	else {
		os << "DNS query\n";
	}
	os << "  ID: " << tmp << " ("<< id << ")\n"; 

	DNSQuestion *q = questionSection;
	if (q) os << "  Question section:\n";
	while (q) {
		os << "    " << q->qname << ", type: ";
		printType(q->qtype, os);
		os << ", class: ";
		printClass(q->qclass, os);

		os << "\n";
		q = q->next;
	}

	DNSResourceRecord *r;

	r = answerSection;
	if (r) os << "  Answer section:\n";
	while (r) {
		os << "    ";
		r->txtprint(os);

		os << "\n";
		r = r->next;
	}
	
	r = authoritySection;
	if (r) os << "  Authority section:\n";
	while (r) {
		os << "    ";
		r->txtprint(os);

		os << "\n";
		r = r->next;
	}

	r = additionalSection;
	if (r) os << "  Additional section:\n";
	while (r) {
		os << "    ";
		r->txtprint(os);

		os << "\n";
		r = r->next;
	}

}

void DNSMessage::printType(unsigned int qtype, std::ostream &os)
{
	switch (qtype) {
		/* type */
		case 1: os << "A"; break;
		case TYPE_NS: os << "NS"; break;
		case 3: os << "MD"; break;
		case 4: os << "MF"; break;
		case 5: os << "CNAME"; break;
		case 6: os << "SOA"; break;
		case 7: os << "MB"; break;
		case 8: os << "MG"; break;
		case 9: os << "MR"; break;
		case 10: os << "NULL"; break;
		case 11: os << "WKS"; break;
		case 12: os << "PTR"; break;
		case 13: os << "HINFO"; break;
		case 14: os << "MINFO"; break;
		case 15: os << "MX"; break;
		case 16: os << "TXT"; break;
		case TYPE_SRV: os << "SRV"; break;
		case TYPE_NAPTR: os << "NAPTR"; break;

		/* qtype */
		case 252: os << "AXFR"; break;
		case 253: os << "MAILB"; break;
		case 254: os << "MAILA"; break;
		case 255: os << "*"; break;

		default: os << qtype;
	}
}

void DNSMessage::printName(const char *name, std::ostream &os)
{
	// quick hack for strange names (in VFI-II dumps) 
	//TODO: repair correctly
	int wrong_chars = 0;
	for (char *cc = (char *)name; *cc; cc++) {
		unsigned int c = (unsigned char)(*cc);
		if ((c < 20) || (c > 127)) wrong_chars = 1;
	}
	if (!wrong_chars) os << name;
	else os << "???";
}


void DNSMessage::printClass(unsigned int qclass, std::ostream &os)
{
	switch (qclass) {
		/* class */
		case 1: os << "IN"; break;
		case 2: os << "CS"; break;
		case 3: os << "CH"; break;
		case 4: os << "HS"; break;

		/* qclass */
		case 255: os << "*"; break;

		default: os << qclass;
	}
}

bool DNSMessage::isSerWatchdog()
{
	if (!questionSection) return false; /* no question */
	if (questionSection != lastQuestion) return false; /* more than 1 */

	if (questionSection->qtype != TYPE_SRV) return false;
	if (questionSection->qclass != CLASS_IN) return false;
	if (!questionSection->qname) return false;
	return strcmp(questionSection->qname, "_sip._udp") == 0;
}

bool DNSMessage::isPTR()
{
	if (questionSection->qtype == TYPE_PTR) return true;
	return false;
}

////////////////////////////////////////////////////////////////////
		
DNSQuestion::DNSQuestion(const char *qname, 
		unsigned int qtype, unsigned int qclass)
{
	if (qname) this->qname = strdup(qname);
	else this->qname = NULL;
	this->qtype = qtype;
	this->qclass = qclass;
}

DNSQuestion::~DNSQuestion()
{
	if (qname) free(qname);
}

////////////////////////////////////////////////////////////////////
		
/*DNSResourceRecord::DNSResourceRecord(const char *name, unsigned int type, 
				unsigned int rr_class, unsigned int ttl,
				unsigned char *rdata, unsigned rdlength)
{
	if (name) this->name = strdup(name);
	else this->name = NULL;
	this->type = type;
	this->rr_class = rr_class;
	if (rdata && (rdlength > 0)) {
		this->rdata = (unsigned char *)malloc(rdlength);
		if (!this->rdata) this->rdlength = 0;
		else {
			this->rdlength = rdlength;
			memcpy(this->rdata, rdata, rdlength);
		}
	}
	else {
		this->rdlength = 0;
		this->rdata = NULL;
	}
}*/

DNSResourceRecord::DNSResourceRecord(unsigned char *data,
				unsigned int &offset)
{
	char tmp[MAX_NAME_LENGTH + 1];
	char tmp2[2 * MAX_NAME_LENGTH + 1];
	unsigned char *rdata_begin;

	readName(offset, data, tmp, sizeof(tmp));
	name = strdup(tmp);
	type = GET_WORD(data, offset);
	rr_class = GET_WORD(data, offset + 2);
	ttl = GET_DWORD(data, offset + 4);
	rdlength = GET_WORD(data, offset + 8);
	offset += 10;

	rdata_begin = data + offset;
	offset += rdlength;

	rdata = NULL;

	if (type == TYPE_NS) {
		unsigned int x = offset - rdlength;
		readName(x, data, tmp, sizeof(tmp));
		rdata = strdup(tmp);
	}
	if (type == TYPE_SRV) {
		srv_priority = GET_WORD(rdata_begin, 0);
		srv_weight = GET_WORD(rdata_begin, 2);
		srv_port = GET_WORD(rdata_begin, 4);

		unsigned int x = offset - rdlength + 6;
		readName(x, data, tmp, sizeof(tmp));
		sprintf(tmp2, " priority: %u, weight: %u, port: %u, name: %s", 
				srv_priority, srv_weight, srv_port, tmp);
		rdata = strdup(tmp2);
	}
	if ((rr_class == CLASS_IN) && (type == TYPE_A)) {
		stringstream ss;

		IPAddress ip(rdata_begin);
		IPDestination ip_dst(ip);

		//pbuf = ss.rdbuf();
		ss << "IP: ";
		ip_dst.printValue(ss);
		ss.flush();
		rdata = strdup(ss.str().c_str());
	}
}

DNSResourceRecord::~DNSResourceRecord()
{
	if (name) free(name);
	if (rdata) free(rdata);
}

		
void DNSResourceRecord::txtprint(std::ostream &os)
{
	os << name << ", type: ";
	DNSMessage::printType(type, os);
	os << ", class: ";
	DNSMessage::printClass(rr_class, os);

	if (rdata) {
		os << ", " << rdata;
	}
	else os << ", rdlength: " << rdlength;
}

