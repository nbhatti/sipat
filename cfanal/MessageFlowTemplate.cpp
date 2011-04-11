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

#include <stdio.h>
#include <string.h>

#include "MessageFlowTemplate.h"
#include "IPHandler.h"
#include "UdpHandler.h"
#include "TcpHandler.h"
#include "SCTPHandler.h"
#include "DNSHandler.h"

#include <iostream>
	

bool text2bool(const char *text)
{
	if (strcasecmp(text, "y") == 0) return true;
	if (strcasecmp(text, "yes") == 0) return true;
	if (strcasecmp(text, "true") == 0) return true;
	if (strcasecmp(text, "1") == 0) return true;
	return false;
}

bool xmltext2bool(const xmlChar *xmltext)
{
	char *text;
	int ilen, olen;

	ilen = xmlStrlen(xmltext);
	olen = ilen + 1;
	text = (char *)malloc(sizeof(char) * olen);

	if (UTF8Toisolat1((unsigned char*)text, &olen, xmltext, &ilen) != ilen) return false;
	text[ilen] = 0;

	bool r = text2bool(text);
	free(text);
	return r;
}

char *xmltext2text(const xmlChar *xmltext)
{
	char *text;
	int ilen, olen;

	ilen = xmlStrlen(xmltext);
	olen = ilen + 1;
	text = (char *)malloc(sizeof(char) * olen);

	if (UTF8Toisolat1((unsigned char*)text, &olen, xmltext, &ilen) != ilen) return false;
	text[ilen] = 0;

	return text;
}

char *getXmlAttr(xmlNode *n, const char *name)
{
	char *res = NULL;
	xmlChar *attr = xmlGetProp(n, BAD_CAST(name));
	if (attr) {
		res = xmltext2text(attr);
		free(attr);
	}
	return res;
}

////////////////////////////////////////////////////////////////////////////////////

static bool readIPandPort(unsigned char *addr, unsigned int *dst_port, 
		const char *s, unsigned int len, bool *ignore_port)
{
	int ip, idx;

	enum { read_ip, read_port } state;
	
	state = read_ip;
	ip = 0;
	idx = 0;
	*dst_port = 0;
	*ignore_port = true; /* port not given */
	for (unsigned int i = 0; i < len; i++) {
		switch (state) {
			case read_ip:
				if ((s[i] >= '0') && (s[i] <= '9')) {
					ip = 10 * ip + (s[i] - '0');
				}
				else {
					if (s[i] == '.') {
						addr[idx] = (unsigned char)ip;
						if (idx == 3) state = read_port;
						else {
							idx++;
							ip = 0;
						}
					}
					else {
						if (s[i] == ':') {
							addr[idx] = (unsigned char)ip;
							state = read_port;
						}
						else return false;
					}
				}
				break;

			case read_port:
				if ((s[i] >= '0') && (s[i] <= '9')) {
					*dst_port = 10 * (*dst_port) + (s[i] - '0');
					*ignore_port = false;
				}
				else {
					if (s[i] == '*') {
						if (!(*ignore_port)) return false; /* already tried to set port */
						*dst_port = 0;
					}
					else return false;
				}
				break;
		}

	}
	if (state == read_ip) {
		addr[idx] = (unsigned char)ip;
		if (idx == 3) return true;
		else return false;
	}

	return true;
}
		
Destination *readBasicDestination(const char *proto, 
		unsigned int proto_len,
		const char *addr, unsigned int addr_len)
{
	unsigned int port;
	unsigned char ip_addr[4];
	bool ignore_port;
	Destination *d = NULL;

#define check_proto(p)	((strlen(p) == proto_len) && (strncasecmp(p, proto, proto_len) == 0))
	
	//printf("reading address: %.*s\n", addr_len, addr);
	if (!readIPandPort(ip_addr, &port, addr, addr_len, &ignore_port)) return NULL; // different format

	IPAddress ip(ip_addr);

	if (check_proto("udp"))
		d = new UdpDestination(ip, port, ignore_port);

	if (check_proto("tcp"))
		d = new TcpDestination(ip, port, ignore_port);

	if (check_proto("sctp")) 
		d = new SCTPDestination(ip, port, ignore_port);

	return d;
}

static const char *_strnchr(const char *text, int len, int c)
{
	int i;
	for (i = 0; (i < len) && (text[i]); i++)
		if (text[i] == c) return text + i;
	return NULL;
}

bool MessageTemplate::readDestination(DestinationList *dst, const char *text, int len)
{
	Destination *d;
	const char *proto, *addr;
	
	proto = text;
	addr = _strnchr(text, len, ':');
	if (addr) { 
		d = readBasicDestination(proto, addr - proto, addr + 1, len - (addr - text + 1));
		if (!d) {
			// couldn't read the destination, was it really protocol:address?
			// try to read it like if no protocol was specified
			addr = NULL;
		}
		else {
			// we have destination
			dst->add(d);
			return true;
		}
	}

	if (!addr) { 
		// protocol not given (or couldn't be handled), try all known protocols
		d = readBasicDestination("udp", 3, text, len);
		if (!d) {
			// impossible to read address -> it is probably alias name instead of IP address
			// or bad address
			/* FIXME: d = new NamedDestination(text);
			if (!d) {
				return false;
			}*/
		}
		else dst->add(d);
		d = readBasicDestination("tcp", 3, text, len);
		if (d) dst->add(d);
		d = readBasicDestination("sctp", 4, text, len);
		if (d) dst->add(d);
	}

	return true;
}

bool MessageTemplate::readDestinationList(DestinationList *dst, const xmlChar *txt_destination)
{
	char *text;
	const char *addr, *next;
	int len;

	text = xmltext2text(txt_destination);
	if (!text) return false;
	//len = strlen(text);

	addr = text;
	while (addr) {
		next = strchr(addr, '|');
		if (next) len = next - addr;
		else len = strlen(addr);
		if (!readDestination(dst, addr, len)) return false;
		if (next) addr = next + 1;
		else addr = NULL;
	}

	free(text);
	return true;
}
		
bool MessageTemplate::readFromXMLElement(xmlNode *n)
{
	if (!n) return false;

	bool res = true;

	xmlChar *src = xmlGetProp(n, BAD_CAST("src"));
	xmlChar *dst = xmlGetProp(n, BAD_CAST("dst"));
	xmlChar *opt = xmlGetProp(n, BAD_CAST("optional"));
	if (src) {
		if (!readDestinationList(&this->src, src)) res = false;
		free(src);
	}
	if (dst) {
		if (!readDestinationList(&this->dst, dst)) res = false;
		free(dst);
	}
	if (opt) optional = xmltext2bool(opt);
	return res;
}

bool MessageTemplate::matches(Message *m)
{
	if (!src.find(m->getSrc())) return false;
	if (!dst.find(m->getDst())) return false;
	return true;
}

void MessageTemplate::print(std::ostream &os)
{
	src.print(os, "/");
	os << " -> ";
	dst.print(os, "/");
	os << "\n";
}

////////////////////////////////////////////////////////////////////////////////////

MessageFlowTemplate::MessageFlowTemplate(bool ignore_unexpected_dns)
{
	first = NULL;
	last = NULL;
	this->ignore_unexpected_dns = ignore_unexpected_dns; 
}

MessageFlowTemplate::~MessageFlowTemplate()
{
	MessageTemplateFactoryElement *n, *e = first;
	while (e) {
		n = e->next;
		delete e->factory;
		free(e->template_name);
		free(e);
		e = n;
	}
}

bool MessageFlowTemplate::handleXMLElement(xmlNode *n)
{
	// find the right factory and create a message template for this element
	// TODO?: try to make tree from factories according names
	// Warning: ignoring namespaces!

	MessageTemplateFactoryElement *e = first;
	while (e) {
		if (xmlStrcasecmp(n->name, e->template_name) == 0) {
			// right factory found -> create message template and try to read it
			MessageTemplate *t = e->factory->createMessageTemplate();
			if (!t) return false;
			if (!t->readFromXMLElement(n)) {
				// can't read from this element, something is wrong
				delete t;
				return false;
			}
			addMessage(t);
			return true;
		}
		e = e->next;
	}
	printf("unknown message template type\n");

	return false;
}

bool MessageFlowTemplate::readFromXMLFile(const char *filename)
{
	FILE *f = fopen(filename, "rb");
	int len = 0;
	char *content;

	// read data from file (at once, it should be reasonably small because it is
	// just configuration)
	if (f) {
		fseek(f, 0, SEEK_END);
		len = ftell(f);
		if (len < 1) len = 0;
		else {
			content = (char *)malloc(len + 1);
			if (!content) {
				//ERROR_LOG("can't allocate memory for file content (%d bytes)\n", dst->len);
				len = 0;
			}
			else {
				fseek(f, 0, SEEK_SET);
				len = fread(content, 1, len, f);
				if (len < 1) {
					free(content);
					len = 0;
				}
				else content[len] = 0;
			}
			
		}
		fclose(f);
	}
	if (len < 1) return false;

	// read message templates from XML nodes

	first_message = NULL;
	last_message = NULL;

	xmlInitParser();

	bool result = true;
	xmlDocPtr doc;
	int xml_parser_flags = XML_PARSE_NOERROR | XML_PARSE_NOWARNING;
	doc = xmlReadMemory(content, len, NULL, NULL, xml_parser_flags);
	xmlNode *root = xmlDocGetRootElement(doc);
	xmlNode *n;
	if (!root) n = NULL;
	else n = root->children;
	while (n) {
		if (n->type == XML_ELEMENT_NODE) {
			if (!handleXMLElement(n)) {
				result = false;
				break;
			}
		}
		n = n->next;
	}

	xmlCleanupParser();
	free(content);
	return result;
}

void MessageFlowTemplate::addMessage(MessageTemplate *t)
{
	if (!t) return;

	t->next = NULL;
	t->prev = last_message;
	if (last_message) last_message->next = t;
	else first_message = t;
	last_message = t;
}

bool MessageFlowTemplate::registerTemplate(const char *template_name, MessageTemplateFactory *factory)
{
	if ((!factory) || (!template_name)) return false;

	MessageTemplateFactoryElement *e = (MessageTemplateFactoryElement *)malloc(sizeof(MessageTemplateFactoryElement));
	if (!e) return false;

	e->template_name = xmlCharStrdup(template_name);
	e->factory = factory;
	e->next = NULL;
	e->prev = last;
	if (last) last->next = e;
	else first = e;
	last = e;

	return true;
}

MessageTemplate *MessageFlowTemplate::findMessageTemplate(Message *m, MessageTemplate *currently_expected)
{
	MessageTemplate *t;

	// try following messages
	t = currently_expected;
	while (t) {
		if (!t->matched_message) {
			if (t->matches(m)) return t; 
		}
		t = t->next;
	}

	// try messages before?
	t = currently_expected;
	while (t) {
		if (!t->matched_message) {
			if (t->matches(m)) return t; 
		}
		t = t->prev;
	}

	return NULL;
}
				
MessageTemplate *MessageFlowTemplate::findNextExpected(MessageTemplate *currently_expected)
{
	MessageTemplate *t;

	// try following messages
	t = currently_expected;
	while (t) {
		if (!t->matched_message) return t;
		t = t->next;
	}
	
	// try messages before?
	t = currently_expected;
	while (t) {
		if (!t->matched_message) return t;
		t = t->prev;
	}

	return NULL;
}

bool MessageFlowTemplate::verify(MessageFlow *flow)
{
	Message *m = flow->first;
	MessageTemplate *t, *expected = first_message;

	while (m) {
/*		printf("-------------------------------------\n");
		printf("Have message: \n");
		m->txtprint(std::cout);
		if (expected) { printf("expected message: "); expected->print(std::cout); }
		printf("\n");*/

		/* TODO: 
		if (ignore_retransmissions) {
			// verify that 'm' is retransmission of a previous message in 'flow'
			if (isRetransmission(m, flow)) { m = m->next; continue; } 
		} */
		t = findMessageTemplate(m, expected);
		if (!t) {
			if (ignore_unexpected_dns && (m->identify() == DNSHandler::id)) {
				// ignore non-matched DNS messages
				m = m->getNext();
				/* if (m) {
					printf("moving to next message: \n");
					m->txtprint(std::cout);
				}*/
				continue;
			}
			else {
				// unexpected message here
				printf("unexpected message\n");
				m->txtprint(std::cout);
				if (expected) {
					printf("expected message was\n");
					expected->print(std::cout);
				}
				printf("NONE message was expected!?\n");
				return false;
			}
		}
		else {
			if (t != expected) {
				if (!t->optional) { 
					// it is not a skipped (or outrun) optional message
					// if it is not optional message it can be outrun by optional messages
					// if there is at least one non-optional it is error
					MessageTemplate *tt = expected;
					while (tt) {
						if (tt == t) break;
						if (!tt->optional) break;
						tt = tt->next;
					}
					if (tt == t) expected = t; // just skipped optional message(s)
					else {
						// out of order message
						printf("out of order message\n");
						m->txtprint(std::cout);
						if (expected) {
							printf("expected message was\n");
							expected->print(std::cout);
						}
						return false;
					}
				}
			}
		}
		printf("matched: "); t->print(std::cout);
		t->matched_message = m;

		// verify the message here
		if (!t->verify(m)) {
			printf("message verification failed\n");
			m->txtprint(std::cout);
			return false;
		}
				
		//move to next expected message (not marked as found yet)
		expected = findNextExpected(expected);

		m = m->getNext();
	}

	// walk through message templates if there are any unmatched
	t = first_message;
	while (t) {
		if (!t->matched_message) {
			if (!t->optional) {
				printf("missing non-optional message\n");
				t->print(std::cout);
				return false;
			}
		}
		t = t->next;
	}

	return true;
}

