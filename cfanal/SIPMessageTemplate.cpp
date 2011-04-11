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

#include "SIPMessageTemplate.h"
#include "helper.h"

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
		
SIPHeaderRule::SIPHeaderRule()
{
	hdr_name = NULL;
	value = NULL;
}

SIPHeaderRule::~SIPHeaderRule()
{
	if (hdr_name) free(hdr_name);
	if (value) free(value);
}

bool SIPHeaderRule::readRule(xmlNode *n)
{
	char *c;
	bool res = true;

	c = getXmlAttr(n, "test");
	if (!c) return false;
	if (strcmp(c, "contains") == 0) test = CONTAINS;
	else if (strcmp(c, "exists") == 0) test = EXISTS;
	else if (strcmp(c, "does not contain") == 0) test = DOES_NOT_CONTAIN;
	else if (strcmp(c, "does not exist") == 0) test = DOES_NOT_EXIST;
	else {
		printf("unknow header rule test: %s\n", c);
		res = false;
	}
	free(c);

	hdr_name = getXmlAttr(n, "header");
	value = getXmlAttr(n, "value");

	if (!(hdr_name || value)) res = false;
	return res;
}

int ls_headers(const osip_message_t * sip)
{
  int i;
  osip_header_t *tmp;
  int pos = 0;

  printf("message headers:\n");
  i = pos;
  if (osip_list_size (&sip->headers) <= pos)
    return -1;                  /* NULL */
  while (osip_list_size (&sip->headers) > i)
    {
      tmp = (osip_header_t *) osip_list_get (&sip->headers, i);
	  printf(" ... %s: %s\n", tmp->hname, tmp->hvalue);
	  i++;
    }
  return -1;                    /* not found */
}

/*static int walk(osip_list_t *list, int pos, osip_header_t **dst)
{
	if (pos < osip_list_size(list)) {
		*dst = (osip_header_t *) osip_list_get(list, pos);
		return pos;
	}
	else {
		*dst = NULL;
		return -1;
	}
}*/

static int get_header(osip_message_t *m, const char *hdr_name, int pos,
		char **txt)
{
	void *dest;
	
	*txt = NULL;

#define IS_HDR(n)	(strcasecmp(hdr_name, n) == 0)
//	if (IS_HDR("route")) { return walk(&m->routes, pos, dst); }

	//printf("looking for %s from %d\n", hdr_name, pos);

//#define GET(a, f, type)	do { pos = osip_message_get_knownheaderlist(&m->a, pos, &dest); if (pos >= 0) { f((type*)dest, txt); }  } while(0)
#define GET(hdr_list, f, type)	do { \
	dest = osip_list_get(&m->hdr_list, pos); \
	/*printf("list elems: %d\n", m->hdr_list.nb_elt); */\
	if (dest) { f((type*)dest, txt); } \
	else pos = -1; \
} while(0)

	if (IS_HDR("record-route")) { GET(record_routes, osip_record_route_to_str, osip_record_route_t); }
	else if (IS_HDR("route")) { GET(routes, osip_route_to_str, osip_route_t); }
	else if (IS_HDR("via")) { GET(vias, osip_via_to_str, osip_via_t); }
	else if (IS_HDR("contact")) { GET(contacts, osip_contact_to_str, osip_contact_t); }
	else if (IS_HDR("r-uri")) { 
		if (pos == 0) {
			osip_uri_to_str(m->req_uri, txt);
		}
		else pos = -1;
	}
	else {
		osip_header_t *h = NULL;
		pos = osip_message_header_get_byname(m, hdr_name, pos, &h);
		if (h) *txt = osip_strdup(h->hvalue);
	}
#undef IF_HDR
	return pos;
}

bool SIPHeaderRule::verify(SIPMessage *m, MessageTemplate *t)
{
	int pos = 0;
	bool res;
	char *tmp;
	bool done = false;
	
	//ls_headers(m->msg);

	switch (test) {
		case CONTAINS: res = false; break;
		case DOES_NOT_CONTAIN: res = true; break;
		case EXISTS: res = false; break;
		case DOES_NOT_EXIST: res = true; break;
	}

	pos = get_header(m->msg, hdr_name, pos, &tmp);
	while (pos >= 0) {
		if (tmp) {
			//printf("*** header '%s' found: %d, value: %s\n", hdr_name, pos, tmp);

			switch (test) {
				case CONTAINS: 
					//printf("testing: %s in %s ... ", value, tmp);
					if (strstr(tmp, value)) {
						//printf("FOUND\n\n");
						res = true;
						done = true;
					}
					//else printf("NOT FOUND\n\n");
					break;
				case EXISTS: 
					res= true; 
					done = true; 
					break;
				case DOES_NOT_CONTAIN: 
					if (strstr(tmp, value)) {
						res = false;
						done = true;
					}
					break;
				case DOES_NOT_EXIST: 
					res = false;
					done = true;
					break;
			}
			if (tmp) osip_free(tmp);
		}
		if (done) break;
		pos = get_header(m->msg, hdr_name, pos + 1, &tmp);
	}
	return res;
}

void SIPHeaderRule::print(std::ostream &os)
{
	switch (test) {
		case CONTAINS: 
			os << hdr_name << " contains " << value;
			break;
		case DOES_NOT_CONTAIN: 
			os << hdr_name << " does not contain " << value;
			break;
		case EXISTS: 
			os << hdr_name << " exists";
			break;
		case DOES_NOT_EXIST: 
			os << hdr_name << " does not exist";
			break;
	}
}

////////////////////////////////////////////////////////////////////////

bool SIPExistenceRule::readRule(xmlNode *n)
{
	char *c;
	bool res = true;

	c = getXmlAttr(n, "result");
	if (!c) existence_ok = true;
	else {
		existence_ok = false;
		if (strcasecmp(c, "true") == 0) existence_ok = true;
		else if (strcasecmp(c, "1") == 0) existence_ok = true;
		else if (strcasecmp(c, "y") == 0) existence_ok = true;
		else if (strcasecmp(c, "yes") == 0) existence_ok = true;
		free(c);
	}

	return res;
}

void SIPExistenceRule::print(std::ostream &os)
{
	if (existence_ok) os << "exists";
	else os << "shouldn't exist";
}
		
bool SIPExistenceRule::verify(SIPMessage *m, MessageTemplate *t) 
{ 
	if (!existence_ok) printf("message shouldn't be present\n");
	return existence_ok; 
}

////////////////////////////////////////////////////////////////////////

double readTime(const char *t) // returns time in milliseconds
{
	return atof(t);
}

bool MessageDelayRule::readRule(xmlNode *n)
{
	char *s;

	s = getXmlAttr(n, "time");
	if (!s) {
		printf("missing time argument in 'delay' rule\n");
		return false;
	}
	delay = readTime(s);
	free(s);
	
	s = getXmlAttr(n, "tolerance");
	if (s) { 
		tolerance = readTime(s);
		free(s);
	}
	else tolerance = 0;
	return true;
}

bool MessageDelayRule::verify(SIPMessage *m, MessageTemplate *t)
{
	MessageTemplate *p = NULL;
	
	if (t) p = t->prev;
	if (p) {
		if (p->matched_message) {
			// find previous message matched in flow
			double d = (double)abs_delta_us(&m->timeStamp, &(p->matched_message->timeStamp)) / 1000000.0;
			//os << " (+" << d / 1000 << " ms)"; // experimental
			double min = delay - tolerance;
			double max = delay + tolerance;

			bool res = true;
			if (d < min) res = false;
			if (d > max) res = false;
			if (!res) printf("message delay %1.3f s outside tolerance %1.3f +/- %1.3f s\n", d, delay, tolerance);
			else printf("message delay %1.3f s in %1.3f +/- %1.3f s\n", d, delay, tolerance);
			return res;
		}
	}

		
	printf("can not measure message delay!\n");
	return false;
}

void MessageDelayRule::print(std::ostream &os)
{
	os << "delayed " << delay << " s +/- " << tolerance << " s";
}

/////////////////////////////////////////////////

bool SIPMessageTemplate::handleRule(xmlNode *n)
{
	char *c = xmltext2text(n->name);
	bool res = false;

	if (c) {
		if (strcmp(c, "header") == 0) {
			SIPHeaderRule *h = new SIPHeaderRule();
			if (!h) res = false;
			else {
				res = h->readRule(n);
				addRule(h);
			}
		}
		if (strcmp(c, "delay") == 0) {
			MessageDelayRule *h = new MessageDelayRule();
			if (!h) res = false;
			else {
				res = h->readRule(n);
				addRule(h);
			}
		}
		if (strcmp(c, "fail") == 0) {
			SIPMessageRule *h = new SIPExistenceRule(false);
			if (!h) res = false;
			else {
				res = true;
				addRule(h);
			}
		}
		if (strcmp(c, "exists") == 0) {
			SIPMessageRule *h = new SIPExistenceRule(true);
			if (!h) res = false;
			else {
				res = h->readRule(n);
				addRule(h);
			}
		}
		//printf("%s ... %s\n", c, res ? "ok": "failed");
		
		free(c);
	}
	return res;
}
		
bool SIPMessageTemplate::readRules(xmlNode *n)
{
	if (!n) return true;
	n = n->children;
	while (n) {
		if (n->type == XML_ELEMENT_NODE) {
			if (!handleRule(n)) return false;
		}
		n = n->next;
	}
	return true;
}
		
void SIPMessageTemplate::addRule(SIPMessageRule *r)
{
	r->next = rules;
	rules = r;
}

bool SIPMessageTemplate::readFromXMLElement(xmlNode *n)
{
	xmlChar *m;
	
	method = getXmlAttr(n, "method");
	if (!method) {
		printf("missing SIP method in flow template!\n");
		return false;
	}
	if (!is_request) {
		m = xmlGetProp(n, BAD_CAST("code"));
		if (!m) {
			printf("missing SIP reply code in flow template!\n");
			return false;
		}
		else {
			char *c = xmltext2text(m);
			if (c) reply_code = atoi(c);
			free(c);
		}
	}
	if (!MessageTemplate::readFromXMLElement(n)) return false;
	return readRules(n);
}
		
SIPMessageTemplate::~SIPMessageTemplate()
{
	if (method) free(method);
}

bool SIPMessageTemplate::matches(Message *m)
{
	if (strcmp(m->identify(), identify()) != 0) return false;

	SIPMessage *mm = (SIPMessage *)m;

	if (is_request) {
		if (!MSG_IS_REQUEST(mm->msg)) return false;
		if (strcmp(mm->msg->sip_method, method) != 0) return false;
	}
	else {
		// compare CSeq method with method
		// compare reply_code

		if (mm->msg->cseq) {
			if (strcmp(mm->msg->cseq->method, method) != 0) return false;
			if (reply_code != osip_message_get_status_code(mm->msg)) return false;
		}
		else {
			printf("wrong sip message?\n");
			return false; //wrong SIP message?
		}
	}

	if (!src.find(m->getSrc())) return false;
	if (!dst.find(m->getDst())) return false;

	return true;
}
		
bool SIPMessageTemplate::verify(Message *m)
{
	SIPMessageRule *r = rules;
	while (r) {
		if (!r->verify((SIPMessage*)m, this)) {
			printf("rule verification failed: ");
			r->print(std::cout);
			printf("\n");
			return false;
		}
		else {
			printf("verified: ");
			r->print(std::cout);
			printf("\n");
		}
		r = r->next;
	}
	return true;
}

void SIPMessageTemplate::print(std::ostream &os)
{
	if (is_request) os << "SIP request - ";
	else {
		os << "SIP response - ";
		os << reply_code;
		os << " ";
	}
	if (method) os << method;
	else os << "unknown request";
	os << ", ";

	src.print(os, "/");
	os << " -> ";
	dst.print(os, "/");
	os << "\n";
}
