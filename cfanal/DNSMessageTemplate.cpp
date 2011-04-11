#include "DNSMessageTemplate.h"

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
		
bool DNSExistenceRule::readRule(xmlNode *n)
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

void DNSExistenceRule::print(std::ostream &os)
{
	if (existence_ok) os << "exists";
	else os << "shouldn't exist";
}
		
bool DNSExistenceRule::verify(DNSMessage *m) 
{ 
	if (!existence_ok) printf("message shouldn't be present\n");
	return existence_ok; 
}

/////////////////////////////////////////////////

bool DNSMessageTemplate::handleRule(xmlNode *n)
{
	char *c = xmltext2text(n->name);
	bool res = true;

	if (c) {
		if (strcmp(c, "fail") == 0) {
			DNSMessageRule *h = new DNSExistenceRule(false);
			if (!h) res = false;
			else {
				//res = h->readRule(n);
				addRule(h);
			}
		}
		else if (strcmp(c, "exists") == 0) {
			DNSMessageRule *h = new DNSExistenceRule(true);
			if (!h) res = false;
			else {
				res = h->readRule(n);
				addRule(h);
			}
		}
		
		free(c);
	}
	return res;
}
		
bool DNSMessageTemplate::readRules(xmlNode *n)
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
		
void DNSMessageTemplate::addRule(DNSMessageRule *r)
{
	r->next = rules;
	rules = r;
}

bool DNSMessageTemplate::readFromXMLElement(xmlNode *n)
{
	char *type;
	
	name = getXmlAttr(n, "name");
	if (!name) {
		printf("missing queried name in DNS message in flow template!\n");
		return false;
	}
	type = getXmlAttr(n, "type");
	if (type) {
		query_type = str2qtype(type);
		free(type);
	}
	else query_type = TYPE_A;  // default query

	if (!MessageTemplate::readFromXMLElement(n)) return false;
	return readRules(n);
}
		
DNSMessageTemplate::~DNSMessageTemplate()
{
	if (name) free(name);
}

bool DNSMessageTemplate::matches(Message *m)
{
	if (strcmp(m->identify(), identify()) != 0) return false;

	DNSMessage *mm = (DNSMessage *)m;

	if (is_request != !mm->isReply()) return false;
	if (name) { if (!mm->queriesName(name)) return false; }

	if (!src.find(m->getSrc())) return false;
	if (!dst.find(m->getDst())) return false;

	return true;
}
		
bool DNSMessageTemplate::verify(Message *m)
{
	DNSMessageRule *r = rules;
	while (r) {
		if (!r->verify((DNSMessage*)m)) {
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

void DNSMessageTemplate::print(std::ostream &os)
{
	if (is_request) os << "DNS request - ";
	else os << "DNS response - ";
	os << qtype2str(query_type);
	if (name) os << " " << name;
	os << " ";

	src.print(os, "/");
	os << " -> ";
	dst.print(os, "/");
	os << "\n";
}
