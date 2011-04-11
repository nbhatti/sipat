#ifndef __DNS_MESSAGE_TEMPLATE_H
#define __DNS_MESSAGE_TEMPLATE_H

#include <cfanal/MessageFlowTemplate.h>
#include <cfanal/DNSHandler.h>

class DNSMessageRule {
	public:
		DNSMessageRule *next;

		DNSMessageRule() { next = NULL; } 
		virtual ~DNSMessageRule() { } 
		virtual bool readRule(xmlNode *n) = 0;
		virtual bool verify(DNSMessage *m) = 0;
		virtual void print(std::ostream &os) = 0;
};

class DNSExistenceRule: public DNSMessageRule {
	public:
		bool existence_ok;
		DNSExistenceRule(bool is_existence_ok) { next = NULL; existence_ok = is_existence_ok; } 
		virtual bool readRule(xmlNode *n);
		virtual bool verify(DNSMessage *m);
		virtual void print(std::ostream &os);
	
};


class DNSMessageTemplate: public MessageTemplate {
	protected:
		int query_type;
		bool is_request;
		int reply_code;

		DNSMessageRule *rules;
		char *name;

		bool handleRule(xmlNode *n);
		bool readRules(xmlNode *n);
		void addRule(DNSMessageRule *r);

	public:	
		DNSMessageTemplate(bool request) { name = NULL; is_request = request; rules = NULL; }

		virtual bool readFromXMLElement(xmlNode *n);
		virtual protocol_id_t identify() { return DNSHandler::id; }
		virtual ~DNSMessageTemplate();

		/** test if given message matches this template */
		virtual bool matches(Message *m);

		/** verifies additional message criteria */
		virtual bool verify(Message *m);

		virtual void print(std::ostream &os); 

};

class DNSRequestTemplateFactory: public MessageTemplateFactory {
	public:
		virtual MessageTemplate *createMessageTemplate() { return new DNSMessageTemplate(true); }
};

class DNSResponseTemplateFactory: public MessageTemplateFactory {
	public:
		virtual MessageTemplate *createMessageTemplate() { return new DNSMessageTemplate(false); }
};

#endif
