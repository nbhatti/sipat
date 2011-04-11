#ifndef __SIP_MESSAGE_TEMPLATE_H
#define __SIP_MESSAGE_TEMPLATE_H

#include <cfanal/MessageFlowTemplate.h>
#include <cfanal/SIPHandler.h>

class SIPMessageRule {
	public:
		SIPMessageRule *next;

		SIPMessageRule() { next = NULL; } 
		virtual ~SIPMessageRule() { } 
		virtual bool readRule(xmlNode *n) = 0;
		virtual bool verify(SIPMessage *m, MessageTemplate *t) = 0;
		virtual void print(std::ostream &os) = 0;
};

class SIPHeaderRule: public SIPMessageRule {
	protected:
		enum { EXISTS, CONTAINS, DOES_NOT_CONTAIN, DOES_NOT_EXIST } test;
		char *hdr_name;
		char *value;

	public:
		SIPHeaderRule();
		virtual ~SIPHeaderRule();

		virtual bool readRule(xmlNode *n);
		virtual bool verify(SIPMessage *m, MessageTemplate *t);
		virtual void print(std::ostream &os);
};

class MessageDelayRule: public SIPMessageRule {
	protected:
		double delay;
		double tolerance;

	public:
		virtual bool readRule(xmlNode *n);
		virtual bool verify(SIPMessage *m, MessageTemplate *t);
		virtual void print(std::ostream &os);
};

class SIPExistenceRule: public SIPMessageRule {
	public:
		bool existence_ok;
		SIPExistenceRule(bool is_existence_ok) { next = NULL; existence_ok = is_existence_ok; } 
		virtual bool readRule(xmlNode *n);
		virtual bool verify(SIPMessage *m, MessageTemplate *t);
		virtual void print(std::ostream &os);
	
};

class SIPMessageTemplate: public MessageTemplate {
	protected:
		char *method;
		bool is_request;
		int reply_code;

		SIPMessageRule *rules;

		bool handleRule(xmlNode *n);
		bool readRules(xmlNode *n);
		void addRule(SIPMessageRule *r);

	public:	
		SIPMessageTemplate(bool request) { method = NULL; is_request = request; rules = NULL; }

		virtual bool readFromXMLElement(xmlNode *n);
		virtual protocol_id_t identify() { return SIPHandler::id; }
		virtual ~SIPMessageTemplate();

		/** test if given message matches this template */
		virtual bool matches(Message *m);

		/** verifies additional message criteria */
		virtual bool verify(Message *m);

		virtual void print(std::ostream &os); 

};

class SIPRequestTemplateFactory: public MessageTemplateFactory {
	public:
		virtual MessageTemplate *createMessageTemplate() { return new SIPMessageTemplate(true); }
};

class SIPResponseTemplateFactory: public MessageTemplateFactory {
	public:
		virtual MessageTemplate *createMessageTemplate() { return new SIPMessageTemplate(false); }
};

#endif
