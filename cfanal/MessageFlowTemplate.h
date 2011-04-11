#ifndef __MESSAGE_FLOW_TEMPLATE_H
#define __MESSAGE_FLOW_TEMPLATE_H

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <cfanal/Destination.h>
#include <cfanal/MessageFlow.h>

class MessageFlowTemplate;

class MessageTemplate {
	protected:
		DestinationList src; // alternate destinations for message source
		DestinationList dst; // alternate destinations for message destination

	public:
		MessageTemplate *prev, *next;

		bool optional;
		Message *matched_message;

		MessageTemplate() { prev = NULL; next = NULL; matched_message = NULL; optional = false; }
		virtual bool readDestination(DestinationList *dst, const char *text, int len);
		virtual bool readDestinationList(DestinationList *dst, const xmlChar *txt_destination);
		virtual ~MessageTemplate() { };
		virtual bool readFromXMLElement(xmlNode *n);

		/** test if given message matches this template */
		virtual bool matches(Message *m);

		/** verifies additional message criteria */
		virtual bool verify(Message *m) { return true; }

		virtual void print(std::ostream &os); 

	friend class MessageFlowTemplate;
};

class MessageTemplateFactory {
	public:
		virtual MessageTemplate *createMessageTemplate() = 0;
};

struct MessageTemplateFactoryElement {
	MessageTemplateFactory *factory;
	MessageTemplateFactoryElement *next, *prev;
	xmlChar *template_name;
};

class MessageFlowTemplate {
	protected:
		bool ignore_unexpected_dns;

		MessageTemplateFactoryElement *first, *last;
		virtual bool handleXMLElement(xmlNode *n);

		MessageTemplate *first_message, *last_message;
			
		void addMessage(MessageTemplate *t);
		MessageTemplate *findMessageTemplate(Message *m, MessageTemplate *currently_expected);
		MessageTemplate *findNextExpected(MessageTemplate *currently_expected);

	public:
		MessageFlowTemplate(bool ignore_unexpected_dns);
		virtual ~MessageFlowTemplate();

		virtual bool readFromXMLFile(const char *filename);
		virtual bool registerTemplate(const char *template_name, MessageTemplateFactory *factory);

		virtual bool verify(MessageFlow *flow);
};

bool text2bool(const char *text);
char *xmltext2text(const xmlChar *xmltext);
char *getXmlAttr(xmlNode *n, const char *name);

#endif
