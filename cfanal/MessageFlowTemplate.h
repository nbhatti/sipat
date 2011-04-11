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
