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
