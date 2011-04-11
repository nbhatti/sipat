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

#ifndef __SIP_HANDLER_H
#define __SIP_HANDLER_H

#include <cfanal/ProtocolHandler.h>
#include <cfanal/IPHandler.h>
#include <cfanal/UdpHandler.h>
#include <cfanal/LogManager.h>
#include <osip2/osip.h>

class SIPTransaction {
	protected:
		char *id;
		SIPTransaction *next;
		SIPTransaction *prev;
	
	public:
		static const char *colors[];

		/* printing parameters */
		struct {
			const char *color; /* points to staticaly allocated string ! */
		} cfPrintParams;

		static const char *getTransactionID(osip_message_t *msg);
		SIPTransaction(const char *transaction_id);

	friend class SIPTransactionManager;
};

class SIPTransactionManager {
	protected:
		SIPTransaction *first;
		SIPTransaction *last;

		int currentColorIndex;

	public:
		SIPTransactionManager() { first = NULL; last = NULL; currentColorIndex = 0; }
		~SIPTransactionManager();

		SIPTransaction *find(const char *transaction_id);
		SIPTransaction *add(const char *transaction_id);
};

class SIPHandler: public ProtocolHandler {
	protected:
		SIPTransactionManager tm;
		bool createMessages;
		bool ignoreOPTIONS;

	public:
		static protocol_id_t id;

		virtual protocol_id_t identify() { return id; }
		virtual int processPacket(struct timeval *ts, 
				unsigned char *data, unsigned int data_len, 
				ProtocolData *parent);
		virtual int initContext(ProtocolHandlerContext *handlers);
		virtual void releaseContext();
		void setIgnoreOPTIONS(bool ignore) { ignoreOPTIONS = ignore; }

		SIPHandler(bool create_messages) { log = NULL; createMessages = create_messages; ignoreOPTIONS = false; }
};

class SIPMessage: public Message {
	public: // handy from outside?
		/** can be NULL !!! */
		SIPTransaction *transaction;

		osip_message_t *msg;
		char *messageText;
		unsigned int messageTextLen;

	public:
		/** the caller can not use sip_message any more - it 
		 * will be freed in the SIPMessage destructor */
		SIPMessage(struct timeval *ts, 
				Destination *src, 
				Destination *dst,
				osip_message_t *sip_message,
				SIPTransaction *tx,
				const char *txt_msg,
				unsigned int txt_msg_len);
		virtual ~SIPMessage();
		virtual protocol_id_t identify() { return SIPHandler::id; }
		
		virtual void cfprint(std::ostream &os);
		virtual void txtprint(std::ostream &os);
};

/* returns:
 *   1 ... yes, it is SIP
 *   -1 ... no, it is NOT SIP
 *   0 ... who knows (not enough input data)
 *   */
int is_sip(unsigned char *data, unsigned int data_len);

#endif
