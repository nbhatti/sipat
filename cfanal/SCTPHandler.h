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

#ifndef __SCTP_HANDLER_H
#define __SCTP_HANDLER_H

#include <cfanal/ProtocolHandler.h>
#include <cfanal/IPHandler.h>
#include <cfanal/LogManager.h>

class SCTPDestination: public IPDestination {
	public:
		unsigned int port;
		bool ignorePort; /* all port values are possible to match this destination */

		SCTPDestination(IPAddress &ip_addr, unsigned int port, bool ignore_port = false);
		SCTPDestination(SCTPDestination *d);

		virtual void printValue(std::ostream &os);
		virtual protocol_id_t identify();
		virtual Destination *duplicate();
		virtual bool equals(Destination *d);
		virtual void printLineType(std::ostream &os) { os << "10,2,2,2"; }

};

class SCTPData: public ProtocolData {
	public:
		SCTPDestination src, dst;

		virtual protocol_id_t identify();

		SCTPData(IPDestination &src_ip, unsigned int src_port,
				IPDestination &dst_ip, unsigned int dst_port):
			src(src_ip.ip_addr, src_port), dst(dst_ip.ip_addr, dst_port) { }
		SCTPData(SCTPData *d): src(d ? d->src: NULL), dst(d ? d->dst: NULL) { }
		SCTPData(SCTPDestination *_src, SCTPDestination *_dst): src(_src), dst(_dst) { }
};

#include <cfanal/SCTPConnection.h>

class SCTPHandler: public ProtocolHandler, public SCTPDataHandler {
	protected:
		ProtocolHandler *sip;
		SCTPConnectionManager cm;
		bool create_sctp_messages;
	public:
		static protocol_id_t id;

		virtual protocol_id_t identify() { return id; }
		virtual int processPacket(struct timeval *ts, 
				unsigned char *data, unsigned int data_len, 
				ProtocolData *parent);
		virtual int initContext(ProtocolHandlerContext *handlers);
		virtual void releaseContext();

		virtual unsigned int processData(unsigned char* data, unsigned int data_len, SCTPData *params, struct timeval *ts, SCTPConnection *c);
		virtual unsigned int processSCTPMessage(unsigned char* data, unsigned int data_len, SCTPData *params, struct timeval *ts, SCTPConnection *c);

		SCTPHandler(bool _create_sctp_messages) { sip = NULL; log = NULL; create_sctp_messages = _create_sctp_messages; }
};

class SCTPControlMessage: public Message {
	protected:
		char *chunk_list;

	public:
		SCTPControlMessage(unsigned char *data, unsigned int data_len, Destination *src, Destination *dst, struct timeval *ts);
		virtual ~SCTPControlMessage();

		virtual protocol_id_t identify() { return SCTPHandler::id; }

		virtual void cfprint(std::ostream &os);
		virtual void txtprint(std::ostream &os);

};

#endif
