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

#ifndef __TCP_HANDLER_H
#define __TCP_HANDLER_H

#include <cfanal/ProtocolHandler.h>
#include <cfanal/IPHandler.h>
#include <cfanal/LogManager.h>

class TcpDestination: public IPDestination {
	public:
		unsigned int port;
		bool ignorePort;

		TcpDestination(IPAddress &ip_addr, unsigned int port, bool ignore_port = false);
		TcpDestination(TcpDestination *d);

		virtual void printValue(std::ostream &os);
		virtual protocol_id_t identify();
		virtual Destination *duplicate();
		virtual bool equals(Destination *d);
		virtual void printLineType(std::ostream &os) { os << "3,3"; }

};

class TcpData: public ProtocolData {
	public:
		TcpDestination src, dst;

		virtual protocol_id_t identify();

		TcpData(IPDestination &src_ip, unsigned int src_port,
				IPDestination &dst_ip, unsigned int dst_port):
			src(src_ip.ip_addr, src_port), dst(dst_ip.ip_addr, dst_port) { }

		TcpData(TcpData *d): src(d ? d->src: NULL), dst(d ? d->dst: NULL) { }
		TcpData(TcpDestination *_src, TcpDestination *_dst): src(_src), dst(_dst) { }
};

#include <cfanal/TcpConnection.h>

class TcpHandler: public ProtocolHandler, public TcpDataHandler {
	protected:
		ProtocolHandler *sip, *dns;
		TcpConnectionManager cm;

	public:
		static protocol_id_t id;

		virtual protocol_id_t identify() { return id; }
		virtual int processPacket(struct timeval *ts, 
				unsigned char *data, unsigned int data_len, 
				ProtocolData *parent);
		virtual int initContext(ProtocolHandlerContext *handlers);
		virtual void releaseContext();

		TcpHandler() { sip = NULL; dns = NULL; log = NULL; }
		
		virtual unsigned int processData(unsigned char* data, unsigned int data_len, TcpData *params, struct timeval *ts, TcpConnection *c);
};

#endif

