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

#ifndef __UDP_HANDLER_H
#define __UDP_HANDLER_H

#include <cfanal/ProtocolHandler.h>
#include <cfanal/IPHandler.h>
#include <cfanal/LogManager.h>

class UdpHandler: public ProtocolHandler {
	protected:
		ProtocolHandler *sip, *dns;

	public:
		static protocol_id_t id;

		virtual protocol_id_t identify() { return id; }
		virtual int processPacket(struct timeval *ts, 
				unsigned char *data, unsigned int data_len, 
				ProtocolData *parent);
		virtual int initContext(ProtocolHandlerContext *handlers);
		virtual void releaseContext();

		UdpHandler() { sip = NULL; dns = NULL; log = NULL; }
};

class UdpDestination: public IPDestination {
	public:
		unsigned int port;
		bool ignorePort; /* all port values are possible to match this destination */

		UdpDestination(IPAddress &ip_addr, unsigned int port, bool ignore_port = false);

		virtual void printValue(std::ostream &os);
		virtual protocol_id_t identify() { return UdpHandler::id; }
		virtual Destination *duplicate();
		virtual bool equals(Destination *d);

};

class UdpData: public ProtocolData {
	public:
		UdpDestination src, dst;

		virtual protocol_id_t identify() { return UdpHandler::id; }

		UdpData(IPDestination &src_ip, unsigned int src_port,
				IPDestination &dst_ip, unsigned int dst_port):
			src(src_ip.ip_addr, src_port), dst(dst_ip.ip_addr, dst_port) { }
};


#endif
