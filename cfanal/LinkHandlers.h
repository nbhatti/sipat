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

#ifndef __LINK_HANDLERS_H
#define __LINK_HANDLERS_H

#include <cfanal/ProtocolHandler.h>
#include <cfanal/LogManager.h>

class EthernetHandler: public ProtocolHandler {
	protected:
		ProtocolHandler *ip;
	public:
		static protocol_id_t id; ///< constant for Ethernet

		virtual protocol_id_t identify() { return id; }
		virtual int processPacket(struct timeval *ts, 
				unsigned char *data, unsigned int data_len, 
				ProtocolData *parent);
		virtual int initContext(ProtocolHandlerContext *handlers);
		virtual void releaseContext();

		EthernetHandler() { ip = NULL; log = NULL; }
};

class LinuxSLLHandler: public ProtocolHandler {
	protected:
		ProtocolHandler *ip;
	public:
		static protocol_id_t id; ///< constant for this protocol

		virtual protocol_id_t identify() { return id; }
		virtual int processPacket(struct timeval *ts, 
				unsigned char *data, unsigned int data_len, 
				ProtocolData *parent);
		virtual int initContext(ProtocolHandlerContext *handlers);
		virtual void releaseContext();

		LinuxSLLHandler() { ip = NULL; log = NULL; }
};

#endif
