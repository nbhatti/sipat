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
