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
