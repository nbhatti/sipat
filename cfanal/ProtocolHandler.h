#ifndef __PROTOCOL_HANDLER_H
#define __PROTOCOL_HANDLER_H

#include <sys/time.h>
#include <stdio.h>

#include <cfanal/MessageFlow.h>
#include <cfanal/LogManager.h>
#include <cfanal/id.h>

class ProtocolHandlerContext;

class ProtocolData {
	public:
		virtual ~ProtocolData() { }

		/** returns protocol identification (MUST be the same like
		 * in corresponding ProtocolHandler) */
		virtual protocol_id_t identify() = 0; 
};

/** Base class for handling specific protocol during pcap decoding. 
 *
 * Each protocol handler must be able to identify itself with unique
 * identificator.
 *
 * Protocol handlers can be stored within lists.
 *
 * Each protocol handler internal data represent context needed for processing
 * protocol packets. This can be for example IP fragments, TCP connections,
 * parts of SIP messages over TCP etc. 
 *
 * Part of this handler context might be required by nested protocols. For
 * example UdpHandler might need IP addresses which are specified in its
 * IP envelope.
 * */
class ProtocolHandler {
	protected:

		/** next protocol handler in list */
		ProtocolHandler	*next;

		/** previous protocol handler in list */
		ProtocolHandler	*prev;

		/** logging for this ProtocolHandler */
		Log *log;

		/** context assigned in initContext */
		ProtocolHandlerContext *context;
		
		unsigned int processedBytes;

	public:
		ProtocolHandler() { processedBytes = 0; context = NULL; log = NULL; prev = NULL; next = NULL; }

		unsigned int getProcessedBytes() { return processedBytes; }

		virtual ~ProtocolHandler() { }

		virtual protocol_id_t identify() = 0; ///< return protocol identification

		/** Process packet from pcap. 
		 * \param ts is time stamp from pcap file
		 * \param data is pointer to data buffer 
		 * \param data_len specifies data buffer length
		 * \param parent holds information from protocol envelope ('parent protocol') */
		virtual int processPacket(struct timeval *ts, 
				unsigned char *data, unsigned int data_len, 
				ProtocolData *parent) = 0;

		/** Initialize context required for packet processing.
		 * Can be used for example to find nested protocol handlers 
		 * in known protocol handlers. Pointer to a handler can be stored 
		 * in context and used until releaseContext is called.*/
		virtual int initContext(ProtocolHandlerContext *context);

		/** release all context data like hold protocol handlers or other
		 * internal data */
		virtual void releaseContext();
	
	friend class ProtocolHandlerContext;
};

class ProtocolHandlerContext {
	protected:
		bool autoFreeHandlers;
		ProtocolHandler *first;
		ProtocolHandler *last;

		/** call flow being constructed */
		MessageFlow *flow;
	public:
		/** \param auto_free_handlers Free all handlers automaticaly in destructor 
		 * */
		ProtocolHandlerContext(MessageFlow *flow, bool auto_free_handlers);

		/** releases contexts and if autoFreeHandlers set frees memory occupied by
		 * all handlers in this list */
		virtual ~ProtocolHandlerContext();

		/** add new protocol handler */
		virtual int add(ProtocolHandler *h);
		
		/** remove protocol handler */
		virtual int remove(ProtocolHandler *h);

		virtual ProtocolHandler *getFirstHandler() { return first; }
		virtual ProtocolHandler *getNextHandler(ProtocolHandler *h) { if (h) return h->next; else return NULL; }

		/** find protocol handler in the list according ID */
		virtual ProtocolHandler *find(protocol_id_t id);

		/** initialize context of all protocol handlers in list */
		virtual int initContext();
		
		/** release context of all protocol handlers in list */
		virtual void releaseContext();

		/** release context of all protocol handlers in list and free all handlers
		 * if autoFreeHandlers set. */
		virtual void freeHandlers();

		virtual MessageFlow *getMessageFlow() { return flow; }
};

#endif
