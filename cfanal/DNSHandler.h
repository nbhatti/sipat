#ifndef __DNS_HANDLER_H
#define __DNS_HANDLER_H

#include <cfanal/ProtocolHandler.h>
#include <cfanal/MessageFlow.h>

#define TYPE_A	        1
#define TYPE_NS	        2
#define TYPE_PTR        12
#define TYPE_SRV        33
#define TYPE_NAPTR      35

#define CLASS_IN        1

#define IS_DNS_REPLY(flags)	((flags & 0x8000) >> 15)

class DNSMessage;
class DNSResourceRecord;

class DNSHandler: public ProtocolHandler {
	protected:
		bool createMessages;
		bool ignoreSERWatchdog;
		bool ignorePTR;

		DNSMessage *parseDNS(struct timeval *ts, 
				Destination *src, Destination *dst,
				unsigned char *data, unsigned int data_len);
#if 0
		/** \retval 0 ... ok,
		 * \retval 1 ... not whole name
		 * \retval -1 ... error 
		 * Warning - changes offset! */
		int readName(unsigned int &offset, 
				unsigned char *data,
				unsigned char *dst, unsigned int dst_len);

		DNSResourceRecord *readResourceRecord(unsigned int &offset, 
				unsigned char *data);
#endif

	public:
		static protocol_id_t id;

		virtual protocol_id_t identify() { return id; }
		virtual int processPacket(struct timeval *ts, 
				unsigned char *data, unsigned int data_len, 
				ProtocolData *parent);

		DNSHandler(bool create_messages, bool ignore_ser_wd, bool ignore_ptr);
};

class DNSQuestion {
	protected:
		DNSQuestion *next;

	public:
		DNSQuestion(const char *qname, unsigned int qtype, unsigned int qclass);
		~DNSQuestion();

		char *qname;
		unsigned int qtype;
		unsigned int qclass;
		
	friend class DNSMessage;
};

class DNSResourceRecord {
	protected:
		DNSResourceRecord *next;

	public:
		/*DNSResourceRecord(const char *name, unsigned int type, 
				unsigned int rr_class, unsigned int ttl,
				unsigned char *rdata, unsigned rdlength);*/
		DNSResourceRecord(unsigned char *data, unsigned int &offset);
		virtual ~DNSResourceRecord();

		//virtual void cfprint(std::ostream &os);
		virtual void txtprint(std::ostream &os);

		char *name;
		unsigned int type;
		unsigned int rr_class;
		unsigned int ttl;
		unsigned int rdlength; /* copied from the message */
		
		/** zero terminated string, does not correspond with rdlength !!! 
		 * according type it is computed somehow !!!*/
		char *rdata; 

		/* SRV data */
		unsigned int srv_priority, srv_weight, srv_port;

	friend class DNSMessage;
};

class DNSMessage: public Message {
	protected:
		unsigned int flags;
		unsigned int id;
		DNSQuestion *questionSection;
		DNSQuestion *lastQuestion;

		DNSResourceRecord *answerSection;
		DNSResourceRecord *lastAnswer;
		
		DNSResourceRecord *authoritySection;
		DNSResourceRecord *lastAuthority;

		DNSResourceRecord *additionalSection;
		DNSResourceRecord *lastAdditional;

	public:
		virtual ~DNSMessage();
		DNSMessage(struct timeval *ts,
				Destination *src, Destination *dst, 
				unsigned int id, unsigned int flags);
		virtual protocol_id_t identify() { return DNSHandler::id; }
		virtual void addQuestion(DNSQuestion *q);
		virtual void addAnswer(DNSResourceRecord *r);
		virtual void addAuthority(DNSResourceRecord *r);
		virtual void addAdditional(DNSResourceRecord *r);

		virtual void cfprint(std::ostream &os);
		virtual void txtprint(std::ostream &os);

		static void printType(unsigned int qtype, std::ostream &os);
		static void printName(const char *name, std::ostream &os);
		static void printClass(unsigned int qclass, std::ostream &os);

		bool isSerWatchdog();
		bool isPTR();
		bool isReply() { return IS_DNS_REPLY(flags); }
		bool queriesName(const char *name);
};

unsigned int str2qtype(const char *s);
const char *qtype2str(unsigned int qtype);

#endif
