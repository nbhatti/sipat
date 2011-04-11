#ifndef __SCTP_CONNECTION_H
#define __SCTP_CONNECTION_H

class SCTPConnectionManager;

struct SCTPDataBlock {
	unsigned int tsn;
	unsigned int next_tsn;
	unsigned char *data;
	unsigned int data_len;
	struct timeval ts;
	SCTPDataBlock *prev, *next; // next data block
	unsigned char buf[1];
};

struct SCTPDataBlockList {
	SCTPDataBlock *data;
//	unsigned int acknowledged_seq;
	unsigned int expected_tsn;
};

class SCTPConnection;

class SCTPDataHandler {
	public:
		virtual unsigned int processData(unsigned char* data, unsigned int data_len, SCTPData *params, struct timeval *ts, SCTPConnection *c) = 0;
		virtual unsigned int processSCTPMessage(unsigned char* data, unsigned int data_len, SCTPData *params, struct timeval *ts, SCTPConnection *c) = 0;
};

class SCTPConnection {
	protected:
		SCTPData sctp_params;
		SCTPConnection *next;
		SCTPDataBlockList src_data;
		SCTPDataBlockList dst_data;
		SCTPDataHandler *sctp_handler;

		unsigned long user_flags;

		bool create_sctp_messages;
		
		Logger log;

		int tryHandleData(SCTPDataBlockList *list, bool reverse_dir);
		void freeBlocks(SCTPDataBlock *data);
	public:
		SCTPConnection(SCTPData *params, SCTPDataHandler *_sctp_handler);
		virtual ~SCTPConnection();

		int processPacket(struct timeval *ts, unsigned char *data, unsigned int data_len, bool reverse_dir);
		int addData(unsigned int tsn, unsigned char *data,
				unsigned int data_len, bool reverse_dir, struct timeval *ts);

		unsigned long getUserFlags() { return user_flags; }
		void setUserFlags(unsigned long f) { user_flags = f; }

		SCTPData *getSCTPParams() { return &sctp_params; }

	friend class SCTPConnectionManager;
};

class SCTPConnectionManager {
	protected:
		SCTPConnection *first;

	public:
		SCTPConnectionManager();
		virtual ~SCTPConnectionManager();

		SCTPConnection *findSCTPConnection(SCTPData *params, bool &reverse_dir);
		SCTPConnection *addSCTPConnection(SCTPData *params, SCTPDataHandler *h);

		virtual void cleanup();
};

#endif

