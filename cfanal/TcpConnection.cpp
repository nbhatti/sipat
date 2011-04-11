#include "IPHandler.h"
#include "SIPHandler.h"
#include "DNSHandler.h"
#include "bits.h"
#include "TcpHandler.h"

#include <string.h>
#include <stdlib.h>

#define FIN 1
#define SYN	2
#define RST 4
#define ACK 16

Logger log("tcp");

void freeBlocks(TcpDataBlock *data)
{
	TcpDataBlock *b, *n;
	unsigned int cnt = 0, bytes = 0;

	b = data;

	while (b) {
		cnt++;
		bytes += b->data_len;
		
		n = b->next;
		free(b);
		b = n;
	}
	log.trace("%u byte(s) left in %u block(s)\n", bytes, cnt);

}

unsigned int addSeq(unsigned int seq, unsigned int len)
{
	return (seq + len) & 0xFFFFFFFF; // just 32 bits
}

bool isLess(unsigned int s, unsigned int t)
{
	/* s < t if 0 < (t - s) < 2**31 */
	unsigned int r = t - s;
	static unsigned int K = 1 << 31;
	if ((r > 0) && (r < K)) return true;
	else return false;
}



TcpConnection::TcpConnection(TcpData *params, TcpDataHandler *_tcp_handler): tcp_params(params)
{
	next = NULL;
	tcp_handler = _tcp_handler;
	memset(&src_data, 0, sizeof(src_data));
	memset(&dst_data, 0, sizeof(dst_data));
	user_flags = 0;
}

static TcpDataBlock *merge2(TcpDataBlock *b, 
		unsigned int seq,
		unsigned char *data, unsigned int data_len)
{
	unsigned int len = data_len + b->data_len;
	TcpDataBlock *n = (TcpDataBlock *)malloc(sizeof(TcpDataBlock) + len);
	if (n) {
		n->data_len = len;
		n->data = n->buf;
		memcpy(&n->ts, &b->ts, sizeof(n->ts));
		if (addSeq(seq, data_len) == b->seq) {
			// first are data
			n->seq = seq;
			memcpy(n->data, data, data_len);
			memcpy(n->data + data_len, b->data, b->data_len);
		}
		else {
			// first is the existing block
			n->seq = b->seq;
			memcpy(n->data, b->data, b->data_len);
			memcpy(n->data + b->data_len, data, data_len);
		}
	}
	return n;
}

static TcpDataBlock *merge3(TcpDataBlock *prev, TcpDataBlock *next, 
		unsigned int seq,
		unsigned char *data, unsigned int data_len)
{
	unsigned int len = data_len + prev->data_len + next->data_len;
	TcpDataBlock *n = (TcpDataBlock *)malloc(sizeof(TcpDataBlock) + len);
	if (n) {
		n->data_len = len;
		n->data = n->buf;
		n->seq = prev->seq;
		memcpy(&n->ts, &prev->ts, sizeof(n->ts));
		memcpy(n->data, prev->data, prev->data_len);
		memcpy(n->data + prev->data_len, data, data_len);
		memcpy(n->data + prev->data_len + data_len, next->data, next->data_len);
	}
	return n;
}

static TcpDataBlock *newBlock(unsigned int seq,
		unsigned char *data, unsigned int data_len,
		struct timeval *ts)
{
	TcpDataBlock *n = (TcpDataBlock *)malloc(sizeof(TcpDataBlock) + data_len);
	if (n) {
		n->data_len = data_len;
		n->data = n->buf;
		n->seq = seq;
		memcpy(n->data, data, data_len);
		memcpy(&n->ts, ts, sizeof(*ts));
	}
	return n;
}

int TcpConnection::addData(unsigned int seq,
		unsigned char *data,
		unsigned int data_len,
		bool reverse_dir,
		struct timeval *ts)
{
	TcpDataBlock **d, *prev, *next;

	if (reverse_dir) {
		d = &dst_data.data;
	}
	else {
		d = &src_data.data;
	}

	if (data_len == 0) return 0;

	/* 
	 * 1. find nearest data with which can be current data merged 
	 * 2. merge if possible or add new data segment if not 
	 * 3. wait for aknowledge of some buffered data and process them further
	 *    (we can't know if there was anything before or not, ACK gives us the
	 *    impression that there was nothing before) 
	 *
	 *    TODO: handle overlapping data
	 */

	next = *d;
	prev = NULL;
	while (next) {
		if (next->seq == seq) {
			 /* we already have this segment,
			TODO: verify if it has the same length, otherwise 
			replace somehow ??? */
			return 0;
		}
		if (!isLess(next->seq, seq)) {
			//log.trace("%u is not less than %u\n", next->seq, seq);
			break;
		}
		prev = next;
		next = prev->next;
	}

	// merge blocks if possible
	bool merge_next = false;
	bool merge_prev = false;
	TcpDataBlock *b = NULL;

	if (next) {
		merge_next = (next->seq == addSeq(seq, data_len));
		/*log.trace("next->seq: %u, seq+data_len: %u\n", 
				next->seq, addSeq(seq, data_len));*/
	}
	if (prev) {
		merge_prev = (seq == addSeq(prev->seq, prev->data_len));
		/*log.trace("seq: %u, prev->seq+prev->data_len: %u\n", 
				seq, addSeq(prev->seq, prev->data_len));*/
	}

	if (merge_prev) {
		if (merge_next) {
			// merge both
			b = merge3(prev, next, seq, data, data_len);
			if (!b) return -1;
			// delete prev, next and insert b instead of them
			b->prev = prev->prev;
			b->next = next->next;
			if (b->prev) b->prev->next = b;
			else *d = b;
			if (b->next) b->next->prev = b;
			free(prev);
			free(next);
			//log.trace("merged 3\n");
		}
		else {
			// merge only with previous
			b = merge2(prev, seq, data, data_len);
			if (!b) return -1;
			// delete prev and insert b instead of it
			b->prev = prev->prev;
			if (b->prev) b->prev->next = b;
			else *d = b;
			b->next = next;
			if (b->next) b->prev = b;
			//log.trace("merged 2\n");
		}
	}
	else {
		if (merge_next) {
			// merge only with next
			b = merge2(next, seq, data, data_len);
			if (!b) return -1;
			// delete next and insert b instead of it
			b->prev = prev;
			if (prev) prev->next = b;
			else *d = b;
			b->next = next->next;
			if (b->next) b->next->prev = b;
			free(next);
			//log.trace("merged 2\n");
		}
		else {
			// do not merge anything
			b = newBlock(seq, data, data_len, ts);
			if (!b) return -1;
			// insert b between prev and next
			b->next = next;
			if (next) next->prev = b;
			b->prev = prev;
			if (prev) prev->next = b;
			else *d = b;
			//log.trace("added new block\n");
		}

	}

	return 0;
}

int TcpConnection::ackData(TcpDataBlockList *list, unsigned int ack_num, bool reverse_dir)
{
	TcpDataBlock *b = list->data;

	if (ack_num == 0) {
		log.trace("nothing to ACK\n");
		return 1; // nothing to ACK
	}

	// process data from list up to ack_num-1

	if (!b) {
		log.trace("warning - no data blocks which could be acked (ACK: %u)\n", ack_num);
		list->expected_seq = ack_num;
		return 1;
	}
	if (!isLess(b->seq, ack_num)) {
		log.trace("warning - no data blocks which could be acked (ACK: %u, SEQ: %u)\n", ack_num, b->seq);
		return 1; // we don't have these data
	}

	unsigned int len = ack_num - b->seq; // at most this range of data

	// take acknowledged bytes from data blocks (should be only one block
	// otherwise something is wrong [like we missed something]!)

	if (len > b->data_len) {
		log.trace("acknowledged more than one block? - ERROR, we missed something\n");
		log.trace("current block len: %u\n", b->data_len);
		log.trace("ACK = %u, SEQ = %u, delta = %u\n", ack_num, b->seq, len);
	
		list->expected_seq = ack_num; //??
		return -1;
	}
	else {
		unsigned int rest = b->data_len - len;

		log.trace("ACK = %u, SEQ = %u, delta = %u\n", ack_num, b->seq, len);
//		log.trace("ACKNOWLEDGED DATA:\n---\n %.*s\n---\n", len, b->data);
		// some data acknowledged -> process them!
		if (tcp_handler) {
			// ACK in reverse direction means acknowledging data in non-reverse
			// direction!
			TcpData params(reverse_dir ? &tcp_params.src: &tcp_params.dst, 
					reverse_dir ? &tcp_params.dst: &tcp_params.src);

			unsigned int processed = tcp_handler->processData(b->data, len, &params, &b->ts, this);
			rest += len - processed;
			len = processed; // remove just processed data
		}

		if (rest == 0) {
			// just free the data block
			list->data = b->next;
			if (list->data) list->data->prev = NULL;
			free(b);
		}
		else {
			// remove just some data from block
			b->seq += len;
			b->data += len;
			b->data_len -= len;
		}
	}
	list->expected_seq = ack_num;
	return 0; // data acknowledged (and ready)
}
		
int TcpConnection::tryHandleData(TcpDataBlockList *list, bool reverse_dir)
{
	TcpDataBlock *b = list->data;
	if (tcp_handler) {
		TcpData params(reverse_dir ? &tcp_params.dst: &tcp_params.src, 
				reverse_dir ? &tcp_params.src: &tcp_params.dst);

		unsigned int processed = tcp_handler->processData(b->data, b->data_len, &params, &b->ts, this);

		if (processed == b->data_len) {
			// just free the data block
			list->data = b->next;
			if (list->data) list->data->prev = NULL;
			free(b);
		}
		else {
			// remove just some data from block
			b->seq += processed;
			b->data += processed;
			b->data_len -= processed;
		}
	}
	return 0;
}

int TcpConnection::processPacket(struct timeval *ts, unsigned char *data, 
		unsigned int data_len, bool reverse_dir)
{
	unsigned int seq_num = GET_DWORD(data, 4);
	unsigned int ack_num = GET_DWORD(data, 8);
	unsigned int win_size = GET_WORD(data, 14);
/*	unsigned int checksum = GET_WORD(data, 16);
	unsigned int urgent = GET_WORD(data, 18);*/
	unsigned int data_offset = (GET_BYTE(data, 12) & 0xF0) >> 4;
	unsigned int hdr_size = data_offset * 4;
	unsigned int flags = GET_BYTE(data, 13);
	unsigned int tmp;
	TcpDataBlockList *blocks, *other_blocks;

	log.trace("handling TCP packet ...  len: %u, src port: %u, dst port: %u, reverse: %s\n", 
			data_len, tcp_params.src.port, tcp_params.dst.port, reverse_dir ? "YES" : "NO" );

	log.trace("   SEQ_NUM: %u\n", seq_num);
	log.trace("   ACK_NUM: %u\n", ack_num);
	log.trace("   window size: %d\n", win_size);
	log.trace("   data offset: %d\n", data_offset);
	log.trace("   hdr size: %d\n", hdr_size);
	log.trace("   SYN: %d\n", flags & SYN);
	log.trace("   FIN: %d\n", flags & FIN);
	log.trace("   RST: %d\n", flags & RST);
	log.trace("   ACK: %d\n", flags & ACK);
	log.trace("   flags: %0xh\n", flags);
	log.trace("   options:\n");

	// print OPTIONS
	for (unsigned int i = 20; i < hdr_size; i++) {
		if (data[i] == 0) break; // end of option list
		int len = 0; // clean
		switch (data[i]) {
			case 1: // NOP
				len = 1;
/*					log.trace("     - NOP\n"); */
				break;
			case 2: // maximum segment size
				tmp = GET_WORD(data, i + 2);
/*					log.trace("     - maximum segment size: %d\n", tmp);*/
				break;
			case 3:
				tmp = GET_BYTE(data, i + 2);
/*					log.trace("     - window scale: %d\n", tmp);*/
				break;
			case 4:
/*					log.trace("     - sack permitted\n"); */
				break;
			case 5:
				tmp = GET_BYTE(data, i + 1);
				if (tmp >= 10) {
					int n = (tmp - 2) / 8;
					for (int j = 0; j < n; j++) {
/*							log.trace("     - SACK: %d:%d\n", 
								GET_DWORD(data, i + 1 + j * 4),
								GET_DWORD(data, i + 1 + (j + 1) * 4)); */
					}
				}
				break;

			default: 
				break;
		}
		if (len == 0) len = GET_BYTE(data, i + 1);
		i += len - 1;

	}
//		log.trace("\n");

	if (reverse_dir) {
		blocks = &dst_data;
		other_blocks = &src_data;
	}
	else {
		blocks = &src_data;
		other_blocks = &dst_data;
	}

	int len = data_len - hdr_size;
	if (blocks->expected_seq)
		if (isLess(seq_num + len, blocks->expected_seq)) return 0; // already processed
	
//data on ack:	ackData(other_blocks, ack_num, reverse_dir);
	int ready_data_len_before = 0;
	if (blocks->data) {
		ready_data_len_before = blocks->data->data_len;
	}

	if (flags & RST) {
		freeBlocks(other_blocks->data);
		other_blocks->data = NULL;
	}

//		if ( ((flags & SYN) == 0) /* && (data_len > hdr_size)*/ ) {
	if ( (data_len > hdr_size)) {
		// data here
/*			log.trace("data: %.*s\n", data_len - hdr_size, data + hdr_size); */
		addData(seq_num, data + hdr_size, data_len - hdr_size, reverse_dir, ts);

		int data_len_now = 0;
		if (blocks->data) {
			data_len_now = blocks->data->data_len;
			// set expected CSeq to data after first block
			blocks->expected_seq = blocks->data->seq + blocks->data->data_len;
		}
		if (data_len_now != ready_data_len_before) {
			tryHandleData(blocks, reverse_dir);
		}
	}

#if 0
	/* try SIP - the protocol is text based and has identification inside ->
	 * try to parse it and see if it works or not */
	if (sip) {
		if (sip->processPacket(ts, data, data_len, &c) == 0) 
			return 0;
	}

	if (dns && (c.dst.port == 53 || c.src.port == 53)) { 
		/* DNS is binary and has no identification - needed to guess according
		 * ports? */
		if (dns->processPacket(ts, data, data_len, &c) == 0) 
			return 0;
	}
#endif
	log.trace("\n");
	return 0;
}

TcpConnection::~TcpConnection()
{
	freeBlocks(src_data.data);
	freeBlocks(dst_data.data);
}

////////////////////////////////////////////////////////////////////////
		
TcpConnectionManager::TcpConnectionManager() { first = NULL; }

TcpConnectionManager::~TcpConnectionManager()
{
	cleanup();
}

void TcpConnectionManager::cleanup()
{
	TcpConnection *c = first, *n;
	while (c) {
		n = c->next;
		delete c;
		c = n;
	}
	first = NULL;
}

TcpConnection *TcpConnectionManager::findTcpConnection(TcpData *params, bool &reverse_dir)
{
	if (!params) return NULL;

	TcpConnection *c = first;
	while (c) {
		if ((c->tcp_params.src.equals(&params->src)) && 
				(c->tcp_params.dst.equals(&params->dst))) {
			reverse_dir = false;
			return c;
		}
		if ((c->tcp_params.src.equals(&params->dst)) && 
				(c->tcp_params.dst.equals(&params->src))) {
			reverse_dir = true;
			return c;
		}
		c = c->next;
	}
	return NULL;
}

TcpConnection *TcpConnectionManager::addTcpConnection(TcpData *params, TcpDataHandler *h)
{
	TcpConnection *c = new TcpConnection(params, h);
	if (c) {
		// add to the beggining for quicker search of most recent connection
		c->next = first;
		first = c;
	}
	return c;
}

