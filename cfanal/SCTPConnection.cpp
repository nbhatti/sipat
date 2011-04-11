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

#include "IPHandler.h"
#include "SIPHandler.h"
#include "DNSHandler.h"
#include "bits.h"
#include "SCTPHandler.h"

#include <string.h>
#include <stdlib.h>

void SCTPConnection::freeBlocks(SCTPDataBlock *data)
{
	SCTPDataBlock *b, *n;
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

static bool isLess(unsigned int s, unsigned int t)
{
	/* s < t if 0 < (t - s) < 2**31 */
	unsigned int r = t - s;
	static unsigned int K = 1 << 31;
	if ((r > 0) && (r < K)) return true;
	else return false;
}



SCTPConnection::SCTPConnection(SCTPData *params, SCTPDataHandler *_sctp_handler): sctp_params(params), log("sctp")
{
	next = NULL;
	sctp_handler = _sctp_handler;
	memset(&src_data, 0, sizeof(src_data));
	memset(&dst_data, 0, sizeof(dst_data));
	user_flags = 0;
}

static SCTPDataBlock *merge2(SCTPDataBlock *b, 
		unsigned int tsn,
		unsigned char *data, unsigned int data_len)
{
	unsigned int len = data_len + b->data_len;
	SCTPDataBlock *n = (SCTPDataBlock *)malloc(sizeof(SCTPDataBlock) + len);
	if (n) {
		n->data_len = len;
		n->data = n->buf;
		memcpy(&n->ts, &b->ts, sizeof(n->ts));
		if (tsn + 1 == b->tsn) {
			// first are data
			n->tsn = tsn;
			n->next_tsn = b->next_tsn;
			memcpy(n->data, data, data_len);
			memcpy(n->data + data_len, b->data, b->data_len);
		}
		else {
			// first is the existing block
			n->tsn = b->tsn;
			n->next_tsn = tsn + 1;
			memcpy(n->data, b->data, b->data_len);
			memcpy(n->data + b->data_len, data, data_len);
		}
	}
	return n;
}

static SCTPDataBlock *merge3(SCTPDataBlock *prev, SCTPDataBlock *next, 
		unsigned int tsn,
		unsigned char *data, unsigned int data_len)
{
	unsigned int len = data_len + prev->data_len + next->data_len;
	SCTPDataBlock *n = (SCTPDataBlock *)malloc(sizeof(SCTPDataBlock) + len);
	if (n) {
		n->data_len = len;
		n->data = n->buf;
		n->tsn = prev->tsn;
		n->next_tsn = next->next_tsn;
		memcpy(&n->ts, &prev->ts, sizeof(n->ts));
		memcpy(n->data, prev->data, prev->data_len);
		memcpy(n->data + prev->data_len, data, data_len);
		memcpy(n->data + prev->data_len + data_len, next->data, next->data_len);
	}
	return n;
}

static SCTPDataBlock *newBlock(unsigned int tsn,
		unsigned char *data, unsigned int data_len,
		struct timeval *ts)
{
	SCTPDataBlock *n = (SCTPDataBlock *)malloc(sizeof(SCTPDataBlock) + data_len);
	if (n) {
		n->data_len = data_len;
		n->data = n->buf;
		n->tsn = tsn;
		n->next_tsn = tsn + 1;
		memcpy(n->data, data, data_len);
		memcpy(&n->ts, ts, sizeof(*ts));
	}
	return n;
}

int SCTPConnection::addData(unsigned int tsn,
		unsigned char *data,
		unsigned int data_len,
		bool reverse_dir,
		struct timeval *ts)
{
	SCTPDataBlock **d, *prev, *next;

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
		if (next->tsn == tsn) {
			 /* we already have this segment,
			TODO: verify if it has the same length, otherwise 
			replace somehow ??? */
			return 0;
		}
		if (!isLess(next->tsn, tsn)) {
			//log.trace("%u is not less than %u\n", next->seq, seq);
			break;
		}
		prev = next;
		next = prev->next;
	}

	// merge blocks if possible
	bool merge_next = false;
	bool merge_prev = false;
	SCTPDataBlock *b = NULL;

	if (next) {
		merge_next = (next->tsn == tsn + 1);
		/*log.trace("next->seq: %u, seq+data_len: %u\n", 
				next->seq, addSeq(seq, data_len));*/
	}
	if (prev) {
		merge_prev = (tsn == prev->next_tsn);
		/*log.trace("seq: %u, prev->seq+prev->data_len: %u\n", 
				seq, addSeq(prev->seq, prev->data_len));*/
	}

	if (merge_prev) {
		if (merge_next) {
			// merge both
			b = merge3(prev, next, tsn, data, data_len);
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
			b = merge2(prev, tsn, data, data_len);
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
			b = merge2(next, tsn, data, data_len);
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
			b = newBlock(tsn, data, data_len, ts);
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

int SCTPConnection::tryHandleData(SCTPDataBlockList *list, bool reverse_dir)
{
	SCTPDataBlock *b = list->data;
	if (sctp_handler) {
		SCTPData params(reverse_dir ? &sctp_params.dst: &sctp_params.src, 
				reverse_dir ? &sctp_params.src: &sctp_params.dst);

		unsigned int processed = sctp_handler->processData(b->data, b->data_len, &params, &b->ts, this);

		if (processed == b->data_len) {
			// just free the data block
			list->data = b->next;
			if (list->data) list->data->prev = NULL;
			free(b);
		}
		else {
			// remove just some data from block
			b->data += processed;
			b->data_len -= processed;
		}
	}
	return 0;
}

int SCTPConnection::processPacket(struct timeval *ts, unsigned char *data, 
		unsigned int data_len, bool reverse_dir)
{
	SCTPDataBlockList *blocks, *other_blocks;

	log.trace("handling SCTP packet ...  len: %u, src port: %u, dst port: %u, reverse: %s\n", 
			data_len, sctp_params.src.port, sctp_params.dst.port, reverse_dir ? "YES" : "NO" );

	if (reverse_dir) {
		blocks = &dst_data;
		other_blocks = &src_data;
	}
	else {
		blocks = &src_data;
		other_blocks = &dst_data;
	}

	if (sctp_handler) {
		// we need to have this BEFORE any message (if the handler wants to print message)
		
		SCTPData params(reverse_dir ? &sctp_params.dst: &sctp_params.src, 
				reverse_dir ? &sctp_params.src: &sctp_params.dst);

		sctp_handler->processSCTPMessage(data, data_len, &params, ts, this);
	}

	int chunk_type, flags, stream_id, stream_sqn;
	unsigned int chunk_length, tsn, payload_proto;
	if (data_len > 12) {
		//data inside SCTP
		data = data + 12;
		data_len -= 12;

		while (data_len > 0) {
			// data & data_len point to first chunk
			chunk_type = GET_BYTE(data, 0);
			flags = GET_BYTE(data, 1);
			chunk_length = GET_WORD(data, 2);
			log.trace(" ... chunk type: %d\n", chunk_type);

			if (chunk_type == 0) {
				// DATA chunk
				tsn = GET_DWORD(data, 4);
				stream_id = GET_WORD(data, 8);
				stream_sqn = GET_WORD(data, 10);
				payload_proto = GET_DWORD(data, 12);

				log.trace(" ... flags: %X\n", flags);
				log.trace(" ... chunk len: %d\n", chunk_length);
				log.trace(" ... tsn: %x\n", tsn);
				log.trace(" ... stream id: %x\n", stream_id);
				log.trace(" ... stream sequence number: %x\n", stream_sqn);

				unsigned char *chunk_data = data + 16;
				unsigned int chunk_data_len = chunk_length - 16;

				bool process = true;
				if (blocks->expected_tsn)
					if (isLess(tsn, blocks->expected_tsn)) process = false; // already processed

				if (process) {
					int ready_data_len_before = 0;
					if (blocks->data) ready_data_len_before = blocks->data->data_len;

					if (chunk_data_len > 0) {
						// data here
				/*			log.trace("data: %.*s\n", data_len - hdr_size, data + hdr_size); */
						addData(tsn, chunk_data, chunk_data_len, reverse_dir, ts);

						int data_len_now = 0;
						if (blocks->data) {
							data_len_now = blocks->data->data_len;
							// set expected CSeq to data after first block
							blocks->expected_tsn = blocks->data->next_tsn;
						}
						if (data_len_now != ready_data_len_before) tryHandleData(blocks, reverse_dir);
					}
				}
#if 0
				/* try SIP -V the protocol is text based and has identification inside ->
				 * try to parse it and see if it works or not */
				if (sip) {
					if (sip->processPacket(ts, chunk_data, chunk_data_len, &c) == 0) {
						//log->error("it is SIP\n");
						return 0;
					}
				}
#endif
			}

			if (chunk_length % 4 != 0) chunk_length += 4 - (chunk_length % 4);
			if (data_len < chunk_length) data_len = 0;
			else {
				data_len -= chunk_length;
				data += chunk_length;
			}
		}

	}

	return 0;

//

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
	return 0;
}

SCTPConnection::~SCTPConnection()
{
	freeBlocks(src_data.data);
	freeBlocks(dst_data.data);
}

////////////////////////////////////////////////////////////////////////
		
SCTPConnectionManager::SCTPConnectionManager() { first = NULL; }

SCTPConnectionManager::~SCTPConnectionManager()
{
	cleanup();
}

void SCTPConnectionManager::cleanup()
{
	SCTPConnection *c = first, *n;
	while (c) {
		n = c->next;
		delete c;
		c = n;
	}
	first = NULL;
}

SCTPConnection *SCTPConnectionManager::findSCTPConnection(SCTPData *params, bool &reverse_dir)
{
	if (!params) return NULL;

	SCTPConnection *c = first;
	while (c) {
		if ((c->sctp_params.src.equals(&params->src)) && 
				(c->sctp_params.dst.equals(&params->dst))) {
			reverse_dir = false;
			return c;
		}
		if ((c->sctp_params.src.equals(&params->dst)) && 
				(c->sctp_params.dst.equals(&params->src))) {
			reverse_dir = true;
			return c;
		}
		c = c->next;
	}
	return NULL;
}

SCTPConnection *SCTPConnectionManager::addSCTPConnection(SCTPData *params, SCTPDataHandler *h)
{
	SCTPConnection *c = new SCTPConnection(params, h);
	if (c) {
		// add to the beggining for quicker search of most recent connection
		c->next = first;
		first = c;
	}
	return c;
}

