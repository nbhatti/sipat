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

#ifndef __TCP_CONNECTION_H
#define __TCP_CONNECTION_H

class TcpConnectionManager;

struct TcpDataBlock {
	unsigned int seq;
	unsigned char *data;
	unsigned int data_len;
	struct timeval ts;
	TcpDataBlock *prev, *next; // next data block
	unsigned char buf[1];
};

struct TcpDataBlockList {
	TcpDataBlock *data;
//	unsigned int acknowledged_seq;
	unsigned int expected_seq;
};

class TcpConnection;

class TcpDataHandler {
	public:
		virtual unsigned int processData(unsigned char* data, unsigned int data_len, TcpData *params, struct timeval *ts, TcpConnection *c) = 0;
};

class TcpConnection {
	protected:
		TcpData tcp_params;
		TcpConnection *next;
		TcpDataBlockList src_data;
		TcpDataBlockList dst_data;
		TcpDataHandler *tcp_handler;

		unsigned long user_flags;

		int ackData(TcpDataBlockList *list, unsigned int ack_num, bool reverse_dir);
		int tryHandleData(TcpDataBlockList *list, bool reverse_dir);
	public:
		TcpConnection(TcpData *params, TcpDataHandler *_tcp_handler);
		virtual ~TcpConnection();

		int processPacket(struct timeval *ts, unsigned char *data, unsigned int data_len, bool reverse_dir);
		int addData(unsigned int seq, unsigned char *data,
				unsigned int data_len, bool reverse_dir, struct timeval *ts);

		unsigned long getUserFlags() { return user_flags; }
		void setUserFlags(unsigned long f) { user_flags = f; }

		TcpData *getTcpParams() { return &tcp_params; }

	friend class TcpConnectionManager;
};

class TcpConnectionManager {
	protected:
		TcpConnection *first;

	public:
		TcpConnectionManager();
		virtual ~TcpConnectionManager();

		TcpConnection *findTcpConnection(TcpData *params, bool &reverse_dir);
		TcpConnection *addTcpConnection(TcpData *params, TcpDataHandler *h);

		virtual void cleanup();
};

#endif

