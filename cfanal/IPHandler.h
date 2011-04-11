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

#ifndef __IPHANDLER_H
#define __IPHANDLER_H

#include <cfanal/ProtocolHandler.h>
#include <cfanal/LogManager.h>
#include <stdio.h>

#define MAX_IP_HEADER_LEN   64
#define MAX_IP_PACKET_LEN   65536
#define MAX_IP_FRAGMENTS    8192

class IPAddress
{
	protected:
		unsigned char addr[4];	
	public:
		IPAddress(unsigned char *addr_start);
		IPAddress();
		bool operator==(IPAddress &a);
		bool operator!=(IPAddress &a) { return !(*this == a); }
		void operator=(IPAddress &a);
		
	friend class IPDestination;
};

/** Class defining IP packet identification used for reassembling fragmented packets. 
  Note that the structure is currently prepared for IPv4 only. */
class IPPacketID {
	public:
		IPAddress src;	///< source IP address 
		IPAddress dst;	///< destination IP address
		unsigned short protocol; ///< protocol identification
		unsigned short id;	///< packet identification from IP header

		/** compare packet ids */
		bool operator==(IPPacketID &b);
		IPPacketID(unsigned char *ip_header);
		IPPacketID(IPPacketID *id);
		IPPacketID();

		/* for tracing */
		void printTrace(Log *log, LogLevel ll);
};

struct IPPacketData {
	int data_len;
	struct timeval ts;

	IPPacketData *next;
	unsigned char data[1];
};

class ListedIPPacketID: public IPPacketID
{
	protected:
		IPPacketData *data;

	public:
		ListedIPPacketID *next;
		ListedIPPacketID(IPPacketID *id): IPPacketID(id) { next = NULL; data = NULL; }

		void addData(struct timeval *ts, const unsigned char *data, int data_len);
		bool findTimedData(struct timeval *ts, const unsigned char *data, int data_len);
};

class IPPacketIDList 
{
	protected:
		ListedIPPacketID *first;

	public:	
		ListedIPPacketID *add(IPPacketID *id);
		ListedIPPacketID *find(IPPacketID *id);

		IPPacketIDList();
		virtual ~IPPacketIDList();
};

class IPHandler;

class FragmentedIPPacket {
	protected:
		IPPacketID id;
		unsigned int defragmentedLength;
		unsigned char *defragmentedData;
		unsigned char *defragmentedHeader;
		FragmentedIPPacket *next;
		FragmentedIPPacket *prev;
		//unsigned char received[MAX_IP_FRAGMENTS / 8];
		unsigned char received[MAX_IP_FRAGMENTS]; /* TODO: reduce size */
		unsigned char buffer[MAX_IP_PACKET_LEN + MAX_IP_HEADER_LEN];

		void setRcvBits(unsigned int offset, unsigned int len);

	public:
		FragmentedIPPacket(IPPacketID *_id);
		~FragmentedIPPacket();

		void handleFragment(unsigned int offset, 
				unsigned char *data, unsigned int len, 
				unsigned char *header, unsigned int header_len,
				bool mf);

		bool isWholePacket();

	friend class IPHandler;
};

#define IGNORE_INTERVAL_US	1000

typedef enum { 
	DO_NOT_IGNORE = 0, ///< do not try to recognize already processed packets
	IGNORE_IP_ID_UNSAFE, ///< ignore the same IP packet ID (for nonzero ID)
	IGNORE_IP_ID_SAFE, ///< ignore the same IP packet ID (if fragmentation enabled!)
	IGNORE_SHORT_INTERVAL_SAME_DATA   ///< ignore the same data within an interval 
} IPPacketIgnoreType;

/** Handler for IPv4 packets.
 *
 * Its context contains:
 *  - list of packets which are still not fully defragmented
 *    and thus they couldn't be processed.
 *  - list of packet IDs which were already processed to be able to
 *    ignore already seen packets.
*/

class IPHandler: public ProtocolHandler {
	protected:
		IPPacketIgnoreType ignoreSeenPackets;
		FragmentedIPPacket *first;	///< first packet in fragmented packet list
		FragmentedIPPacket *last;	///< last packet in fragmented packet list

		IPPacketIDList idList;

		/** look if there is already given packet in reassembly 'queue' */
		FragmentedIPPacket *findFragmentedPacket(IPPacketID *id);

		void addFragmentedPacket(FragmentedIPPacket *p);
		void removeFragmentedPacket(FragmentedIPPacket *p);

		int processDefragmented(struct timeval *ts, 
				IPPacketID *id,
				unsigned char *header, 
				unsigned char *data, unsigned int data_len,
				ProtocolData *parent);

		/** returns true if the packet should be ignored */
		bool ignorePacket(struct timeval *ts, 
				IPPacketID *id,
				unsigned char *header, 
				unsigned char *data, 
				unsigned int data_len);

		ProtocolHandler *udp;
		ProtocolHandler *tcp;
		ProtocolHandler *sctp;
	public:
		static protocol_id_t id; ///< constant for IP

		virtual protocol_id_t identify() { return id; }
		virtual int processPacket(struct timeval *ts, 
				unsigned char *data, unsigned int data_len, 
				ProtocolData *parent);
		virtual int initContext(ProtocolHandlerContext *handlers);
		virtual void releaseContext();

		IPHandler(IPPacketIgnoreType ignore_seen_packets);
		virtual ~IPHandler();
};

class IPDestination: public Destination {
	public:
		IPAddress ip_addr;

		virtual protocol_id_t identify() { return IPHandler::id; }
		virtual Destination *duplicate();
		virtual bool equals(Destination *d);
		virtual void printValue(std::ostream &os);

		IPDestination(IPAddress &ip): ip_addr(ip) { }
		IPDestination(IPAddress *ip): ip_addr(ip ? ip->addr: NULL) { }
		IPDestination(unsigned char *ip): ip_addr(ip) { }
};

class IPData: public ProtocolData {
	public:
		IPDestination src, dst;
		virtual protocol_id_t identify() { return IPHandler::id; }

//		IPData(IPAddress &src_ip, IPAddress &dst_ip): src(src_ip), dst(dst_ip) { }
		IPData(unsigned char *ip_header): src(ip_header + 12), dst(ip_header + 16) { }
};



#endif

