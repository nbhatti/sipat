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

#ifndef __MESSAGE_FLOW_H
#define __MESSAGE_FLOW_H

#include <sys/time.h>
#include <stdio.h>

#include <cfanal/Destination.h>
#include <cfanal/id.h>

#include <ostream>
#include <iostream>
#include <fstream>

class MessageFlow;

class Message {
	public:
		struct timeval timeStamp;

	protected:
		Message *next;
		Message *prev;

		Destination *src;
		Destination *dst;

	public:
		Message(Destination *src, Destination *dst, struct timeval *ts);
		virtual ~Message() { }
		virtual protocol_id_t identify() = 0;

		//virtual void printMessage();
		virtual void cfprint(std::ostream &os);
		virtual void txtprint(std::ostream &os);
		//virtual unsigned int getCfWidth(); //< returns width of message in call flow diagram

		Destination *getSrc() { return src; }
		Destination *getDst() { return dst; }
		Message *getNext() { return next; }
		Message *getPrev() { return prev; }

		int cmpTimeStamp(struct timeval *ts);
	friend class MessageFlow;
};

class MessageFlow {
	protected:
		bool autoFree;
		bool sortDestinationsAccordingTime;

		/* CF related parameters */
		int headingHeight;
		int vspacePerMessage;
		int vspacePerSelfMessage;
		int hspacePerDestination;

		int messageCount;
		DestinationManager dm;
		DestinationManager *aliases;

		void computeCFDimensions(int *dst_width, int *dst_height);

		bool printStream;
		std::ofstream stream;
	public:
		Message *first;
		Message *last;

		MessageFlow(DestinationManager *aliases, bool auto_free, bool time_sort_destinations);
		virtual ~MessageFlow() { releaseMessages(); if (printStream) stream.close(); }

		bool printStreamToFile(const char *fname);
		void add(Message *m);
		void releaseMessages();
		Message *getFirstMessage() { return first; }
		Message *getNextMessage(Message *m) { if (m) return m->next; else return NULL; }

		virtual void cfprint(std::ostream &os);
		virtual void txtprint(std::ostream &os);

		/** duplicate the destination and put into list of known ones 
		 * or return existing one if already exists */
		virtual Destination *knownDestination(Destination *d);
};

#endif
