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
