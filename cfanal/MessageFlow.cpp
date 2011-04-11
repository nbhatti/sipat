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

#include "MessageFlow.h"
#include <string.h>

Message::Message(Destination *src, Destination *dst, struct timeval *ts)
{
	if (ts) memcpy(&timeStamp, ts, sizeof(timeStamp));
	else {
		memset(&timeStamp, 0, sizeof(timeStamp));
	}
	this->src = src;
	this->dst = dst;
}
		
int Message::cmpTimeStamp(struct timeval *ts)
{
	if (!ts) return -2;

	if (ts->tv_sec < timeStamp.tv_sec) return -1;
	if (ts->tv_sec > timeStamp.tv_sec) return 1;
	if (ts->tv_usec < timeStamp.tv_usec) return -1;
	if (ts->tv_usec > timeStamp.tv_usec) return 1;
	return 0;
}
		
void Message::cfprint(std::ostream &os)
{
	//char tmp[256];
	os << identify() << " message";
	os << " at " << timeStamp.tv_sec << " s " << timeStamp.tv_usec << " us";
	os << " from ";
//	src->cfprint(os);
	os << " to ";
//	dst->cfprint(os);

/*	src->snprint(tmp, sizeof(tmp));
	printf("   src: %s\n", tmp); 
	dst->snprint(tmp, sizeof(tmp));
	printf("   dst: %s\n", tmp); */
}
		
void Message::txtprint(std::ostream &os)
{
	struct tm t;
	char tmp[128];
	gmtime_r(&timeStamp.tv_sec, &t);

	/* print header */
	if (src) src->printName(os);
	else os << "?";
	os << " -> ";
	if (dst) dst->printName(os);
	else os << "?";

	os << "      ";
	if (src) src->printValue(os);
	else os << "?";
	os << " -> ";
	if (dst) dst->printValue(os);
	else os << "?";

//	ios_base::fmtflags orig = os.flags();

	snprintf(tmp, sizeof(tmp), "%02d:%02d:%02d.%06ld", 
			t.tm_hour, t.tm_min, t.tm_sec, timeStamp.tv_usec);
//	os << " ... " << t.tm_hour << ":" << t.tm_min << ":" << (double)t.tm_sec + (double)timeStamp.tv_usec / 1000000.0 << "\n";
	os << " ... " << tmp;

//	os << orig;
}

/////////////////////////////////////////////

MessageFlow::MessageFlow(DestinationManager *aliases, bool auto_free, bool time_sort_destinations) 
{ 
	autoFree = auto_free; 
	sortDestinationsAccordingTime = time_sort_destinations;
	first = NULL;
	last = NULL;
	this->aliases = aliases;
	messageCount = 0;
	
	headingHeight = 30;
	vspacePerMessage = 10;
	vspacePerSelfMessage = 20;
	hspacePerDestination = 60;

	printStream = false;
}

void MessageFlow::releaseMessages()
{
	Message *m, *n;

	if (autoFree) {
		m = first;
		while (m) {
			n = m->next;
			delete m;
			m = n;
		}
	}

	first = NULL;
	last = NULL;
	messageCount = 0;
}

void MessageFlow::add(Message *m)
{
	Message *l;
	if (!m) return;

	if (printStream) {
		// just printing messages into stream, not storing them - used for large pcaps
		m->txtprint(stream);
		stream << "\n";
		messageCount++;
		delete m;
		return;
	}

	/* find last message with time stamp lower than this message time stamp */
	l = last;
	while (l) {
		if (l->cmpTimeStamp(&m->timeStamp) >= 0) break;
		l = l->prev;
	}

	m->prev = l;
	if (l) {
		m->next = l->next;
		if (l->next) l->next->prev = m;
		else last = m;
		l->next = m;
	}
	else {
		m->next = first;
		if (first) first->prev = m;
		else last = m;
		first = m;
	}

	messageCount++;
}
		
bool isSelfCall(Message *m) 
{
	Destination *src = m->getSrc();
	Destination *dst = m->getDst();

	if (src == dst) return true;

	const char *a = NULL;
	const char *b = NULL;

	if (src) a = src->getName();
	if (dst) b = dst->getName();

	if (a) {
		if (!b) return false;
		return (strcmp(a, b) == 0);
	}
	else {
		if (!b) return true;
	}

	return false;
}

void MessageFlow::computeCFDimensions(int *dst_width, int *dst_height)
{
	int height = messageCount * vspacePerMessage + headingHeight;
	int width = dm.computeCFWidth(hspacePerDestination);

	if (messageCount == 0) {
		height = 1;
		width = 1;
		/* zero leads to bigger empty image because gimp then uses 500 px by default */
	}
	else {
		height = headingHeight;

		Message *m = first;
		while (m) {
			if (isSelfCall(m)) height += vspacePerSelfMessage;
			else height += vspacePerMessage;
			m = m->next;
		}
	}
	
	if (dst_width) *dst_width = width;
	if (dst_height) *dst_height = height;
}

void MessageFlow::cfprint(std::ostream &os)
{
	int height, width;

	computeCFDimensions(&width, &height);

	os << "<?xml version='1.0' encoding='UTF-8'?>\n"
		"<flow width='" << width << "' height='" << height << "' scale='1'>\n"; 

	/* print definition of destinations */
	dm.cfprintDef(os, hspacePerDestination, height);
	os << "\n";

	/* print messages */
	Message *m = first;
	while (m) {
		os << "\t";
		m->cfprint(os);
		os << "\n";
		m = m->next;
	}	

	os << "\n</flow>\n";
}

void MessageFlow::txtprint(std::ostream &os)
{
	/* print messages */
	Message *m = first;
	int idx = 0;
	while (m) {
		os << "" << ++idx << ". message \n\n";
		m->txtprint(os);
		os << "--------------------------------------------------------------\n\n";
		m = m->next;
	}	
}


Destination *MessageFlow::knownDestination(Destination *d)
{
	Destination *a, *alias;
	a = dm.find(d);

	if (!a) {
		a = d->duplicate();
		if (a) {
			if (aliases) {
				alias = aliases->find(d);
				if (alias) a->setName(alias->getName());
			}
			dm.add(a);
		}
	}
	if (a) {
		if (a->getUsageCnt() == 0) {
			if (sortDestinationsAccordingTime) dm.moveBehindLastUsed(a);
		}
		a->incUsed();
	}
	return a;
}

		
bool MessageFlow::printStreamToFile(const char *fname)
{
	if (!fname) return false;
	stream.open(fname);
	if (stream) printStream = true;
	else printStream = false;
	return printStream;
}
