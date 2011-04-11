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

#ifndef __DESTINATION_H
#define __DESTINATION_H

#include <cfanal/id.h>
#include <ostream>

class Destination
{
	protected:
		Destination *next;
		Destination *prev;
		char *name;
		unsigned int used;

	public:
		Destination();

		virtual ~Destination() { }
		virtual Destination *duplicate() = 0;
		virtual bool equals(Destination *d) = 0;
		virtual protocol_id_t identify() = 0;

		virtual void printName(std::ostream &os);
		virtual void printValue(std::ostream &os) = 0;
		virtual void cfprintDef(std::ostream &os, int x, int height);
		virtual void printLineType(std::ostream &os) { os << "10,0"; }

		void incUsed() { used++; }
		void decUsed() { if (used > 0) used--; }
		unsigned int getUsageCnt() { return used; }
		void setName(const char *new_name);
		const char *getName() { return name; }

	friend class DestinationManager;
	friend class DestinationList;
};

class DestinationList 
{
	protected:
		Destination *first;
		Destination *last;

	public:
		DestinationList();
		virtual ~DestinationList();

		virtual Destination *find(Destination *xd);
		virtual void add(Destination *d);
		virtual void remove(Destination *d);
		virtual void print(std::ostream &os, const char *separator);
};

class DestinationManager: public DestinationList
{
	protected:
		/* CF parameter */
		int startXPos;
		bool nameUsedBefore(Destination *d);

	public:
		DestinationManager();
		virtual ~DestinationManager();

		/** for sorting according usage 'time' */
		virtual void moveBehindLastUsed(Destination *d);

		virtual int computeCFWidth(int hspace);
		virtual void cfprintDef(std::ostream &os, int hspace, int height);
};


#endif
