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
