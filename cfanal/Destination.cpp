#include "Destination.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

DestinationList::DestinationList()
{
	first = NULL;
	last = NULL;
}

DestinationList::~DestinationList()
{
	Destination *d = first, *n;
	while (d) {
		n = d->next;
		delete d;
		d = n;
	}
	first = NULL;
	last = NULL;
}

Destination *DestinationList::find(Destination *xd)
{
	Destination *d = first;
	while (d) {
		if (d->equals(xd)) return d;
		d = d->next;
	}

	return NULL;
}

void DestinationList::add(Destination *d)
{
	if (!d) return;

	d->next = NULL;
	d->prev = last;
	if (last) last->next = d;
	else first = d;
	last = d;
}

void DestinationList::remove(Destination *d)
{
	if (!d) return;

	if (d->next) d->next->prev = d->prev;
	else last = d->prev;
	if (d->prev) d->prev->next = d->next;
	else first = d->next;

	d->next = NULL;
	d->prev = NULL;
}
		
void DestinationList::print(std::ostream &os, const char *separator)
{
	Destination *d = first;
	while (d) {
		d->printValue(os);
		if (separator && d->next) os << separator;
		d = d->next;
	}
}

////////////////////////////////////////////////

DestinationManager::DestinationManager()
{
	startXPos = 20;
}

DestinationManager::~DestinationManager()
{
}

bool DestinationManager::nameUsedBefore(Destination *d)
{
	// not huge amount of destinations expected -> O(x*x) is enough?
	if (!d) return false;

	const char *name = d->getName();
	if (!name) return false; // not using name -> can't check homonyms

	Destination *p = d->prev;
	while (p) {
		if (p->getUsageCnt() > 0) {
			const char *n = p->getName();
			if (n) if (strcmp(n, name) == 0) return true;
		}
		p = p->prev;
	}
	return false;
}

int DestinationManager::computeCFWidth(int hspace)
{
	int x = 0;
	int cnt = 0;
	Destination *d = first;
	while (d) {
		if ((d->getUsageCnt() > 0) && (!nameUsedBefore(d))) cnt++;
		d = d->next;
	}
	if (cnt > 0) {
		x = startXPos + cnt * hspace;
		//x = 2 * startXPos + (cnt - 1) * hspace;
	}
	else x = hspace;
	return x;
}

void DestinationManager::cfprintDef(std::ostream &os, int hspace, int height)
{
	int x = startXPos;
	os << "<objects>\n";
	Destination *d = first;
	while (d) {
		if ((d->getUsageCnt() > 0) && (!nameUsedBefore(d))) {
			os << "\t";
			d->cfprintDef(os, x, height);
			os << "\n";
			x += hspace;
		}
		/* else {
			const char *name = d->getName();
			printf("skipping destination %s, usage: %d\n", 
					name ? name : "xxx", d->getUsageCnt());
		} */
		d = d->next;
	}
	os << "</objects>\n";
}
	
void DestinationManager::moveBehindLastUsed(Destination *d)
{
	if (!d) return;
	remove(d);

	Destination *x = first;
	while (x) {
		if (x->getUsageCnt() > 0) x = x->next;
		else break;
	}

	if (x) {
		/* we should put d before x */
		d->next = x;
		d->prev = x->prev;
		if (d->prev) x->prev->next = d;
		else first = d;
		x->prev = d;
	}
	else {
		/* d should be the last one or none element in list */
		add(d);
	}
}

///////////////////////////////////////////////////////////////////////
		
void Destination::setName(const char *new_name)
{
	if (name) free(name);
	if (new_name) name = strdup(new_name);
	else name = NULL;
}

void Destination::printName(std::ostream &os)
{
	if (name) os << name;
	else {
		/* print value instead of name */
		printValue(os);
	}
}

void Destination::cfprintDef(std::ostream &os, int x, int height)
{
	os << "<object name='";
	printName(os);
	os << "' desc='";
	printName(os);
	os << "' x='" << x << "' y='" << height << "'/>";
}
	
Destination::Destination()
{
	next = NULL;
	prev = NULL;
	name = NULL;
	used = false;
}

