#include "ProtocolHandler.h"
#include <stdlib.h>

		
int ProtocolHandler::initContext(ProtocolHandlerContext *context)
{
	log = LogManager::getDefaultLog(NULL);
	if (!log) return -1; /* can't continue without logger? */

	this->context = context;

	return 0;
}
		
void ProtocolHandler::releaseContext()
{
	log = NULL; /* release log */
	context = NULL; /* release context */
}


/////////////////////////////////////////////////////////////////////

void ProtocolHandlerContext::freeHandlers() 
{
	ProtocolHandler *h, *n;

	/* first release context of ALL protocol handlers
	 * (we can not free handlers if somebody casn still use them) */
	releaseContext();

	/* no handlers are used more, we can free them */
	if (autoFreeHandlers) {
		h = first;
		while (h) {
			n = h->next;
			delete h;
			h = n;
		}

	}

	first = NULL;
	last = NULL;
}
		
ProtocolHandler *ProtocolHandlerContext::find(protocol_id_t id)
{
	ProtocolHandler *h;

	h = first;
	while (h) {
		if (h->identify() == id) return h;
		h = h->next;
	}
	return NULL;
}

int ProtocolHandlerContext::initContext()
{
	ProtocolHandler *h;
	int res = 0, r;

	h = first;
	while (h) {
		r = h->initContext(this);
		if (r < 0) res = r;
		h = h->next;
	}
	return res;
}
	
void ProtocolHandlerContext::releaseContext()
{
	ProtocolHandler *h;

	h = first;
	while (h) {
		h->releaseContext();
		h = h->next;
	}
}


int ProtocolHandlerContext::add(ProtocolHandler *h)
{
	if (!h) return -1;

	h->next = NULL;
	h->prev = last;
	if (last) last->next = h;
	else first = h;
	last = h;

	return 0;
}
		
int ProtocolHandlerContext::remove(ProtocolHandler *h)
{
	if (!h) return -1;

	if (h->next) h->next->prev = h->prev;
	else last = h->prev;
	if (h->prev) h->prev->next = h->next;
	else first = h->next;

	h->next = NULL;
	h->prev = NULL;

	return 0;
}

ProtocolHandlerContext::ProtocolHandlerContext(MessageFlow *flow,
		bool auto_free_handlers) 
{ 
	autoFreeHandlers = auto_free_handlers; 
	first = NULL;
	last = NULL;
	this->flow = flow;
}

ProtocolHandlerContext::~ProtocolHandlerContext()
{
	freeHandlers();
}


