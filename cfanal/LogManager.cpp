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

#include "LogManager.h"
		
void Log::log(LogLevel level, const char *s ...)
{
	va_list ap;
	va_list apc;
	va_start(ap, s);
	va_copy(apc, ap);

	vlog_ex(level, NULL, 0, s, apc);
	va_end(ap);
}


void Log::log_ex(LogLevel level, const char *file, int line, const char *s ...)
{
	va_list ap;
	va_list apc;
	va_start(ap, s);
	va_copy(apc, ap);

	vlog_ex(level, file, line, s, apc);
	va_end(ap);
}
		
////////////////////////////////////////////////////////////////////////////////

Logger::Logger(log_id_t id)
{
	log_id = id;
	l = NULL;
}

void Logger::vlog_ex(LogLevel level, const char *file, int line, const char *s, va_list ap)
{
	if (!l) l = LogManager::getDefaultLog(log_id);
	if (l) l->vlog_ex(level, file, line, s, ap);
}

Logger::~Logger()
{
	LogManager *lm = LogManager::getDefaultLogManager();
	if (l && lm) lm->releaseLog(l);
}

////////////////////////////////////////////////////////////////////////////////

LogManager *LogManager::defaultLogManager = NULL;
