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

#ifndef __LOG_MANAGER_H
#define __LOG_MANAGER_H

#include <stdio.h>
#include <stdarg.h>

#define error(s, args...)	log_ex(LL_ERR, __FILE__, __LINE__, s, ##args)
#define warning(s, args...)	log_ex(LL_WARN, __FILE__, __LINE__, s, ##args)
#define info(s, args...)	log_ex(LL_INFO, __FILE__, __LINE__, s, ##args)
#define debug(s, args...)	log_ex(LL_DEBUG, __FILE__, __LINE__, s, ##args)
#define trace(s, args...)	log(LL_DEBUG, s, ##args)

enum LogLevel { LL_ERR, LL_WARN, LL_INFO, LL_DEBUG };

typedef const char *log_id_t;

class Log {
	public:
		virtual ~Log() { }
		virtual void log(LogLevel level, const char *s ...);	
		virtual void log_ex(LogLevel level, const char *file, int line, const char *s ...);	
		virtual void vlog_ex(LogLevel level, const char *file, int line, const char *s, va_list ap) = 0;	
};

/** simple class which only asks Default LogManager for log with given ID
 * first time when logging is called 
 *
 * usage:
 * static Logger my_log("some_area");
 * ...
 * some_func() {
 *   ...
 *   my_log.log(...)
 *   ...
 * }
 * */
class Logger: public Log {
	public:
		Log *l;
		log_id_t log_id;

		Logger(log_id_t id); /*< the id is not copied! thus the pointer must be valid for whole life of Logger instance*/
		virtual void vlog_ex(LogLevel level, const char *file, int line, const char *s, va_list ap);	
		virtual ~Logger();
};


class LogManager {
	protected:
		static LogManager *defaultLogManager;

	public:
		virtual ~LogManager() { }

		virtual Log *createLog(log_id_t id) = 0;
		virtual void releaseLog(Log *l) = 0;

		static LogManager *getDefaultLogManager() { return defaultLogManager; }
		static void setDefaultLogManager(LogManager *m) { defaultLogManager = m; }
		static Log *getDefaultLog(log_id_t id) { if (defaultLogManager) return defaultLogManager->createLog(id); else return NULL; }
};

#endif
