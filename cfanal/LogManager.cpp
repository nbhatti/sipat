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
