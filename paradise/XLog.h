#pragma once

#include <fstream>
#include <stdarg.h>
#include <time.h>
#include "paradise.h"

class XLog
{
public:
	XLog(const char* filename)
	{
		file = new std::fstream();
		char dir[256] = { NULL };
		GetCurrentDirectoryA(128, dir);
		strcat_s(dir, "//");
		strcat_s(dir, filename);
		file->open(dir, std::fstream::out | std::fstream::ate | std::fstream::app);
	}
	~XLog()
	{
		file->close();
		SAFE_DELETE(file);
	}
	void print(const char* format, ...)
	{
		if (!file->is_open())
			return;
		char buffer[256] = { NULL };

		char buf[512] = { NULL };
		time_t now = time(0);
		struct tm _time;
		localtime_s(&_time, &now);
		strftime(buf, sizeof(buf), "[%H:%M:%S] ", &_time);

		va_list args;
		va_start(args, format);
		vsnprintf(buffer, sizeof(buffer), format, args);
		strcat_s(buffer, "\n");
		strcat_s(buf, buffer);
		file->write(buf, strlen(buf));
		va_end(args);
		file->flush();
	}
private:
	std::fstream* file = NULL;
};