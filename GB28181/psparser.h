#ifndef _PSPARSER_H__
#define _PSPARSER_H__

typedef int (*h264framecallback)(char* data, int length, void* usrdata);

class PsPacketParser {
public:
	void Parse(const char* data, size_t size);
	void setcallback(h264framecallback _callback, void* _usrdata);

private:
	void ParsePes(const char* data, size_t size);

private:
	h264framecallback callback;
	void *usrdata;
};

#endif