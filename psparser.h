#ifndef _PSPARSER_H__
#define _PSPARSER_H__

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int (*h264framecallback)(char* data, int length, void* usrdata);

class PsPacketParser {
public:
	PsPacketParser();
	~PsPacketParser();

	void Parse(const char* data, size_t size);
	int getpacket(char **pktbuffer, uint32_t *pktsize);
private:
	void ParsePes(const char* data, size_t size);

private:
	char *h264buffer;
	uint32_t h264buffersize;
	uint32_t h264packetsize;
};

#endif