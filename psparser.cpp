#ifndef WIN32
#include <netinet/in.h>
#include <arpa/inet.h>
#else
#include <winsock2.h>
#endif

#include <stdint.h>

#include "psparser.h"

PsPacketParser::PsPacketParser()
{
	h264buffersize = 1024 * 1024 * 4;
	h264buffer = new char[h264buffersize];
	h264packetsize = 0;
}

PsPacketParser::~PsPacketParser()
{
	if( h264buffer )
	{
		delete []h264buffer;
		h264buffer = NULL;
	}
}

void PsPacketParser::Parse(const char* data, size_t size) 
{
	if (size < 14 || 0xba010000 != *(int32_t*)data) return;
	int extlen = uint8_t(data[13]) & 0x07;
	if (size <= 14 + extlen) return;

	const char * buffer = data + (14 + extlen);
	int length = size - extlen - 14;
	while (length > 0) {
		if (length < 6) break;
		int32_t chunk_flag = *(int32_t*)buffer;
		uint16_t chunk_size = ntohs(*(uint16_t*)(buffer + 4));
		if (chunk_size + 6 > length) break;

		switch (chunk_flag)	{
		case 0xe0010000:
			ParsePes(buffer + 6, chunk_size);
			break;
		}

		buffer += (6 + chunk_size);
		length -= (6 + chunk_size);
	}
}

int PsPacketParser::getpacket(char **pktbuffer, uint32_t *pktsize)
{
	if( !pktbuffer )
		return -1;

	*pktbuffer = h264buffer;
	*pktsize = h264packetsize;
	h264packetsize = 0;

	return 0;
}

void PsPacketParser::ParsePes(const char* data, size_t size) 
{
	if (size > 3){
		int32_t len = uint8_t(data[2]) + 3;
//		if (size > len && callback) callback((char*)data + len, size - len, usrdata);
		if (size > len )
		{
			memcpy(h264buffer+h264packetsize, data + len, size - len);
			h264packetsize += size - len;
		}
	}
}