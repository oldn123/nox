#pragma once

#include "RtmpPacket.h"

class RtmpPacketAggregator
{
public:
	RtmpPacketAggregator(int port);
	void Add(const char * data, int bytesTotal);
	void AddTcpData(const char * data, int bytesTotal);
	RtmpPacket * PacketReady();

private:
	RtmpPacket::RtmpDataTypes packetType;
	int totalExpected;
	int totalFound;
	
	bool foundStart;
	char * dataCopy;
	RtmpPacket::RtmpDataTypes payloadType;

	int _port;
};

