// RtmpWatcher.Introp.h

#pragma once

#include "RtmpPacket.h"
#include "RtmpPacketTypeManaged.h"

namespace RtmpInterop {

	class RtmpPacketInterop
	{
		public:
			RtmpPacketInterop(RtmpPacket * packet);
			RtmpPacketInterop(array<unsigned char> ^bytes, int length, String ^ sourceIP, String ^ destIP);
			int GetLength();
			String ^ GetSourceIP();
			String ^ GetDestIP();
			array<unsigned char>^ GetBytes();
			RtmpPacketTypeManaged::RtmpPacketType GetRtmpPacketType();

		private:
			array<unsigned char>^ _bytes;
			int _length;
			String ^ _sourceIP;
			String ^ _destIp;
			RtmpPacketTypeManaged::RtmpPacketType _packetType;
			RtmpPacketTypeManaged::RtmpPacketType DeterminePacketType(RtmpPacket::RtmpDataTypes rawType);
	};
}
