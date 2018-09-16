#pragma once

namespace RtmpInterop {

	class RtmpPacketTypeManaged{
	public:
		enum RtmpPacketType{
			Handshake = 0,
			ChunkSize = 1,
			Ping = 2,
			ServerBandwidth = 3,
			ClientBandwidth = 4,
			Audio = 4,
			Video = 5,
			Notify = 6,
			Invoke = 7,
			AggregateMessage = 8,
			Unknown = 9
		};
	};
}