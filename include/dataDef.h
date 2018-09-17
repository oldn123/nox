#pragma once
enum MsgType{
	eMt_send,
	eMt_sendto,
	eMt_WSASend,
	eMt_recv,
	eMt_recvfrom,
	eMt_WSARecv,
};


struct SendInfo
{
	SOCKET	sock;
	int		nLen;
	BYTE    data;
};

struct RecvInfo : public SendInfo
{

};



struct MsgInfo
{
	MsgType nType;
	union Data
	{
		SendInfo si;
		RecvInfo ri;

	} data;
};