#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <Iphlpapi.h>
#include <Assert.h>
#include <process.h>
#include <assert.h>
//#include "HookApi.h"
#include "mhook.h"
//#include <openssl/rand.h>
//#include <openssl/ssl.h>
//#include <openssl/err.h>
#include <vector>
#include <queue>
#include <map>
#include <set>
using namespace std;
#include "../../eikasia.h"
#include "dataDef.h"
HINSTANCE g_hMod = NULL;


typedef int (WINAPI *PCONNECT)(SOCKET s, const struct sockaddr *address, int namelen);
typedef int (WINAPI *PGETHOSTBYNAME)(const char *name);
typedef int (WINAPI *PSEND)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI *PRECV)(SOCKET s, const char* buf, int len, int flags);
typedef int (WINAPI *PRECVFROM)(SOCKET s, char * buf, int len,int flags,struct sockaddr FAR * from,int * fromlen);
typedef int (WINAPI *PSENDTO) (SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen);
typedef int (WINAPI *PWSASEND)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef int (WINAPI *PWSARECV)(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
typedef SOCKET (WINAPI *PSOCKET) (int af, int type, int protocol);
typedef int (WINAPI *PCLOSESOCKET) (SOCKET s);


/*
typedef int (WINAPI *PSPRINTF) (char *_Dest, const char *_Format, va_list ap);
typedef time_t (WINAPI *PTIME)(time_t *);

typedef void (WINAPI *PGRFREADER) (char *grf_file, int grf_num);
typedef void (__fastcall *PHOTKEY) (int key_num);
typedef int (WINAPI *PMakeWindow) (int window);
typedef int (WINAPI *PLoginWindow) (int a, int b);
*/
PSOCKET	OrigSocket = (PSOCKET)
	GetProcAddress(GetModuleHandle("Ws2_32.dll"), "socket");

PCONNECT OrigConnect = (PCONNECT)
	GetProcAddress(GetModuleHandle("Ws2_32.dll"), "connect");

PSEND OrigSend = (PSEND)
	GetProcAddress(GetModuleHandle("Ws2_32.dll"), "send");

PSENDTO	OrigSendTo = (PSENDTO)
	GetProcAddress(GetModuleHandle("Ws2_32.dll"), "sendto");

PWSASEND OrigWSASend = (PWSASEND)
	GetProcAddress(GetModuleHandle("Ws2_32.dll"), "WSASend");

PWSARECV OrigWSARecv = (PWSARECV)
	GetProcAddress(GetModuleHandle("Ws2_32.dll"), "WSARecv");

PRECVFROM OrigRecvfrom = (PRECVFROM)
	GetProcAddress(GetModuleHandle("Ws2_32.dll"), "recvfrom");

PRECV OrigRecv  = (PRECV)
	GetProcAddress(GetModuleHandle("Ws2_32.dll"), "recv");

PCLOSESOCKET OrigClosesocket = (PCLOSESOCKET)
	GetProcAddress(GetModuleHandle("Ws2_32.dll"), "closesocket");

PGETHOSTBYNAME OrigGethost;

/*
PGRFREADER OrigGrfReader;
PHOTKEY OrigHotKey;

PMakeWindow OrigMakeWindow;
int WINAPI MyMakeWindow(int window) {
	return OrigMakeWindow(window);
}


PLoginWindow OrigLoginWindow;
int WINAPI MyLoginWindow(int a, int b) {
	return OrigLoginWindow(a, b);
}

PSPRINTF OrigSprintf;
PTIME OrigTime;*/

SOCKET sockMsg = 0;
struct sockaddr_in addr;   
int addr_len = sizeof(struct sockaddr_in);  

void SendData(MsgInfo & mi, int nSize)
{
	if (sockMsg > 0)
	{
		int ret = OrigSendTo(sockMsg, (char*)&mi, nSize, 0, (struct sockaddr*)&addr, addr_len);
		if (ret == -1)
		{
			OutputDebugStringA(">>> 发送数据失败");
		}
	}
}

void hextostr(char *ptr,unsigned char *buf,int len)
{
	if (len > 999)
	{
		len = 999;
	}
	for(int i = 0; i < len; i++)
	{
		sprintf(ptr, "%02x",buf[i]);
		ptr += 2;
	}
}

bool ReplaceBuf(char * pSrcBuf, char * strFind, char * strRep)
{
	char * pfind = strstr((char*)&pSrcBuf[0], strFind);
	if (pfind)
	{
		memcpy(pfind, strRep, strlen(strRep));
		return true;
	}
	return false;
}


SYSTEMTIME st;

//===========================Socket===========================
SOCKET WINAPI MySocket(int af, int type, int protocol) {
	return OrigSocket(af, type, protocol);
}

int WINAPI MyClosesocket (SOCKET s) {
	int nret = OrigClosesocket(s);
	return nret;
}
/*
int WINAPI MySprintf (char *_Dest, const char *_Format, ...) {

	va_list ap;
	int ret;

	va_start(ap,_Format);
	ret = vsprintf(_Dest, _Format, ap);
	va_end(ap);

	return ret;
}

void test(char *grf_file, int grf_num) {
	char msgbuf[255];
	const char* grf_files[] = { "data.grf", "rdata.grf" };
	int i = 0, e =0;

	for(i=0; i <= ARRAYLENGTH(grf_files); i++) {
		if(strcmp(grf_files[0],grf_file) == 0)
			break;
		else
			e++;
	}
			FILE *fp = fopen("log.txt", "ab");
			sprintf(msgbuf, "%d - %s", grf_num, grf_file);
			fwrite(msgbuf, strlen(msgbuf), 1, fp);
			fputc(0x0d, fp);
			fputc(0x0a, fp);
			fclose(fp);

	if(e > ARRAYLENGTH(grf_files))
		exit(0);
}

void WINAPI MyGrfReader(char *grf_file, int grf_num) {
	OrigGrfReader(grf_file, grf_num);
	//test(grf_file, grf_num);
}

void __fastcall MyHotKey(int key_num) {
	OrigHotKey(key_num);
	//test(grf_file, grf_num);
}
*/

//===========================SEND===========================
int WINAPI __stdcall MySend(SOCKET s, const char* buf, int len, int flags)
{
	char stext[80] = {0};
	sprintf(stext, ">>> send: %d\n", len);
	OutputDebugStringA(stext);

	char * pData = new char[len + sizeof(MsgInfo)];
	MsgInfo & mi = *(MsgInfo*)pData;
	mi.nType = eMt_send;
	mi.data.si.sock = s;
	mi.data.si.nLen = len;
	memcpy(&mi.data.si.data, buf, len);
	SendData(mi, len+sizeof(MsgInfo));
	delete [] pData;

	int SentBytes = OrigSend(s, buf, len, flags);
	if(SentBytes == SOCKET_ERROR) return SentBytes;
	return SentBytes;
}

//===========================WSASEND===========================
int WINAPI __stdcall MyWSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	char stext[80] = {0};
	sprintf(stext, ">>> wsaSend: %d\n", dwBufferCount );
	OutputDebugStringA(stext);

	char * pData = new char[dwBufferCount + sizeof(MsgInfo)];
	MsgInfo & mi = *(MsgInfo*)pData;
	mi.nType = eMt_WSASend;
	mi.data.si.sock = s;
	mi.data.si.nLen = dwBufferCount;
	memcpy(&mi.data.si.data, lpBuffers, dwBufferCount);
	SendData(mi, dwBufferCount+sizeof(MsgInfo));
	delete [] pData;

	int Errors = OrigWSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, lpFlags, lpOverlapped, lpCompletionRoutine);
	if(Errors == SOCKET_ERROR) return Errors;
	return Errors;
}

//===========================SENDTO===========================
int WINAPI __stdcall MySendTo(SOCKET s, const char *buf, int len, int flags, const struct sockaddr *to, int tolen)
{
	char stext[80] = {0};
	sprintf(stext, ">>> sendTo: %d\n", len );
	OutputDebugStringA(stext);

	char * pData = new char[len + sizeof(MsgInfo)];
	MsgInfo & mi = *(MsgInfo*)pData;
	mi.nType = eMt_sendto;
	mi.data.si.sock = s;
	mi.data.si.nLen = len;
	memcpy(&mi.data.si.data, buf, len);
	SendData(mi, len+sizeof(MsgInfo));
	delete [] pData;


	return OrigSendTo(s, buf, len, flags, to, tolen);
}

//===========================RECV===========================
int WINAPI __stdcall MyRecv(SOCKET s, const char* buf, int len, int flags)
{
	int RecvedBytes = 0;
	RecvedBytes = OrigRecv(s, (char*)buf, len, flags);
	if (RecvedBytes > 0)
	{
		char * pData = new char[RecvedBytes + sizeof(MsgInfo)];
		MsgInfo & mi = *(MsgInfo*)pData;
		mi.nType = eMt_recv;
		mi.data.ri.sock = s;
		mi.data.ri.nLen = RecvedBytes;
		memcpy(&mi.data.si.data, buf, RecvedBytes);
		SendData(mi, RecvedBytes + sizeof(MsgInfo));
		delete [] pData;
	}
	return RecvedBytes;
}

//===========================RECVFROM===========================
int WINAPI __stdcall MyRecvfrom(SOCKET s, char * buf, int len,int flags,struct sockaddr FAR * from,int * fromlen)
{
	int RecvedBytes = 0;
	RecvedBytes = OrigRecvfrom(s, (char*)buf, len, flags, from, fromlen);
	if (RecvedBytes > 0)
	{
		char * pData = new char[RecvedBytes + sizeof(MsgInfo)];
		MsgInfo & mi = *(MsgInfo*)pData;
		mi.nType = eMt_recvfrom;
		mi.data.ri.sock = s;
		mi.data.ri.nLen = RecvedBytes;
		memcpy(&mi.data.si.data, buf, RecvedBytes);
		SendData(mi, RecvedBytes + sizeof(MsgInfo));
		delete [] pData;
	}
	return RecvedBytes;
}

//===========================WSARECV===========================
int WINAPI __stdcall MyWSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine)
{
	int Errors = OrigWSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
	if(Errors == SOCKET_ERROR) return Errors;

	char stext[80] = {0};
	sprintf(stext, ">>> wsaRecv: %d\n", *lpNumberOfBytesRecvd );
	OutputDebugStringA(stext);
	int RecvedBytes = *lpNumberOfBytesRecvd;
	if (RecvedBytes > 0)
	{
		char * pData = new char[RecvedBytes + sizeof(MsgInfo)];
		MsgInfo & mi = *(MsgInfo*)pData;
		mi.nType = eMt_WSARecv;
		mi.data.ri.sock = s;
		mi.data.ri.nLen = RecvedBytes;
		memcpy(&mi.data.si.data, lpBuffers, RecvedBytes);
		SendData(mi, RecvedBytes + sizeof(MsgInfo));
		delete [] pData;
	}

	return Errors;
}

//===========================CONNECT===========================
int WINAPI __stdcall MyConnect(SOCKET s, const struct sockaddr *address, int namelen)
{
	char stext[80] = {0};
	sprintf(stext, ">>> connect: %d\n", address->sa_data);
	OutputDebugStringA(stext);

	int errors = OrigConnect(s, address, namelen);
	if(errors == SOCKET_ERROR) return errors;
	return errors;
}



//===========================GETHOSTBYNAME===========================
int WINAPI __stdcall Mygethostbyname(const char *name)
{
	return OrigGethost(name);

}

bool g_bquit = false;


int InitSvrSocket()
{
	//sendto中使用的对方地址
	struct sockaddr_in toAddr;
	//在recvfrom中使用的对方主机地址
	struct sockaddr_in fromAddr;
	int recvLen;
	int addrLen = 0;
	char recvBuffer[128] = {0};
	sockMsg = OrigSocket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if(sockMsg < 0)
	{
		return 0;
	}

	// 填写sockaddr_in
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(4012);					//  将16位主机字符顺序转换成网络字符顺序 
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");	// 网络地址字符串转换成网络所使用的二进制数字（无符号长整型）

	memset(&fromAddr,0,sizeof(fromAddr));
	fromAddr.sin_family=AF_INET;
	fromAddr.sin_addr.s_addr=htonl(INADDR_ANY);
	fromAddr.sin_port = htons(4011);
	if(bind(sockMsg,(struct sockaddr*)&fromAddr,sizeof(fromAddr))<0)
	{
		OrigClosesocket(sockMsg);
		return 0;
	}
	while(!g_bquit){
		addrLen = sizeof(toAddr);
		memset(recvBuffer, 0, 128);
		if((recvLen = OrigRecvfrom(sockMsg,recvBuffer,128,0,(struct sockaddr*)&toAddr,&addrLen)) > 0)
		{
			if (strncmp(recvBuffer, "****on", 6) == 0)
			{
				EnableHook(true);
			}
			else if (strncmp(recvBuffer, "****off", 7) == 0)
			{
				EnableHook(false);
			}
			else if (strncmp(recvBuffer, "****quit", 8) == 0)
			{
				EnableHook(false);
				g_bquit = false;
				break;
			}
		}

		Sleep(500);
	}

// 	OutputDebugStringA(">>> free ok");
// 	if(FreeLibrary(g_hMod))
// 	{
// 		OutputDebugStringA(">>> free ok");
// 	}
// 	else
// 	{
// 		OutputDebugStringA(">>> free faild");
// 	}
	return 1;
}


//#ifdef _TestMode
unsigned __stdcall ThreadStaticEntryPoint(void*)
{
// 	do 
// 	{	
// 		if (g_dwTestTick == 0)
// 		{
// 			g_dwTestTick = GetTickCount();
// 		}
// 		else
// 		{
// 			if(GetTickCount() - g_dwTestTick > 1000 * 60)
// 			{
// 
// 			}
// 		}
// 		Sleep(1000*60);
// 	} while (true);
	InitSvrSocket();


	return 1;// the thread exit code
}
//#endif


void WINAPI EndHook()
{
	EnableHook(FALSE);
}

bool WINAPI EnableHook(BOOL bHook)
{
	OutputDebugStringA(">>> EnableHook in");
	int n = 0;
	if (bHook)
	{
		if (Mhook_SetHook((PVOID*)&OrigRecv, MyRecv)) {		
			n++;
		}

		if (Mhook_SetHook((PVOID*)&OrigWSARecv, MyWSARecv)) {		
			n++;
		}

		if (Mhook_SetHook((PVOID*)&OrigRecvfrom, MyRecvfrom)) {		
			n++;
		}

		if (Mhook_SetHook((PVOID*)&OrigSend, MySend)) {		
			n++;
		}

		if (Mhook_SetHook((PVOID*)&OrigSendTo, MySendTo)) {		
			n++;
		}

		if (Mhook_SetHook((PVOID*)&OrigWSASend, MyWSASend)) {		
			n++;
		}

		if (Mhook_SetHook((PVOID*)&OrigClosesocket, MyClosesocket)) {		
			n++;
		}

		if (Mhook_SetHook((PVOID*)&OrigSocket, MySocket)) {		
			n++;
		}

		if (Mhook_SetHook((PVOID*)&OrigConnect, MyConnect)) {		
			n++;
		}

		if (n == 9)
		{
			OutputDebugStringA(">>> EnableHook(1) ret true");
		}
		else
		{
			OutputDebugStringA(">>> EnableHook(1) ret false");
		}
	}
	else
	{
		if (Mhook_Unhook((PVOID*)&OrigRecv)) {		
			n++;
		}

		if (Mhook_Unhook((PVOID*)&OrigWSARecv)) {		
			n++;
		}

		if (Mhook_Unhook((PVOID*)&OrigRecvfrom)) {		
			n++;
		}

		if (Mhook_Unhook((PVOID*)&OrigSend)) {		
			n++;
		}

		if (Mhook_Unhook((PVOID*)&OrigSendTo)) {		
			n++;
		}

		if (Mhook_Unhook((PVOID*)&OrigWSASend)) {		
			n++;
		}

		if (Mhook_Unhook((PVOID*)&OrigClosesocket)) {		
			n++;
		}

		if (Mhook_Unhook((PVOID*)&OrigSocket)) {		
			n++;
		}

		if (Mhook_Unhook((PVOID*)&OrigConnect)) {		
			n++;
		}

		OrigSocket = (PSOCKET)
			GetProcAddress(GetModuleHandle("Ws2_32.dll"), "socket");

		OrigConnect = (PCONNECT)
			GetProcAddress(GetModuleHandle("Ws2_32.dll"), "connect");

		OrigSend = (PSEND)
			GetProcAddress(GetModuleHandle("Ws2_32.dll"), "send");

		OrigSendTo = (PSENDTO)
			GetProcAddress(GetModuleHandle("Ws2_32.dll"), "sendto");

		OrigWSASend = (PWSASEND)
			GetProcAddress(GetModuleHandle("Ws2_32.dll"), "WSASend");

		OrigWSARecv = (PWSARECV)
			GetProcAddress(GetModuleHandle("Ws2_32.dll"), "WSARecv");

		OrigRecvfrom = (PRECVFROM)
			GetProcAddress(GetModuleHandle("Ws2_32.dll"), "recvfrom");

		OrigRecv  = (PRECV)
			GetProcAddress(GetModuleHandle("Ws2_32.dll"), "recv");

		OrigClosesocket = (PCLOSESOCKET)
			GetProcAddress(GetModuleHandle("Ws2_32.dll"), "closesocket");
		
		if (n == 9)
		{
			OutputDebugStringA(">>> EnableHook(0) ret true");
		}
		else
		{
			OutputDebugStringA(">>> EnableHook(0) ret false");
		}
	}

	return n == 2;
}

//#endif


void WINAPI WinsockHook(HINSTANCE hInst)
{

	g_hMod = hInst;
	//WSADATA wsaData;
	//char msgbuf[255];
	//WSAStartup(MAKEWORD(1,1), &wsaData);

//	FILE *fp = fopen("log.txt", "ab");
//	sprintf(msgbuf, "%x", GetProcAddress(GetModuleHandle("Ws2_32.dll"), "send"));
//	fwrite(msgbuf, strlen(msgbuf), 1, fp);
//	fputc(0x0d, fp);
//	fputc(0x0a, fp);
//	fclose(fp);


// 	if(DoCreateWnd(hInst))
// 	{
// 		OutputDebugStringA(">>> 窗口创建ok");
// 	}
// 	else
// 	{
// 		OutputDebugStringA(">>> 窗faild");
// 	}

// 	g_hj.AddHookFun("Ws2_32.dll","closesocket", (DWORD)MyClosesocket);
// 	g_hj.AddHookFun("Ws2_32.dll","recv", (DWORD)MyRecv);
// 
// 	g_hj.SetHookOn("closesocket");
// 	g_hj.SetHookOn("recv");

	HANDLE hProc = NULL;

//#ifdef _TestMode
	unsigned int dwThread = 0;
	HANDLE hth1 = (HANDLE)_beginthreadex(NULL,0,ThreadStaticEntryPoint,0,CREATE_SUSPENDED,&dwThread);
	ResumeThread(hth1);
//#endif	// Set the hook
	
	OutputDebugStringA(">>> 123");

	EnableHook(TRUE);

	OutputDebugStringA(">>> 456");
}