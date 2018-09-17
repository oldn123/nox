
// wjs.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "wjs.h"
#include "wjsDlg.h"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Iprtrmib.h>
#include <stdlib.h>
#include <iostream>
#include <vector>

using std::cin;
using std::cout;
using std::endl;
using std::vector;
using std::string;


#pragma  comment(lib,"Psapi.lib")
#pragma  comment(lib,"Iphlpapi.Lib")
#pragma  comment(lib,"WS2_32.lib")

#include "..\DllInjector\dllinjector.h"
#ifdef _DEBUG
#pragma comment(lib, "..\\debug\\DllInjector.lib")
#else
#pragma comment(lib, "..\\release\\finder.lib")
#endif


bool sendbuf(char * strData)
{
	int sock;
	//sendto中使用的对方地址
	struct sockaddr_in toAddr;
	//在recvfrom中使用的对方主机地址
	struct sockaddr_in fromAddr;
	int fromLen = 0;
	char recvBuffer[128];
	bool bok = false;
	do 
	{
		sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
		if(sock < 0)
		{
			break;
		}
		
		memset(&toAddr,0,sizeof(toAddr));
		toAddr.sin_family=AF_INET;
		toAddr.sin_addr.s_addr=inet_addr("127.0.0.1");
		toAddr.sin_port = htons(4011);

		char buf[128] = {0};
		strcpy(buf, strData);
		if(sendto(sock,buf,strlen(buf),0,(struct sockaddr*)&toAddr,sizeof(toAddr)) < 1)
		{
			break;
		}
		bok = true;
// 		fromLen = sizeof(fromAddr);
// 		if(recvfrom(sock,recvBuffer,128,0,(struct sockaddr*)&fromAddr,&fromLen)<0)
// 		{
// 			break;
// 		}
	} while (0);


	printf("recvfrom() result:%s\r\n",recvBuffer);
	closesocket(sock);

	return bok;
}



#ifdef _DEBUG
#define new DEBUG_NEW
#endif
HWND g_hMsgWndDest = NULL;
HWND g_hMsgWnd = NULL;
int g_nHotKeyID1 = 100;
int g_nHotKeyID2 = 101;
int g_nHotKeyID3 = 102;
// CwjsApp

BEGIN_MESSAGE_MAP(CwjsApp, CWinApp)
	ON_COMMAND(ID_HELP, &CWinApp::OnHelp)
END_MESSAGE_MAP()


// CwjsApp construction

CwjsApp::CwjsApp()
{
	// support Restart Manager
	m_dwRestartManagerSupportFlags = AFX_RESTART_MANAGER_SUPPORT_RESTART;

	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}



//#define TestMode

// The one and only CwjsApp object

CwjsApp theApp;



DWORD WINAPI GetIDProcessByName(const char* pszProcessName)
{
	DWORD id = 0; 
	//获得系统快照句柄 (通俗的讲, 就是得到当前的所有进程) 
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0) ; 
	PROCESSENTRY32 pInfo; //用于保存进程信息的一个数据结构 
	pInfo.dwSize = sizeof(pInfo); 
	//从快照中获取进程列表 
	Process32First(hSnapShot, &pInfo) ; //从第一个进程开始循环 
	do 
	{ 
		//这里的 pszProcessName 为你的进程名称 
		if(stricmp(strlwr(_strdup(pInfo.szExeFile)), pszProcessName) == 0) 
		{ 
			id = pInfo.th32ProcessID ; 
			break ; 
		} 
	}while(Process32Next(hSnapShot, &pInfo) != FALSE); 

	return id;
}


DWORD dwId = 0;
HWND hWndGame = NULL;
HMODULE g_hMod = NULL;
DWORD DoInject()
{
	// TODO: Add your control notification handler code here
	do 
	{
		//hWndGame = FindWindow(NULL, "维加斯 - Google Chrome");
// 		if (!hWndGame)
// 		{
// 			hWndGame = FindWindow("Chrome_WidgetWin_1", NULL);
// 		}

		dwId = GetIDProcessByName("nox.exe");

		if (dwId)
		{
// 			dwId = 0;
// 			GetWindowThreadProcessId(hWndGame, &dwId);
// 			if (dwId != 0)
			{
				TCHAR strFile[MAX_PATH] = {0};
				GetModuleFileName(NULL, strFile, MAX_PATH);
				CString sFile = strFile;
				CString sName = sFile.Right(sFile.GetLength() - sFile.ReverseFind('\\'));
				sFile.Replace((LPCTSTR)sName, "\\eikn.dll");

				g_hMod = InjectDll(dwId, sFile, LoadLib, ThreadHijacking);
				if(g_hMod)
				{
					break;
				}
				dwId = 0;
			}
		}
		OutputDebugStringA(">>> 注入失败!");
		//MessageBox(0,"Network connection faild","message",MB_OK);
	} while (0);

	return dwId;

	//CDialogEx::OnOK();
}


CString GetHostbyName(const char * HostName)
{
	CString strIPAddress=_T("");
	int WSA_return;
	WSADATA WSAData;

	WSA_return=WSAStartup(0x0202,&WSAData);
	/* 结构指针 */ 
	HOSTENT *host_entry;
	if(WSA_return==0)
	{
		/* 即要解析的域名或主机名 */
		host_entry=gethostbyname(HostName);
		if(host_entry!=0)
		{
			strIPAddress.Format(_T("%d.%d.%d.%d"),
				(host_entry->h_addr_list[0][0]&0x00ff),
				(host_entry->h_addr_list[0][1]&0x00ff),
				(host_entry->h_addr_list[0][2]&0x00ff),
				(host_entry->h_addr_list[0][3]&0x00ff));
		}
	}
	return strIPAddress;
}

DWORD g_dwPid = 0;

LRESULT CALLBACK WndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	switch (uMsg)
	{
	case WM_HOTKEY:
		{
			OutputDebugStringA(">>> hotkey 1");
			if (wParam == g_nHotKeyID1)
			{
				OutputDebugStringA(">>> hotkey on");
				if(sendbuf("****on"))
				{
					OutputDebugStringA(">>> sendbuf on ok");
				}
				else
				{
					OutputDebugStringA(">>> sendbuf on faild");
				}
			}
			else if (wParam == g_nHotKeyID2)
			{
				OutputDebugStringA(">>> hotkey off");
				if(sendbuf("****off"))
				{
					OutputDebugStringA(">>> sendbuf off ok");
				}
				else
				{
					OutputDebugStringA(">>> sendbuf off faild");
				}
			}
			else if (wParam == g_nHotKeyID3)
			{
				sendbuf("****quit");

				//RemoteEject(g_dwPid, );

				DestroyWindow(hWnd);
				//SendMessage(hWnd, WM_CLOSE, 0,0);
			}
			OutputDebugStringA(">>> hotkey 4");
		}
		break;
	case WM_DESTROY:
		UnregisterHotKey(hWnd, g_nHotKeyID1);
		UnregisterHotKey(hWnd, g_nHotKeyID2);
		UnregisterHotKey(hWnd, g_nHotKeyID3);
		PostQuitMessage(0);//可以使GetMessage返回0
		break;
	default:
		break;
	}

	return DefWindowProc(hWnd, uMsg, wParam, lParam);

}


bool DoCreateWnd(HINSTANCE hInst)
{
	//注册窗口类

	WNDCLASSEX wce = { 0 };
	wce.cbSize = sizeof(wce);
	wce.cbClsExtra = 0;
	wce.cbWndExtra = 0;
	wce.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wce.hCursor = NULL;
	wce.hIcon = NULL;
	wce.hIconSm = NULL;
	wce.hInstance = hInst;
	wce.lpfnWndProc = WndProc;
	wce.lpszClassName = "EikMsgWndA";
	wce.lpszMenuName = NULL;
	wce.style = CS_HREDRAW | CS_VREDRAW;
	ATOM nAtom = RegisterClassEx(&wce);
	if (!nAtom )
	{
		return false;
	}

	g_hMsgWnd = CreateWindowEx(0, "EikMsgWndA", "", WS_POPUPWINDOW, 0, 0, 0, 0, NULL, NULL, hInst, NULL);
	if (!g_hMsgWnd)
	{
		return false;
	}


	//向系统注册热键:ALT+0



	BOOL bKeyRegistered1 =RegisterHotKey(g_hMsgWnd, g_nHotKeyID1, MOD_CONTROL,VK_F1);
	BOOL bKeyRegistered2 =RegisterHotKey(g_hMsgWnd, g_nHotKeyID2, MOD_CONTROL,VK_F2);
	BOOL bKeyRegistered3 =RegisterHotKey(g_hMsgWnd, g_nHotKeyID3, MOD_CONTROL,VK_F3);
	if (bKeyRegistered1 && bKeyRegistered2)
	{
		OutputDebugStringA(">>> hotkey reg ok");
	}
	else
	{
		OutputDebugStringA(">>> hotkey reg faild");
	}

	return true;
}



// CwjsApp initialization

BOOL CwjsApp::InitInstance()
{
	// InitCommonControlsEx() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	INITCOMMONCONTROLSEX InitCtrls;
	InitCtrls.dwSize = sizeof(InitCtrls);
	// Set this to include all the common control classes you want to use
	// in your application.
	InitCtrls.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&InitCtrls);

	CWinApp::InitInstance();


	AfxEnableControlContainer();

	// Create the shell manager, in case the dialog contains
	// any shell tree view or shell list view controls.
	CShellManager *pShellManager = new CShellManager;

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	// of your final executable, you should remove from the following
	// the specific initialization routines you do not need
	// Change the registry key under which our settings are stored
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));

	CString sIp = GetHostbyName("qqyonghu888.3322.org");
	if (sIp != "192.168.1.140")
	{
		return FALSE;
	}

#ifdef TestMode

	CwjsDlg dlg;
	m_pMainWnd = &dlg;
	INT_PTR nResponse = dlg.DoModal();
	if (nResponse == IDOK)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with OK
	}
	else if (nResponse == IDCANCEL)
	{
		// TODO: Place code here to handle when the dialog is
		//  dismissed with Cancel
	}
#else
	DoCreateWnd(AfxGetInstanceHandle());

	g_dwPid = DoInject();
	if(g_dwPid)
	{
		MSG msg;
		while (GetMessage(&msg, NULL, 0, 0))  //获取消息
		{
			TranslateMessage(&msg);    //将虚拟键消息转换为字符消息。字符消息被发送到调用线程的消息队列，在下一次线程调用GetMessage或PeekMessage函数时读取
			DispatchMessage(&msg);     //将消息分派给窗口过程。它通常用于分派由GetMessage函数检索的消息。
		}
	}
#endif



// 
// 	// Delete the shell manager created above.
// 	if (pShellManager != NULL)
// 	{
// 		delete pShellManager;
// 	}

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}



int CwjsApp::ExitInstance()
{
	// TODO: Add your specialized code here and/or call the base class
	if (g_hMod)
	{
		EjectDll(dwId, g_hMod);
	}
	return CWinApp::ExitInstance();
}
