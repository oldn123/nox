#include <Windows.h>
#include ".\header\dllinject.h"

extern "C"
{
	HMODULE __declspec(dllexport) __stdcall InjectDll(int processId, const char* DllPath, InjectionMethod injectionMethod, StartMethod startMethod)
	{
		HANDLE hToken;
		if (OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
		{
			TOKEN_PRIVILEGES tp;
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			tp.Privileges[0].Luid.LowPart = 20;
			tp.Privileges[0].Luid.HighPart = 0;

			AdjustTokenPrivileges(hToken, 0, &tp, 0, 0, 0);
			CloseHandle(hToken);
		}

		HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
		if (!hProc)
			return NULL;

		auto result = DllInject::InjectDll(hProc, DllPath, injectionMethod, startMethod);
		return CloseHandle(hProc), result;
	}

	BOOL __declspec(dllexport) __stdcall EjectDll(DWORD dwProcessID, HMODULE hModule)
	{
		BOOL bRetCode = FALSE;
		HANDLE hProcess = NULL;
		HANDLE hThread = NULL;

		PTHREAD_START_ROUTINE pfnThreadRoutine;

		do
		{
			//获得想要注入代码的进程的句柄
			hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
			if (hProcess == NULL)
				break;

			HMODULE hKern = GetModuleHandle(TEXT("Kernel32"));

			//获得LoadLibraryA在Kernel32.dll中的真正地址
			pfnThreadRoutine = (PTHREAD_START_ROUTINE)::GetProcAddress(hKern , "FreeLibrary");
			if (pfnThreadRoutine == NULL)
				break;
	
			//创建远程线程，并通过远程线程调用用户的DLL文件
			hThread = ::CreateRemoteThread(hProcess, NULL, 0, pfnThreadRoutine, (LPVOID)hModule, 0, NULL);
			if (hThread == NULL)
				break;

			//等待远程线程终止
			::WaitForSingleObject(hThread, INFINITE);
		}while(FALSE);

		if (hThread != NULL)
		{
			DWORD dwExitCode;
			::GetExitCodeThread(hThread, &dwExitCode);
			bRetCode = (BOOL)dwExitCode;
			::CloseHandle(hThread);
		}
		if (hProcess != NULL)
		{
			::CloseHandle(hProcess);
		}
		return bRetCode;
	}

}