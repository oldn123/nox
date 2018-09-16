#include <Windows.h>
#include ".\header\dllinject.h"

extern "C"
{
	BOOL __declspec(dllexport) __stdcall InjectDll(int processId, const char* DllPath, InjectionMethod injectionMethod, StartMethod startMethod)
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
			return FALSE;

		auto result = DllInject::InjectDll(hProc, DllPath, injectionMethod, startMethod);
		return CloseHandle(hProc), result;
	}
}