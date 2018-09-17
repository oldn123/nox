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
			//�����Ҫע�����Ľ��̵ľ��
			hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessID);
			if (hProcess == NULL)
				break;

			HMODULE hKern = GetModuleHandle(TEXT("Kernel32"));

			//���LoadLibraryA��Kernel32.dll�е�������ַ
			pfnThreadRoutine = (PTHREAD_START_ROUTINE)::GetProcAddress(hKern , "FreeLibrary");
			if (pfnThreadRoutine == NULL)
				break;
	
			//����Զ���̣߳���ͨ��Զ���̵߳����û���DLL�ļ�
			hThread = ::CreateRemoteThread(hProcess, NULL, 0, pfnThreadRoutine, (LPVOID)hModule, 0, NULL);
			if (hThread == NULL)
				break;

			//�ȴ�Զ���߳���ֹ
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