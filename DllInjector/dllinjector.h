#pragma once

enum StartMethod 
{
	CreateThreadEx,
	ThreadHijacking,
	ntCreateThreadEx,
};

enum InjectionMethod 
{
	LoadLib,
	ManualMap,
};

extern "C"
{
	HMODULE __declspec(dllexport) __stdcall InjectDll(int processId, const char* DllPath, InjectionMethod injectionMethod, StartMethod startMethod);

	BOOL __declspec(dllexport) __stdcall EjectDll(DWORD dwProcessID, HMODULE hModule);
}