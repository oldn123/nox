#ifndef _DLLINJECT_H
#define _DLLINJECT_H
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <tchar.h>
#include <fstream>
#include "..\dllinjector.h"

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib, "Advapi32.lib")

#ifdef _WIN64
#define IMAGE_FILE_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define IMAGE_FILE_MACHINE IMAGE_FILE_MACHINE_I386
#endif

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

typedef std::basic_string<TCHAR> inject_string;

typedef HMODULE (WINAPI *LoadLibraryA_t)(LPCSTR);

typedef FARPROC (WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);

typedef BOOL (WINAPI *DllMain_t)(HMODULE, DWORD, LPVOID);

typedef struct _MANUAL_INJECT
{
	LPVOID ImageBase;
	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
	LoadLibraryA_t loadLibraryA;
	GetProcAddress_t getProcAddress;
}MANUAL_INJECT, *PMANUAL_INJECT, *LPMANUAL_INJECT;

inline BOOL WINAPI ManualMapInternalLoadDll(LPMANUAL_INJECT ManualInject)
{
	auto pBase = (BYTE*)ManualInject->ImageBase;
	auto optionalHeader = ManualInject->NtHeaders->OptionalHeader;
	auto delta = (DWORD)(pBase - optionalHeader.ImageBase);
	
	auto baseRelocation = ManualInject->BaseRelocation;
	while (baseRelocation->VirtualAddress)
	{
		if (baseRelocation->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			DWORD count = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			auto list = (PWORD)(baseRelocation + 1);
			for (DWORD i = 0; i < count; i++)
			{
				if (list[i])
				{
					auto ptr = (PDWORD)(pBase + (baseRelocation->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}
		baseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)baseRelocation + baseRelocation->SizeOfBlock);
	}

	auto importDescriptor = ManualInject->ImportDirectory;
	while (importDescriptor->Characteristics)
	{
		auto origFirstThunk = (PIMAGE_THUNK_DATA)(pBase + importDescriptor->OriginalFirstThunk);
		auto firstThunk = (PIMAGE_THUNK_DATA)(pBase + importDescriptor->FirstThunk);

		auto hModule = ManualInject->loadLibraryA((LPCSTR)pBase + importDescriptor->Name);
		if (!hModule)
			return FALSE;

		while (origFirstThunk->u1.AddressOfData)
		{
			char * name = NULL;
			if(origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) 
			{
				name = (char*)(origFirstThunk->u1.Ordinal & 0xFFFF);
			}
			else
			{
				name = (char*)((PIMAGE_IMPORT_BY_NAME)(pBase + origFirstThunk->u1.AddressOfData))->Name;
			}
			auto Function = (DWORD)ManualInject->getProcAddress(hModule, name);
			if (!Function)
				return FALSE;
			firstThunk->u1.Function = Function;
			origFirstThunk++;
			firstThunk++;
		}
		importDescriptor++;
	}

	auto dataDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (dataDirectory.Size)
	{
		auto tls = (PIMAGE_TLS_DIRECTORY)(pBase + dataDirectory.VirtualAddress);
		auto callback = (PIMAGE_TLS_CALLBACK*)(tls->AddressOfCallBacks);
		while (callback && *callback)
		{
			(*callback)(pBase, DLL_PROCESS_ATTACH, nullptr);
			callback++;
		}
	}

	if (optionalHeader.AddressOfEntryPoint)
	{
		auto dllMain = (DllMain_t)(pBase + optionalHeader.AddressOfEntryPoint);
		return dllMain((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}

namespace DllInject
{
	inline HMODULE HijackThread(HANDLE hProc, LPVOID fn, LPVOID arg)
	{
		HMODULE hRet = NULL;
		BOOLEAN bl;
		RtlAdjustPrivilege(20, 1, 0, &bl);

		DWORD ProcessId = GetProcessId(hProc);

		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (!hSnap)
			return NULL;
		THREADENTRY32 te32;
		te32.dwSize = sizeof(THREADENTRY32);
		if (!Thread32First(hSnap, &te32))
			return NULL;
		do
		{
			if (te32.th32OwnerProcessID == ProcessId && te32.th32ThreadID != GetCurrentThreadId())
				break;
		} while (Thread32Next(hSnap, &te32));
		CloseHandle(hSnap);

		HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, 0, te32.th32ThreadID);
		if (!hThread)
			return NULL;
		if (SuspendThread(hThread) == (DWORD)-1)
		{
			CloseHandle(hThread);
			return NULL;
		}

		BOOL b32 = TRUE;
		if (!IsWow64Process(hProc, &b32))	//判断目标进程是否为32位
		{
			CloseHandle(hThread);
			return NULL;
		}
		
		if (b32)
		{

		}
		else
		{

		}

		CONTEXT ctx;
		memset(&ctx, 0, 716u);
		ctx.ContextFlags = CONTEXT_CONTROL;
		if (!GetThreadContext(hThread, &ctx))
		{
			ResumeThread(hThread);
			CloseHandle(hThread);
			return NULL;
		}

		LPVOID shellCodeAddress = VirtualAllocEx(hProc, 0, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!shellCodeAddress)
		{
			ResumeThread(hThread);
			CloseHandle(hThread);
			return NULL;
		}

#ifdef _WIN64

		BYTE Shellcode[] =
		{
			0x48, 0x83, 0xEC, 0x08,												// + 0x00			-> sub rsp, 0x08

			0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,							// + 0x04 (+ 0x07)	-> mov [rsp], RipLowPart
			0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,						// + 0x0B (+ 0x0F)	-> mov [rsp + 04], RipHighPart		

			0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,	// + 0x13			-> push r(acd)x / r(8-11)
			0x9C,																// + 0x1E			-> pushfq

			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			// + 0x1F (+ 0x21)	-> mov rax, pFunc
			0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,			// + 0x29 (+ 0x2B)	-> mov rcx, pArg

			0x48, 0x83, 0xEC, 0x20,												// + 0x33			-> sub rsp, 0x20
			0xFF, 0xD0,															// + 0x37			-> call rax
			0x48, 0x83, 0xC4, 0x20,												// + 0x39			-> add rsp, 0x20

			0x9D,																// + 0x3D			-> popfq
			0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,	// + 0x3E			-> pop r(11-8) / r(dca)x

			0xC6, 0x05, 0xB0, 0xFF, 0xFF, 0xFF, 0x00,							// + 0x49			-> mov byte ptr[$ - 0x49], 0

			0xC3																// + 0x50			-> ret
		}; // SIZE = 0x51

		DWORD dwLoRIP = (DWORD)(ctx.Rip & 0xFFFFFFFF);
		DWORD dwHiRIP = (DWORD)((ctx.Rip >> 0x20) & 0xFFFFFFFF);

		*(DWORD*)(Shellcode + 0x07) = dwLoRIP;
		*(DWORD*)(Shellcode + 0x0F) = dwHiRIP;
		*(void**)(Shellcode + 0x21) = fn;
		*(void**)(Shellcode + 0x2B) = arg;

		ctx.Rip = (DWORD64)shellCodeAddress;

#else

		BYTE Shellcode[] =
		{
			0x83, 0xEC, 0x04,							// + 0x00				-> sub esp, 0x04
			0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,	// + 0x03 (+ 0x06)		-> mov [esp], OldEip

			0x9C,										// + 0x0A				-> pushfd
			0x60,										// + 0x0B				-> pushad

			0xB9, 0x00, 0x00, 0x00, 0x00,				// + 0x0C (+ 0x0D)		-> mov ecx, pArg
			0xB8, 0x00, 0x00, 0x00, 0x00,				// + 0x11 (+ 0x12)		-> mov eax, pFunc

			0x51,										// + 0x16 (__stdcall)	-> push ecx	(default)
														// + 0x16 (__fastcall)	-> nop (0x90)
			0xFF, 0xD0,									// + 0x17				-> call eax

			0xA3, 0x00, 0x00, 0x00, 0x00,				// + 0x19 (+ 0x1A)		-> mov dword ptr[pCodecave], eax

			0x61,										// + 0x1E				-> popad
			0x9D,										// + 0x1F				-> popfd

			//0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,	// + 0x1B (+ 0x1D)		-> mov byte ptr[pCodecave], 0

			0xC3										// + 0x20				-> ret
		}; // SIZE = 0x23

		Shellcode[0x16] = 0x51;

		*(DWORD*)(Shellcode + 0x06) = ctx.Eip;
		*(void**)(Shellcode + 0x0D) = arg;
		*(void**)(Shellcode + 0x12) = fn;
		*(void**)(Shellcode + 0x1A) = shellCodeAddress;

		ctx.Eip = (DWORD)(shellCodeAddress);
#endif
		DWORD dwCheckByteSrc = *(LPDWORD)&Shellcode[0];

		if (!WriteProcessMemory(hProc, shellCodeAddress, Shellcode, sizeof(Shellcode), 0))
		{
			VirtualFreeEx(hProc, shellCodeAddress, 0, MEM_RELEASE);
			ResumeThread(hThread);
			CloseHandle(hThread);
			return NULL;
		}

		if (!SetThreadContext(hThread, &ctx))
		{
			VirtualFreeEx(hProc, shellCodeAddress, 0, MEM_RELEASE);

			ResumeThread(hThread);
			CloseHandle(hThread);
			return NULL;
		}

		if (ResumeThread(hThread) == (DWORD)-1)
		{
			VirtualFreeEx(hProc, shellCodeAddress, 0, MEM_RELEASE);
			CloseHandle(hThread);
			return NULL;
		}

		DWORD dwCheckByte = dwCheckByteSrc;
		while (true)
		{
			dwCheckByte = 0;
			if(ReadProcessMemory(hProc, shellCodeAddress, &dwCheckByte, sizeof(int), nullptr))
			{
				if (dwCheckByteSrc != dwCheckByte)
				{
					hRet = (HMODULE)dwCheckByte;
					break;
				}
			}
			Sleep(100);
		}

		VirtualFreeEx(hProc, shellCodeAddress, 0, MEM_RELEASE);
		CloseHandle(hThread);

		return hRet;
	}

	inline HMODULE CreateThreadEx(HANDLE hProc, LPVOID fn, LPVOID arg)
	{
		HMODULE hModRet = NULL;
		HANDLE hThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)fn, arg, 0, 0);
		if (!hThread)
			return NULL;
		WaitForSingleObject(hThread, INFINITE);
		DWORD ExitCode;
		do
		{
			GetExitCodeThread(hThread, &ExitCode);
			Sleep(1);
		} while (ExitCode == STILL_ACTIVE);
		CloseHandle(hThread);
		hModRet = (HMODULE)ExitCode;
		return hModRet;
	}

	inline HMODULE NtCreateThreadEx(HANDLE hProc, LPVOID fn, LPVOID arg)
	{
		struct NtCreateThreadExBuffer
		{
			ULONG Size;
			ULONG Unknown1;
			ULONG Unknown2;
			PULONG Unknown3;
			ULONG Unknown4;
			ULONG Unknown5;
			ULONG Unknown6;
			PULONG Unknown7;
			ULONG Unknown8;
		};

		typedef NTSTATUS (WINAPI *NtCreateThreadEx_t)(
			PHANDLE hThread,
			ACCESS_MASK DesiredAccess,
			LPVOID ObjectAttributes,
			HANDLE ProcessHandle,
			LPTHREAD_START_ROUTINE lpStartAddress,
			LPVOID lpParameter,
			BOOL CreateSuspended,
			ULONG StackZeroBits,
			ULONG SizeOfStackCommit,
			ULONG SizeOfStackReserve,
			LPVOID lpBytesBuffer);

		HMODULE hRet = NULL;
		auto ntCreateThreadEx = (NtCreateThreadEx_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
		DWORD temp1 = 0;
		DWORD temp2 = 0;
		NtCreateThreadExBuffer buffer = { 0 };
		buffer.Size = sizeof(NtCreateThreadExBuffer);
		buffer.Unknown1 = 0x10003;
		buffer.Unknown2 = 0x8;
		buffer.Unknown3 = &temp2;
		buffer.Unknown4 = 0;
		buffer.Unknown5 = 0x10004;
		buffer.Unknown6 = 4;
		buffer.Unknown7 = &temp1;
		buffer.Unknown8 = 0;
		
		HANDLE hThread;
		ntCreateThreadEx(&hThread, 0x1FFFFF, 0, hProc, (LPTHREAD_START_ROUTINE)fn, arg, FALSE, 0, 0, 0, &buffer);
		if (!hThread)
			return NULL;
		WaitForSingleObject(hThread, INFINITE);
		DWORD ExitCode;
		do
		{
			GetExitCodeThread(hThread, &ExitCode);
			Sleep(1);
		} while (ExitCode == STILL_ACTIVE);
		CloseHandle(hThread);
		return hRet;
	}

	inline HMODULE StartRoutline(HANDLE hProc, LPVOID fn, LPVOID arg, StartMethod startMethod)
	{
		switch (startMethod)
		{
		case StartMethod::CreateThreadEx:
			return CreateThreadEx(hProc, fn, arg);
		case StartMethod::ThreadHijacking:
			return HijackThread(hProc, fn, arg);
		}
		return NULL;
	}

	//Standard Injection.
	inline HMODULE LoadLib(HANDLE hproc, const inject_string& dllpath, StartMethod startMethod)
	{
		LPVOID remoteString = VirtualAllocEx(hproc, 0, _MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!remoteString)
			return NULL;
		if (!WriteProcessMemory(hproc, remoteString, dllpath.c_str(), dllpath.size() + 1, 0))
		{
			VirtualFreeEx(hproc, remoteString, _MAX_PATH, MEM_RELEASE);
			return NULL;
		}
		auto result = StartRoutline(hproc, GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), remoteString, startMethod);
		VirtualFreeEx(hproc, remoteString, _MAX_PATH, MEM_RELEASE);
		return result;
	}

	//ManualMap Injection. Only work on release version
	inline HMODULE ManualMap(HANDLE hproc, const inject_string& dllPath, StartMethod startMethod)
	{
		HMODULE hRet = NULL;
		if (GetFileAttributes(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES)
			return hRet;

		std::ifstream file(dllPath, std::ios::binary | std::ios::ate);

		if (file.fail())
			return hRet;

		auto fileSize = file.tellg();
		if (fileSize < 0x1000)
		{
			file.close();
			return hRet;
		}

		auto buffer = new BYTE[static_cast<size_t>(fileSize)];
		if (!buffer)
		{
			file.close();
			return hRet;
		}

		file.seekg(0, std::ios::beg);

		file.read((char*)buffer, fileSize);
		file.close();

		auto pIDH = (PIMAGE_DOS_HEADER)buffer;
		if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
		{
			delete[] buffer;
			return hRet;
		}

		auto lpOldNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);
		if (lpOldNtHeader->Signature != IMAGE_NT_SIGNATURE || !(lpOldNtHeader->FileHeader.Characteristics & IMAGE_FILE_DLL))
		{
			delete[] buffer;
			return hRet;
		}
		auto lpFileHeader = &lpOldNtHeader->FileHeader;
		auto lpOptHeader = &lpOldNtHeader->OptionalHeader;

		if (lpFileHeader->Machine != IMAGE_FILE_MACHINE)
		{
			delete[] buffer;
			return hRet;
		}

		auto lpTargetBase = (BYTE*)VirtualAllocEx(hproc, (LPVOID)lpOptHeader->ImageBase, lpOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!lpTargetBase)
		{
			lpTargetBase = (BYTE*)VirtualAllocEx(hproc, nullptr, lpOldNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if(!lpTargetBase)
			{
				delete[] buffer;
				return hRet;
			}
		}

		MANUAL_INJECT data;
		data.loadLibraryA = LoadLibraryA;
		data.getProcAddress = GetProcAddress;

		auto lpSectionHeader = IMAGE_FIRST_SECTION(lpOldNtHeader);

		for (UINT i = 0; i < lpFileHeader->NumberOfSections; i++, lpSectionHeader++)
		{
			if (lpSectionHeader->SizeOfRawData)
			{
				if (!WriteProcessMemory(hproc, lpTargetBase + lpSectionHeader->VirtualAddress, buffer + lpSectionHeader->PointerToRawData, lpSectionHeader->SizeOfRawData, nullptr))
				{
					delete[] buffer;
					VirtualFreeEx(hproc, lpTargetBase, lpOptHeader->SizeOfImage, MEM_RELEASE);
					return hRet;
				}
			}
		}


		// Copy the header to target process
		if (!WriteProcessMemory(hproc, lpTargetBase, buffer, lpOldNtHeader->OptionalHeader.SizeOfHeaders, 0))
		{
			VirtualFreeEx(hproc, lpTargetBase, 0, MEM_RELEASE);
			delete[] buffer;
			VirtualFree(buffer, 0, MEM_RELEASE);
			return hRet;
		}

		PIMAGE_SECTION_HEADER pISH = (PIMAGE_SECTION_HEADER)(lpOldNtHeader + 1);

		// Copy the DLL to target process
		for (WORD i = 0; i < lpOldNtHeader->FileHeader.NumberOfSections; i++)
			WriteProcessMemory(hproc, (LPVOID)((LPBYTE)lpTargetBase + pISH[i].VirtualAddress), (LPVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, 0);

		LPVOID loaderArgument = VirtualAllocEx(hproc, 0, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code
		if (!loaderArgument)
		{
			VirtualFreeEx(hproc, lpTargetBase, 0, MEM_RELEASE);
			delete[] buffer;
			return hRet;
		}

		MANUAL_INJECT manualInject = { 0 };
		manualInject.ImageBase = lpTargetBase;
		manualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)lpTargetBase + pIDH->e_lfanew);
		manualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)lpTargetBase + lpOldNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		manualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)lpTargetBase + lpOldNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		manualInject.loadLibraryA = LoadLibraryA;
		manualInject.getProcAddress = GetProcAddress;

		WriteProcessMemory(hproc, loaderArgument, &manualInject, sizeof(MANUAL_INJECT), 0); // Write the loader information to target process

		LPVOID loaderFunction = (LPVOID)((DWORD)loaderArgument + sizeof(MANUAL_INJECT));
		WriteProcessMemory(hproc, loaderFunction, ManualMapInternalLoadDll, 0x1000 - sizeof(MANUAL_INJECT), 0); // Write the loader code to target process

		hRet = StartRoutline(hproc, loaderFunction, loaderArgument, startMethod);

		delete[] buffer;
		VirtualFreeEx(hproc, loaderArgument, 0x1000, MEM_RELEASE);
		return hRet;
	}

	inline HMODULE InjectDll(HANDLE hProc, const inject_string& dllpath, InjectionMethod injectionMethod, StartMethod startMethod)
	{
		switch (injectionMethod)
		{
		case InjectionMethod::LoadLib:
			return LoadLib(hProc, dllpath, startMethod);
		case  InjectionMethod::ManualMap:
			return ManualMap(hProc, dllpath, startMethod);
		}
		return FALSE;
	}

}

#endif //Include Guard