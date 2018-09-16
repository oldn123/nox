//Originally coded by Polpop, you are authorized to modify and distribute this file as long you keep this line of credit.
#ifndef _DLLHACK_H
#define _DLLHACK_H
#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <functional>
#include <tchar.h>
#include <cassert>
#include "propertymacro.h"

#ifndef _TSTRING
#define _TSTRING
using _tstring = std::basic_string<TCHAR, std::char_traits<TCHAR>, std::allocator<TCHAR>>;
#endif

void ErasePE(DWORD GetModuleBase)
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleBase;
	PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + (DWORD)pDosHeader->e_lfanew);

	if (pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		return;

	if (pNTHeader->FileHeader.SizeOfOptionalHeader)
	{
		DWORD oldProtect;
		WORD Size = pNTHeader->FileHeader.SizeOfOptionalHeader;
		VirtualProtect((void*)GetModuleBase, Size, PAGE_EXECUTE_READWRITE, &oldProtect);
		RtlZeroMemory((void*)GetModuleBase, Size);
		VirtualProtect((void*)GetModuleBase, Size, oldProtect, &oldProtect);
	}
}

DWORD* AOBScan(const _tstring& module, const _tstring& pattern, const _tstring& mask, DWORD fix = 0, size_t patternNumber = 1)
{
	MODULEINFO modinfo = { 0 };
	HMODULE hmodule = GetModuleHandle(module.c_str());
	if (!hmodule)
		return 0;
	GetModuleInformation(GetCurrentProcess(), hmodule, &modinfo, sizeof(MODULEINFO));

	DWORD patternlenght = DWORD(mask.length());
	DWORD base = (DWORD)modinfo.lpBaseOfDll;
	DWORD end = base + (DWORD)modinfo.SizeOfImage - patternlenght;

	bool found = false;
	size_t g = 1;

	for (DWORD i = base; i < end; i++)
	{
		for (DWORD j = 0; j < patternlenght; j++)
		{
			if (*(char*)(i + j) == pattern[j] || mask[j] == '?')
				found = true;
			else
				found = false;

			if (!found)
			{
				i += j;
				break;
			}
		}
		if (found)
		{
			if (g == patternNumber)
				return (DWORD*)(i + fix);
			else
			{
				g++;
				i += patternlenght;
			}
		}
	}
	return nullptr;
}

void DejectDll(std::function<bool(MODULEENTRY32)> cmp)
{
	MODULEENTRY32 current = { 0 };
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
	if (Module32First(handle, &current))
	{
		do
		{
			if (cmp(current))
			{
				CloseHandle(handle);
				FreeLibraryAndExitThread(LoadLibrary(current.szModule), 0);
				return;
			}
		} while (Module32Next(handle, &current));
	}
	CloseHandle(handle);
}

class Detour
{
	void* const originalFunction;
	const void* const customFunction;
	const size_t lenght;

	const BYTE* const m_disable;
	const BYTE* const oBytes;
	BYTE jmpBytes[5];

	bool enabled = false;

	BYTE* AllocDisableBytes() const
	{
		auto buffer = new BYTE[lenght];
		memcpy(buffer, originalFunction, lenght);
		return buffer;
	}

	BYTE* AllocOBytes() const
	{
		auto buffer = new BYTE[lenght + 5u];
		memcpy(buffer, originalFunction, lenght);
		buffer[lenght] = 0xE9;
		*(DWORD*)(&jmpBytes[lenght + 1]) = (DWORD)customFunction - (DWORD)originalFunction - 5;
		return buffer;
	}

	~Detour()
	{
		Disable();
		delete[] m_disable;
		delete[] oBytes;
	}

public:
	const DWORD jump;
	const DWORD jumpO;

	Detour(void* originalFunction, const void* customFunction, size_t lenght = 5u) :
	originalFunction(originalFunction), customFunction(customFunction), lenght(lenght),
	m_disable(AllocDisableBytes()), oBytes(AllocOBytes()),
	jump((DWORD)originalFunction + lenght), jumpO((DWORD)oBytes)
	{
		assert(lenght >= 5u);
		jmpBytes[0] = 0xE9;
		*(DWORD*)(&jmpBytes[1]) = (DWORD)customFunction - (DWORD)originalFunction - 5;
	}

	Detour(const Detour& a) : Detour(a.originalFunction, a.customFunction, a.lenght)
	{
		
	}

	void Release() const
	{
		delete this;
	}

	void Enable()
	{
		if (!originalFunction || enabled)
			return;
		DWORD oldProtect;
		VirtualProtect(originalFunction, lenght, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy(originalFunction, jmpBytes, 5);
		VirtualProtect(originalFunction, lenght, oldProtect, 0);
		enabled = true;
	}

	void Disable()
	{
		if (!originalFunction || !enabled)
			return;
		DWORD oldProtect;
		VirtualProtect(originalFunction, lenght, PAGE_EXECUTE_READWRITE, &oldProtect);
		memcpy(originalFunction, m_disable, lenght);
		VirtualProtect(originalFunction, lenght, oldProtect, 0);
		enabled = false;
	}
	//return the active state of the script.
	bool GetEnabled() const { return enabled; }
	void SetEnabled(bool value) { value ? Enable() : Disable(); }
	Property(bool, Enabled);

};

template<typename T>
void VmtHook(const void* lpClass, size_t index, const void* hkFunction, T& OriginalFunction)
{
	auto vtable = *(LPVOID**)lpClass;
	if (vtable[index] == hkFunction)
		return;
	OriginalFunction = (T)vtable[index];
	DWORD oldProtect;
	VirtualProtect(&vtable[index], 4, PAGE_EXECUTE_READWRITE, &oldProtect);
	vtable[index] = (LPVOID)hkFunction;
	VirtualProtect(&vtable[index], 4, oldProtect, 0);
}

template<typename T>
void VmtUnHook(const void* lpClass, size_t index, T OriginalFunction)
{
	auto vtable = *(LPVOID**)lpClass;
	if (vtable[index] == (LPVOID)OriginalFunction)
		return;
	DWORD oldProtect;
	VirtualProtect(&vtable[index], 4, PAGE_EXECUTE_READWRITE, &oldProtect);
	vtable[index] = (LPVOID)OriginalFunction;
	VirtualProtect(&vtable[index], 4, oldProtect, 0);
}

template<typename T>
T VmtGetFunction(void* lpClass, size_t index)
{
	DWORD* vtable = *(DWORD**)lpClass;
	return (T)vtable[index];
}

class CVMTHook
{
public:
	template<typename T>
	void Hook(size_t index, const void* hkFunction, T& OriginalFunction) const
	{
		VmtHook(this, index, hkFunction, OriginalFunction);
	}

	template<typename T>
	void UnHook(size_t index, T OriginalFunction) const
	{
		VmtUnHook(this, index, OriginalFunction);
	}

};

#endif