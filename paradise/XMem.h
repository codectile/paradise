#pragma once

#include "paradise.h"

namespace XMem
{
	enum calling_convention
	{
		cdeclcall,
		stdcall,
		thiscall,
		fastcall
	};

	inline BOOL UnProtect(void* memaddr, int length, DWORD &dwOldProtect)
	{
		return VirtualProtect(memaddr, length, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	}

	inline BOOL Protect(void* memaddr, int length, DWORD dwOldProtect)
	{
		return VirtualProtect(memaddr, length, dwOldProtect, NULL);
	}

	template<typename T1, typename T2> inline void Write(T1 memaddr, T2 bytes, int length)
	{
		memcpy((void*)memaddr, (void*)bytes, length);
	}

	template<typename T1, typename T2> inline void WriteSingle(T1 memaddr, T2 value)
	{
		*(T2*)memaddr = value;
	}

	template<typename T1, typename T2> inline void Read(T1 memaddr, T2 dest, int length)
	{
		memcpy((LPVOID)dest, (LPVOID)memaddr, length);
	}

	template<typename R, typename T> inline R ReadSingle(T memaddr)
	{
		return *(R*)(memaddr);
	}

	template<typename T> inline void PatchJump(void* dest, void* func)
	{
		*(BYTE*)dest = 0xE9;
		*(T*)((BYTE*)dest + 1) = (T)func - ((T)dest + 5);
	}

	template<typename T> inline void PatchCall(void* dest, void* func)
	{
		*(BYTE*)dest = 0xE8;
		*(T*)((BYTE*)dest + 1) = (T)func - ((T)dest + 5);
	}

	template<typename T> inline void PatchNOP(T source, int length)
	{
		memset((LPVOID)source, 0x90, length);
	}

	template<typename R> inline R GetBase()
	{
		return (R)GetModuleHandle(NULL);
	}

	static bool compare_bytes(BYTE* data, BYTE* pattern, char* mask)
	{
		for (; *mask; ++mask, ++data, ++pattern)
		{
			if (*mask == 'x' && *data != *pattern)
				return false;
		}
		return (*mask == 0);
	};

	template<typename T, typename R> R ScanMemory(char* pattern, char* mask)
	{
		T address = GetBase<T>();
		MODULEINFO info = { NULL };
		GetModuleInformation(GetCurrentProcess(), (HMODULE)address, &info, sizeof(MODULEINFO));

		for (T i = 0; i < (T)info.SizeOfImage; i++)
		{
			if (compare_bytes((BYTE*)(address + i), (BYTE*)pattern, mask))
				return (R)(address + i);
		}
		return NULL;
	}

	template<typename T> static void* AllocPageWithin2GB(T pSource)
	{
		MEMORY_BASIC_INFORMATION mbi;
		for (size_t addr = (size_t)pSource; addr > (size_t)pSource - 0x80000000; addr = (size_t)mbi.BaseAddress - 1)
		{
			if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)))
				return NULL;

			if (mbi.State == MEM_FREE)
				return VirtualAlloc(mbi.BaseAddress, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE); // allocate a page of 4 kilobytes
		}
		return NULL;
	}

	static int length_disassemble(void* pSource, int size, cs_mode mode)
	{
		DWORD prot;
		XMem::UnProtect(pSource, size, prot);

		csh handle;
		cs_insn* insn;

		size_t count;

		int jmp_size = mode == CS_MODE_32 ? 5 : 6;;
		if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK)
			return NULL;
		count = cs_disasm(handle, (BYTE*)pSource, size, (size_t)pSource, 0, &insn);
		if (count <= 0)
			return NULL;
		int length = 0;
		int num_insn = count;
		int i = 0;
		while (count-- && length < jmp_size)
			length += insn[i++].size;
		cs_free(insn, num_insn);
		cs_close(&handle);
		XMem::Protect(pSource, size, prot);
		return (length >= jmp_size ? length : NULL);
	}

	template<typename R, typename T, typename... Args> inline R Call(calling_convention convention, T address, Args... args)
	{
		if(convention == calling_convention::stdcall)
			return (reinterpret_cast<R(__stdcall *)(Args...)>(address))(args...);
		else if(convention == calling_convention::thiscall)
			return (reinterpret_cast<R(__thiscall *)(Args...)>(address))(args...);
		else if (convention == calling_convention::fastcall)
			return (reinterpret_cast<R(__fastcall *)(Args...)>(address))(args...);
		return (reinterpret_cast<R(__cdecl *)(Args...)>(address))(args...);
	}

}
