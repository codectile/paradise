#pragma once
#include "paradise.h"

#ifdef WIN32
class X32Hook
{
public:
	X32Hook();
	~X32Hook();
	void SetupHook(void* pSource, void* pFunc);
	void* InstallHook();
	void* Trampoline();
	void FreeTrampline();
	int GetJMPSize();
	void RemoveHook();
private:
	unsigned long m_size;
	BYTE m_obytes[MAX_BYTES];
	BYTE* m_memloc;
	void* func_address;
	void* func_hook;
	bool m_isdetoured;
};
#else
// TODO: add x64 support
class X64Hook
{
public:
	X64Hook();
	~X64Hook();
};
#endif // WIN64
