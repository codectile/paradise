#pragma once
#include "paradise.h"

// x32 hooking class
class X32Hook
{
public:
	X32Hook();
	~X32Hook();
	void SetupHook(void* pSource, void* pFunc);
	void* InstallHook();
	void* Trampoline();
	void FreeTrampoline();
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

// x64 hooking class
// thanks to DarthTon for providing clear concept on x64 hooking
class X64Hook
{
public:
	X64Hook();
	~X64Hook();
	void SetupHook(void* pSource, void* pFunc);
	void* InstallHook();
	void* Trampoline();
	void FreeTrampoline();
	int GetJMPSize();
	void RemoveHook();
private:
	unsigned long m_size;
	BYTE m_obytes[MAX_BYTES];
	void* func_address;
	void* func_hook;
	struct Context
	{
		BYTE m_detrbytes[64];
		SIZE_T dst_ptr;
	} *pContext;
	bool m_isdetoured;
};
