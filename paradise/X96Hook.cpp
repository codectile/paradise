#include "X96Hook.h"
#include "XMem.h"
#include "XLog.h"

// 32-bit hooking functions
X32Hook::X32Hook()
{
	func_address = NULL;
	func_hook = NULL;
	m_memloc = NULL;
	m_size = NULL;
	m_isdetoured = false;
	XMem::PatchNOP(m_obytes, sizeof(m_obytes));
}

X32Hook::~X32Hook()
{
	RemoveHook();
	func_address = NULL;
	func_hook = NULL;
	m_size = NULL;
}

void X32Hook::SetupHook(void* pSource, void* pFunc)
{
	func_address = pSource;
	func_hook = pFunc;
}

void* X32Hook::InstallHook()
{
	if (m_isdetoured)
		return NULL;
	int length = XMem::length_disassemble(func_address, MAX_BYTES, CS_MODE_32);
	if (!length)
		return NULL;
	DWORD prot;
	m_size = length;
	XMem::UnProtect(func_address, length, prot);
	memcpy(m_obytes, func_address, length);
	m_memloc = (BYTE*)malloc(length + 5);
	memcpy(m_memloc, func_address, length);
	m_memloc += length;
	*m_memloc = 0xE9;
	*(DWORD*)(m_memloc + 1) = (DWORD)((DWORD)func_address + length - (DWORD)m_memloc) - 5;
	XMem::PatchNOP(func_address, length);
	XMem::PatchJump<DWORD>(func_address, func_hook);
	XMem::Protect(func_address, length, prot);
	m_isdetoured = true;
	return (void*)(m_memloc - length);
}

void* X32Hook::Trampoline()
{
	return m_isdetoured ? m_memloc : NULL;
}

void X32Hook::FreeTrampoline()
{
	if (m_isdetoured && m_memloc)
	{
		free(m_memloc);
		m_memloc = NULL;
	}
}

int X32Hook::GetJMPSize()
{
	return m_isdetoured ? m_size : -1;
}

void X32Hook::RemoveHook()
{
	if (!m_isdetoured)
		return;
	DWORD prot;
	XMem::UnProtect(func_address, m_size, prot);
	memcpy(func_address, m_obytes, m_size);
	XMem::Protect(func_address, m_size, prot);
	if(m_memloc)
		free(m_memloc);
	m_isdetoured = false;
	m_memloc = NULL;
	XMem::PatchNOP(m_obytes, sizeof(m_obytes));
}

// x64-bit hooking functions
X64Hook::X64Hook()
{
	func_address = NULL;
	func_hook = NULL;
	pContext = NULL;
	m_size = NULL;
	m_isdetoured = false;
	XMem::PatchNOP(m_obytes, sizeof(m_obytes));
}

X64Hook::~X64Hook()
{
	RemoveHook();
	func_address = NULL;
	func_hook = NULL;
	pContext = NULL;
	m_size = NULL;
}

void X64Hook::SetupHook(void* pSource, void* pFunc)
{
	func_address = pSource;
	func_hook = pFunc;
}

void* X64Hook::InstallHook()
{
	if (m_isdetoured)
		return NULL;
	int length = XMem::length_disassemble(func_address, MAX_BYTES, CS_MODE_64);
	if (!length)
		return NULL;
	pContext = (X64Hook::Context*)XMem::AllocPageWithin2GB(func_address);
	if (!pContext)
		return NULL;
	BYTE detour[] = { 0x50, 0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0x87, 0x04, 0x24, 0xC3 };

	DWORD prot;
	m_size = length;
	XMem::UnProtect(func_address, length, prot);
	memcpy(m_obytes, func_address, length);
	XMem::Write(pContext->m_detrbytes, func_address, length);
	XMem::Write(&pContext->m_detrbytes[length], detour, sizeof(detour));
	XMem::WriteSingle<BYTE*, SIZE_T>(&pContext->m_detrbytes[length + 3], (SIZE_T)func_address + length);
	XMem::PatchNOP(func_address, length);
	*(BYTE*)func_address = 0xFF;
	*((BYTE*)func_address + 1) = 0x25;
	*(DWORD*)((BYTE*)func_address + 2) = (DWORD)((SIZE_T)pContext - (SIZE_T)func_address + FIELD_OFFSET(X64Hook::Context, dst_ptr)) - 6;
	pContext->dst_ptr = (SIZE_T)func_hook;
	XMem::Protect(func_address, length, prot);
	m_isdetoured = true;
	return pContext->m_detrbytes;
}

void* X64Hook::Trampoline()
{
	return m_isdetoured ? pContext->m_detrbytes : NULL;
}

void X64Hook::FreeTrampoline()
{
	if (m_isdetoured && pContext)
	{
		VirtualFree(pContext, NULL, MEM_RELEASE);
		pContext = NULL;
	}
}

int X64Hook::GetJMPSize()
{
	return m_isdetoured ? m_size : -1;
}

void X64Hook::RemoveHook()
{
	if (!m_isdetoured)
		return;
	DWORD prot;
	XMem::UnProtect(func_address, m_size, prot);
	memcpy(func_address, m_obytes, m_size);
	XMem::Protect(func_address, m_size, prot);
	if (pContext)
		VirtualFree(pContext, NULL, MEM_FREE);
	m_isdetoured = false;
	pContext = NULL;
	XMem::PatchNOP(m_obytes, sizeof(m_obytes));
}

// VTable hooking functions
VTableHook::VTableHook()
{
	m_table = NULL;
	func_addr = NULL;
	func_hook = NULL;
	id = -1;
}

VTableHook::~VTableHook()
{
	m_table = NULL;
	func_addr = NULL;
	func_hook = NULL;
	id = -1;
}

void VTableHook::SetupHook(void* ptr, int index, void* func_ptr)
{
	m_table = *(void***)ptr;
	id = index;
	func_hook = func_ptr;
	func_addr = m_table[id];
}

void VTableHook::InstallHook()
{
	DWORD prot;
	XMem::UnProtect(&m_table[id], 8, prot);
	m_table[id] = func_hook;
	XMem::Protect(&m_table[id], 8, prot);
}

void VTableHook::RemoveHook()
{
	DWORD prot;
	XMem::UnProtect(&m_table[id], 8, prot);
	m_table[id] = func_addr;
	XMem::Protect(&m_table[id], 8, prot);
}
