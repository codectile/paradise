#include "X96Hook.h"
#include "XMem.h"
#include "XLog.h"

#ifdef WIN32
// 32-bit Detour
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
	int length = XMem::length_disassemble(func_address, MAX_BYTES);
	if (!length)
		return NULL;
	unsigned long prot;
	m_size = length;
	XMem::UnProtect(func_address, length, prot);
	memcpy(m_obytes, func_address, length);
	m_memloc = (BYTE*)malloc(length + 5);
	memcpy(m_memloc, func_address, length);
	m_memloc += length;
	*m_memloc = 0xE9;
	*(unsigned long*)(m_memloc + 1) = (unsigned long)((unsigned long)func_address + length - (unsigned long)m_memloc) - 5;
	XMem::PatchNOP(func_address, length);
	XMem::PatchJump<unsigned long>(func_address, func_hook);
	XMem::Protect(func_address, length, prot);
	m_isdetoured = true;
	return (void*)(m_memloc - length);
}

void* X32Hook::Trampoline()
{
	return m_isdetoured ? m_memloc : NULL;
}

void X32Hook::FreeTrampline()
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
	unsigned long prot;
	XMem::UnProtect(func_address, m_size, prot);
	memcpy(func_address, m_obytes, m_size);
	XMem::Protect(func_address, m_size, prot);
	if(m_memloc)
		free(m_memloc);
	m_isdetoured = false;
	m_memloc = NULL;
	XMem::PatchNOP(m_obytes, sizeof(m_obytes));
}
#endif