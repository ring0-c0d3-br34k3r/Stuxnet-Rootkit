#include "OS.h"
#include "STUBHandler.h"

#include "config.h"

void 
CheckSystemVersion
(BOOL bBool)
{
	OSVERSIONINFO lpSysInfo;
	lpSysInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	
	if(!GetVersionEx(&lpSysInfo)
	|| lpSysInfo.dwPlatformId != VER_PLATFORM_WIN32_NT
	|| (lpSysInfo.dwMajorVersion < 5 && lpSysInfo.dwMajorVersion > 6))
	{
		DEBUG_P("Wrong system version detected.")
		return;
	}
	
	Core_Load();
}