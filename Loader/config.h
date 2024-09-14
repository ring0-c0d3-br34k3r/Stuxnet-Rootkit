#ifndef CONFIG_H
#define CONFIG_H

#include "StdAfx.h"

#define X_CORE_KEY 		(BYTE )0x96
#define X_PTR_KEY		(DWORD)0xAE1979DD
#define X_STRING_KEY	(WORD )0xAE12

#define X_SIGNATURE 	(DWORD)0xAE39120D
#define X_SECTION_NAME	".stub"

#define ENTRY_FUNC		(LPCSTR)15

#ifdef _DEBUG
#	define DEBUG_P(s) { OutputDebugString(TEXT(s"\n")); }
#else
#	define DEBUG_P(s)
#endif

#endif