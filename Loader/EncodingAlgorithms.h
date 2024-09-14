#ifndef __ENCODING_ALGORITHMS_H__
#define __ENCODING_ALGORITHMS_H__

#include "StdAfx.h"

void DecodeModuleNameA
(const WORD *pEncodedFunctionName,
char *pDecodedFunctionName);

void 
DecodeModuleNameW
(const WORD *pEncodedModuleName,
WCHAR *pDecodedModuleName);

HMODULE GetModuleNTDLL(void);

FARPROC 
GetFunctionFromModule
(const WCHAR *pEncodedModuleName,
const char *pEncodedFunctionName);

void 
__memcpy
(void *lpTo,
const void *lpFrom,
size_t nSize);

FARPROC GetFunctionFromKERNEL32(const WORD *lpEncodedFunc);
FARPROC GetFunctionFromNTDLL(const WORD *lpEncodedFunc);

#endif