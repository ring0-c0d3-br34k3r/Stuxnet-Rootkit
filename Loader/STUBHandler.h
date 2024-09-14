#ifndef __STUB_HANDLER_H__
#define __STUB_HANDLER_H__

#include "StdAfx.h"

typedef 
struct 
SCoreHeader {
	DWORD HeaderLength;
	DWORD SectionLength;
	DWORD FullLength;
	DWORD dw4;
	DWORD dw5;
	DWORD dw6;
	DWORD dw7[130];
	DWORD dw137;
	DWORD dw138;
} TCoreHeader;

void Core_Load(void);

void 
Core_Crypt
(BYTE *lpStream,
 DWORD dwLength);
 
BOOL 
Core_GetDLL
(LPVOID *ppCore,
 INT32 *pCoreLen);

#endif