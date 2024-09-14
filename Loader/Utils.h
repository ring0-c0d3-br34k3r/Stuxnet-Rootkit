#ifndef __UTILS_H__
#define __UTILS_H__

#include "StdAfx.h"
#include "define.h"

INT32 
SharedMapViewOfSection
(HANDLE hHandle,
 SIZE_T iSectionSize,
 PHANDLE pSectionHandle,
 PVOID *pBaseAddr1,
 PVOID *pBaseAddr2);
 
void 
CopySegmentIntoSections
(PVOID *pProcessSection,
PVOID pModuleSection,
INT32 *pSectionPointer,
PSECTION_SEGEMENT_INFO sSegment,
PVOID pSegmentContent,
UINT32 iSegmentSize);

INT32 
GetRandomModuleName
(GENERAL_INFO_BLOCK *sInfoBlock,
LPCWSTR szDebugLibraryName);

#endif