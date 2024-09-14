#include "AssemblyBlock0.h"

void
__declspec(naked)
__ASM_BLOCK0_0(void)
{
	__asm
	{
		cmp     edx, [eax]
		dec     ecx
		stosd

		mov     dl, 0
		jmp     short __ASM_REF_0
		
		mov     dl, 1
		jmp     short __ASM_REF_0
		
		mov     dl, 2
		jmp     short __ASM_REF_0
		
		mov     dl, 3
		jmp     short __ASM_REF_0
		
		mov     dl, 4
		jmp     short __ASM_REF_0
		
		mov     dl, 5
		jmp     short $+2
		
	__ASM_REF_0:
		push    edx
		call    __ASM_BLOCK0_2
	}
}

void
__declspec(naked)
__ASM_BLOCK0_1(void)
{
	__asm
	{
		xchg    ebx, [ebx+0]
		add     [eax], dl
	}
}

void
__declspec(naked)
__ASM_BLOCK0_2(void)
{
	__asm
	{
		pop     edx
		jmp     dword ptr [edx]
	}
}