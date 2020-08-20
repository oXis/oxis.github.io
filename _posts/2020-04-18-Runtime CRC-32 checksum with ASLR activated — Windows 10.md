---
title:  "Runtime CRC-32 checksum with ASLR activated - Windows 10"
layout: post
---

This is my first blog post ever. I wanted to create a CRC-32 checksum that could work when ASLR is activated.  



## Intro

I was doing some challenges on Root-me when I discovered this anti-debug technique. When a software breakpoint in set by a debugger, a special instruction (0xCC) is written to the code where the breakpoint should be. So the code of the binary is modified.
The challenge binary was checking against a precomputed hash of its code, and if the computed hash was different, the binary refused to launch. That challenge is quite easy, you just have to setup a hardware breakpoint, but this is not the topic.

I was curious about how to implement such anti-debug technique, that could also act as an anti-tamper technique. A simple way to prevent cracking for example.

This code from the wonderful [Al-Khaser](https://github.com/LordNoteworthy/al-khaser) project describes how to implement this technique.

```cpp
#include "pch.h"

#include "SoftwareBreakpoints.h"


/*
Software breakpoints aka INT 3 represented in the IA-32 instruction set with the opcode CC (0xCC).
Given a memory addresse and size, it is relatively simple to scan for the byte 0xCC -> if(pTmp[i] == 0xCC)
An obfuscated method would be to check if our memory byte xored with 0x55 is equal 0x99 for example ... 
*/

VOID My_Critical_Function()
{
	int a = 1;
	int b = 2;
	int c = a + b;
	_tprintf(_T("I am critical function, you should protect against int3 bps %d"), c);
}


VOID Myfunction_Adresss_Next()
{
	My_Critical_Function();
	/*
	There is no guaranteed way of determining the size of a function at run time(and little reason to do so)
	however if you assume that the linker located functions that are adjacent in the source code sequentially in memory,
	then the following may give an indication of the size of a function Critical_Function by using :
	int Critical_Function_length = (int)Myfunction_Adresss_Next - (int)Critical_Function
	Works only if you compile the file in Release mode.
	*/
};

BOOL SoftwareBreakpoints()
{
	//NOTE this check might not work on x64 because of alignment 0xCC bytes
	size_t sSizeToCheck = (size_t)(Myfunction_Adresss_Next)-(size_t)(My_Critical_Function);
	PUCHAR Critical_Function = (PUCHAR)My_Critical_Function;

	for (size_t i = 0; i < sSizeToCheck; i++) {
		if (Critical_Function[i] == 0xCC) // Adding another level of indirection : 0xCC xor 0x55 = 0x99
			return TRUE; // Debugger set a breakpoint
	}
	return FALSE;
}
```

But as you can see, this is only protecting a single function. What about protecting the whole binary?
This is where ASLR comes into play.

### ASLR
From Wikipedia.
> Address space layout randomization (ASLR) is a computer security technique involved in preventing exploitation of memory corruption vulnerabilities. In order to prevent an attacker from reliably jumping to, for example, a particular exploited function in memory, ASLR randomly arranges the address space positions of key data areas of a process, including the base of the executable and the positions of the stack, heap and libraries. 

This means that each time the binary is loaded by the Windows loader, addresses of functions are fixed with the new image base, hence the *code changes* at each run. So storing a precomputed hash of the binary will no work.

For example, if a function is located at address `0x00040135` then a `call` instruction could be

```
nasm > call 0x00040135
       E830010400        call 0x40135
```

But with ASLR activated, if the binary is loaded at address `0x002b0000`, the `call` instruction is "fixed", the new instruction is

```
nasm > call 0x002b0135
       E830012B00        call 0x2b0135
```

This is called Base Relocation, more on [Relocation_(computing)](https://www.wikiwand.com/en/Relocation_(computing)).

### CRC
From Wikipedia.
> A cyclic redundancy check (CRC) is an error-detecting code commonly used in digital networks and storage devices to detect accidental changes to raw data. Blocks of data entering these systems get a short check value attached, based on the remainder of a polynomial division of their contents. On retrieval, the calculation is repeated and, in the event the check values do not match, corrective action can be taken against data corruption.

I won't go into detail about CRCs, you can see it as a hash function. For this demo, I took the CRC-32 code from [Sourceforge](https://sourceforge.net/projects/crccalculator/)

## Relocations? Just get rid of dem'
If you want to do a runtime CRC that works even when ASLR is activated, why not just get rid of those relocations?

### CalcCRC.exe

First we need a piece of code to compute the CRC-32 of a binary. I present to you, `CalcCRC.exe`!

```cpp
#include <windows.h>
#include <stdio.h>

#include "crc.h"

int main(int argc, const char* argv[])
{
    HANDLE  hIn;
    DWORD nIn = 0;

    if (argc != 2)
    {
        printf("Usage Error: Incorrect number of arguments\n\n");
        return 1;
    }

    hIn = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
    //check the handle
    if (hIn == INVALID_HANDLE_VALUE)
    {
        printf("[-] Open file error\n");
    }
    printf("[+] File opened\n");

    DWORD fileSize = GetFileSize(hIn, 0);
    printf("[+] File Size: %d\n", fileSize);

    uint8_t* buffer = (uint8_t*)malloc(fileSize);

    //read from file
    if (FALSE == ReadFile(hIn, buffer, fileSize - 1, &nIn, NULL))
    {
        printf("[-] Unable to read from file.\n GetLastError=%08x\n", GetLastError());
        CloseHandle(hIn);
        return 0;
    }

    if (buffer[0] != 'M' && buffer[0] != 'Z') {
        printf("[-] Not a PE file!\n");
    }

    // Get a handle to the module
    HMODULE imageBase = (HMODULE)buffer;
    // Parse to get headers
    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS imageHeader = (PIMAGE_NT_HEADERS)((SIZE_T)imageBase + imageDosHeader->e_lfanew);

    // Pointer to section headers
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageHeader);

    // Loop through all the section and search for the .text section (where the code is)
    int base = 0, end = 0, size = 0;
    for (int i = 0; i < imageHeader->FileHeader.NumberOfSections; i++, section++)
    {
        if (strcmp((char*)section->Name, ".text") == 0)
        {   
            // Get where the .text section is inside the file
            base = (SIZE_T)imageBase + section->PointerToRawData;
            size = section->SizeOfRawData;
            end = base + section->SizeOfRawData;
            printf("[+] Found %s at 0x%08x\n", (char*)section->Name, base);
        }
    }

    // Init some buffer
    uint8_t* code = (uint8_t*)malloc(size);
    uint8_t* ptr = code;

    printf("[+] PointerToRawData: 0x%x - EndOfRawData: 0x%x\n", base, end);

    // Fill the buffer
    while (base < end)
    {
        *ptr++ = *((uint8_t*)base);
        base++;
    }

    // Init CRC-32
    F_CRC_InicializaTabla();

    // Start CRC from .text section until end of it
    crc res = F_CRC_CalculaCheckSum(code, size);

    printf("CRC is %d", res);

    return 0;
}
```

The code is very simple, it takes a PE file in input, grab the `.text` section, where the code resides, put it into a buffer and compute the CRC-32 of that buffer.

```powershell
PS C:\Users\User\source\repos\Project1\Release> .\CalcCRC.exe .\CalcCRC.exe
[+] File opened
[+] File Size: 10240
[+] Found .text at 0x007f92f8
[+] PointerToRawData: 0x7f92f8 - EndOfRawData: 0x7fa2f8
CRC is -939333021
```

### Project1.exe (yes, really)

So now we need a binary that is capable of printing its own CRC.

```cpp
#include <windows.h>
#include <stdio.h>

#include "crc.h"

int main(int argc, TCHAR* argv[])
{
    // Get a handle to the module
    HMODULE imageBase = GetModuleHandle(NULL);
    // Parse to get headers
    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS imageHeader = (PIMAGE_NT_HEADERS)((SIZE_T)imageBase + imageDosHeader->e_lfanew);

    // Pointer to section headers
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(imageHeader);
    int numSec = imageHeader->FileHeader.NumberOfSections;

    printf("[+] RealImageBase: 0x%08x - NormalImageBase: 0x%08x - Delta: 0x%08x\n", imageBase, 0x00400000, (SIZE_T)((SIZE_T)imageBase - 0x00400000));

    // Start, size and end of the module.
    SIZE_T base = (SIZE_T)imageBase;
    SIZE_T size = (SIZE_T)imageHeader->OptionalHeader.SizeOfImage;
    SIZE_T end = (SIZE_T)base + size;

    // Loop through all the section and search for the .text section (where the code is)
    int codeBaseOffset = 0, codeEnd = 0, codeSize = 0;
    for (int i = 0; i < numSec; i++, section++)
    {
        if (strcmp((char*)section->Name, ".text") == 0)
        {
            // Get where the module loaded the .text section and it's size without padding.
            codeBaseOffset = section->VirtualAddress;
            codeSize = section->SizeOfRawData;
            printf("[+] Found %s at 0x%08x\n", (char*)section->Name, base + section->VirtualAddress);
        }
    }

    uint8_t* code = (uint8_t*)malloc(size);
    uint8_t* ptr = code;

    // Fill the buffer
    while (base < end)
    {
        *ptr++ = *((uint8_t*)base);
        base++;
    }

    // Init CRC-32
    F_CRC_InicializaTabla();

    // Start CRC from .text section until end of it
    crc res = F_CRC_CalculaCheckSum(code + codeBaseOffset, codeSize);

    printf("CRC is %d", res);

    return 0;
}
```

As you can see the code to get to `.text` is slightly different than the one from `CalcCRC.exe`. We are reaching for `section->VirtualAddress` instead of `section->PointerToRawData`. That is because, the binary is loaded at this address.

Remember to compile with `/DYNAMICBASE` flag. 

```powershell
PS C:\Users\User\source\repos\Project1\ASLR_On> .\Project1.exe
[+] RealImageBase: 0x00b10000 - NormalImageBase: 0x00400000 - Delta: 0x00710000
[+] Found .text at 0x00b11000
[+] Remove Relocations...
CRC is -1452293510
```

Same code, run twice.

```powershell
PS C:\Users\User\source\repos\Project1\ASLR_On> .\Project1.exe
[+] RealImageBase: 0x002b0000 - NormalImageBase: 0x00400000 - Delta: 0xffeb0000
[+] Found .text at 0x002b1000
[+] Remove Relocations...
CRC is 1109485166
```

Different results, *same binary!*. ASLR seed is set when Windows 10 boots, so you have to reboot the machine to get a different address base, or you can recompile the same code.

What happens if we turn ASLR off? Compile with `/DYNAMICBASE:NO`

```powershell
PS C:\Users\User\source\repos\Project1\ASLR_Off> .\Project1.exe
[+] RealImageBase: 0x00400000 - NormalImageBase: 0x00400000 - Delta: 0x00000000
[+] Found .text at 0x00401000
[+] No Relocations...
CRC is -812111699
PS C:\Users\User\source\repos\Project1\ASLR_Off> .\Project1.exe
[+] RealImageBase: 0x00400000 - NormalImageBase: 0x00400000 - Delta: 0x00000000
[+] Found .text at 0x00401000
[+] No Relocations...
CRC is -812111699
```

Same CRC.

Running our `CalcCRC.exe` on the binary will ASLR off gives us the same sum.

```powershell
PS C:\Users\User\source\repos\Project1\Release> .\CalcCRC.exe ..\ASLR_Off\Project1.exe
[+] File opened
[+] File Size: 20992
[+] Found .text at 0x00ad9318
[+] PointerToRawData: 0xad9318 - EndOfRawData: 0xadc518
CRC is 1138314871
```



```powershell
PS C:\Users\User\source\repos\Project1\ASLR_Off> .\Project1.exe
[+] RealImageBase: 0x00400000 - NormalImageBase: 0x00400000 - Delta: 0x00000000
[+] Found .text at 0x00401000
CRC is 1138314871
```

But we have a different CRC if we run it on the ASLR on binary.

### Ok then, so remove those relocations already!

Add this piece of code just before `F_CRC_InicializaTabla`.

```cpp
if (imageHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
    printf("[+] Remove Relocations...\n");
    SIZE_T delta = (SIZE_T)(imageHeader->OptionalHeader.ImageBase - 0x00400000);
    PIMAGE_BASE_RELOCATION relocAddr = (PIMAGE_BASE_RELOCATION)((SIZE_T)imageBase + imageHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

    // Relocation offsets start from ImageBase
    ImageBaseRelocation(relocAddr, (SIZE_T)code, delta);
}
else {
    printf("[+] No Relocations...\n");
}

// Init CRC-32
F_CRC_InicializaTabla();
```

And then, add this before the `main` function.

```cpp
void ImageBaseRelocation(PIMAGE_BASE_RELOCATION relocAddr, SIZE_T code, SIZE_T delta)
{
    // Loop over all the relocation blocks
    while (relocAddr->SizeOfBlock > 0)
    {
        // Get reloc virtual address for that block
        SIZE_T va = code + relocAddr->VirtualAddress;

        // Get relocations of that block
        uint16_t* relocation = (uint16_t*)((uint8_t*)relocAddr + sizeof(IMAGE_BASE_RELOCATION));

        // Loop over relocations
        for (DWORD i = sizeof(IMAGE_BASE_RELOCATION); i < relocAddr->SizeOfBlock; i += sizeof(WORD), relocation++)
        {
            int type = *relocation >> 12;
            int offset = *relocation & 0xfff;

            if (type == IMAGE_REL_BASED_HIGHLOW)
            {
                // REMOVE DELTA FROM THE ADDR
                *((SIZE_T*)(va + offset)) -= delta;
            }
        }

        // Next block
        relocAddr = (PIMAGE_BASE_RELOCATION)(((SIZE_T)relocAddr) + relocAddr->SizeOfBlock);
    }
}
```

That function takes the address of the first relocation block, a pointer to the image base, and a `delta`. The former argument is the difference between the default load address `0x00400000` and the actual load address `imageHeader->OptionalHeader.ImageBase`.

### Try it out!

Let's compile the code twice, the first with ASLR on and the second with ASLR off.

Then, run the code.
```powershell
PS C:\Users\User\source\repos\Project1\ASLR_Off> .\Project1.exe
[+] RealImageBase: 0x00400000 - NormalImageBase: 0x00400000 - Delta: 0x00000000
[+] Found .text at 0x00401000
[+] No Relocations...
CRC is 1494432894
PS C:\Users\User\source\repos\Project1\ASLR_Off> .\Project1.exe
[+] RealImageBase: 0x00400000 - NormalImageBase: 0x00400000 - Delta: 0x00000000
[+] Found .text at 0x00401000
[+] No Relocations...
CRC is 1494432894
```

Two runs with ASLR off gives us the same CRC, so at least we know it works. What about ASLR on?

```powershell
PS C:\Users\User\source\repos\Project1\ASLR_On> .\Project1.exe
[+] RealImageBase: 0x00740000 - NormalImageBase: 0x00400000 - Delta: 0x00340000
[+] Found .text at 0x00741000
[+] Remove Relocations...
CRC is 1494432894
PS C:\Users\User\source\repos\Project1\ASLR_On> .\Project1.exe
[+] RealImageBase: 0x00df0000 - NormalImageBase: 0x00400000 - Delta: 0x009f0000
[+] Found .text at 0x00df1000
[+] Remove Relocations...
CRC is 1494432894
```

We have the same CRC even when the loaded image base is different, but we also have the same CRC than the ASLR off version, wunderbar!

But now, let's test with our `CalcCRC.exe`.

```powershell
PS C:\Users\User\source\repos\Project1\Release> .\CalcCRC.exe ..\ASLR_Off\Project1.exe
[+] File opened
[+] File Size: 21504
[+] Found .text at 0x015c9318
[+] PointerToRawData: 0x15c9318 - EndOfRawData: 0x15cc718
CRC is 1494432894
PS C:\Users\User\source\repos\Project1\Release> .\CalcCRC.exe ..\ASLR_On\Project1.exe
[+] File opened
[+] File Size: 22528
[+] Found .text at 0x01469318
[+] PointerToRawData: 0x1469318 - EndOfRawData: 0x146c718
CRC is 1494432894
```

It returns the *same CRC* for the two binaries, but also the same CRC returned by the binaries themselves! Wunderbar wunderbar!

### Debug?

Last, let's run the ASLR code through a debugger and see what happens.

![x32Dbg](/assets/pics/2020-04-18/dbg.png "Logo Title Text 1")

CRC is different!

## Outro

All the work was done on a up-to-date version of Windows 10 and Visual Studio 2019 Community.
End of my first blog post ever, hope you liked it!