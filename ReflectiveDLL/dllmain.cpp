// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

// Ham Dll tieu chuan
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MessageBoxA(NULL, "Process nay da bi inject!", "Injected Notice", MB_OK);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// Khai bao ham export ReflectiveLoader cua thu vien.
extern"C" __declspec(dllexport) void WINAPI ReflectiveLoader(LPVOID lpParameter) {
    // Cac con tro ham
    GETPROCADDRESS pGetProcAdrress = 0; // con tro ham
    VIRTUALALLOC pVirtualAlloc = 0; // con tro ham
    LOADLIBRARYA pLoadLibraryA = 0; // con tro ham
    NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache = 0;   // con tro ham
    // 0. Lay dia chi cua chinh ham nay trong memory
  
    ULONG_PTR uLibAddress = (ULONG_PTR)lpParameter;

    // 1. Lay dia chi cac ham API can thiet tu kernel32.dll

    // Duyet PEB
    ULONG_PTR uBaseAddress = __readgsqword(0x60); // Lay PEB tren Windows x64.
    // Lay process loaded modules
    uBaseAddress = (ULONG_PTR)((_PPEB)uBaseAddress)->pLdr;
    // Lay entry trong module list
    PLIST_ENTRY entry = ((PPEB_LDR_DATA1)uBaseAddress)->InMemoryOrderModuleList.Flink;
    
    while (entry != &(((PPEB_LDR_DATA1)uBaseAddress)->InMemoryOrderModuleList))
    {
        wchar_t* a = ((PLDR_DATA_TABLE_ENTRY1)entry)->BaseDllName.pBuffer;
        int hash = 0;
        while (*a != 0)
        {
            hash = hash ^ *a;
            hash = hash << 1;
            a++;
        }
        if (0x000724e8 == hash)
        {
            ULONG_PTR moduleBase = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY1)entry)->DllBase;
            ULONG_PTR moduleNTHeader = moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew;
            ULONG_PTR exportDirVA = ((PIMAGE_NT_HEADERS)moduleNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            
            ULONG_PTR exportDir = moduleBase + exportDirVA;
            // nameArray la pointer tro toi mang RVA cua cac string name.
            DWORD * nameArray = (DWORD *)(moduleBase + ((PIMAGE_EXPORT_DIRECTORY)exportDir)->AddressOfNames);
            // nameOrdinal la pointer tro toi mang cac Ordinal
            WORD* nameOrdinal = (WORD*) (moduleBase + ((PIMAGE_EXPORT_DIRECTORY)exportDir)->AddressOfNameOrdinals);
            // AddressArray la pointer tro toi mang cac dia chi RVA cua ham.
            DWORD* addressArray = (DWORD*)(moduleBase + ((PIMAGE_EXPORT_DIRECTORY)exportDir)->AddressOfFunctions);
            for (DWORD i = 0; i< ((PIMAGE_EXPORT_DIRECTORY)exportDir)->NumberOfNames; i++)
            {
                char* fName = (char*)(moduleBase + nameArray[i]);
                hash = 0;
                while (*fName != 0)
                {
                    hash = hash ^ *fName;
                    hash = hash << 1;
                    fName++;
                }
                if (hash == 0x0019e522) {
                    WORD ordinal = nameOrdinal[i];
                    pGetProcAdrress = (GETPROCADDRESS)(moduleBase + addressArray[ordinal]);
                }
                if (hash == 0x00075a7a) {
                    WORD ordinal = nameOrdinal[i];
                    pVirtualAlloc = (VIRTUALALLOC)(moduleBase + addressArray[ordinal]);
                }
                if (hash == 0x00069ea6) {
                    WORD ordinal = nameOrdinal[i];
                    pLoadLibraryA = (LOADLIBRARYA)(moduleBase + addressArray[ordinal]);
                }
            }
        }

        if (hash == 0x00008c28)
        {
            ULONG_PTR moduleBase = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY1)entry)->DllBase;
            ULONG_PTR moduleNTHeader = moduleBase + ((PIMAGE_DOS_HEADER)moduleBase)->e_lfanew;
            ULONG_PTR exportBase = (ULONG_PTR) & (((PIMAGE_NT_HEADERS)moduleNTHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);

            ULONG_PTR exportDir = moduleBase + ((PIMAGE_DATA_DIRECTORY)exportBase)->VirtualAddress;
            // nameArray la pointer tro toi mang RVA cua cac string name.
            DWORD* nameArray = (DWORD*)(moduleBase + ((PIMAGE_EXPORT_DIRECTORY)exportDir)->AddressOfNames);
            // nameOrdinal la pointer tro toi mang cac Ordinal
            WORD* nameOrdinal = (WORD*)(moduleBase + ((PIMAGE_EXPORT_DIRECTORY)exportDir)->AddressOfNameOrdinals);
            // AddressArray la pointer tro toi mang cac dia chi RVA cua ham.
            DWORD* addressArray = (DWORD*)(moduleBase + ((PIMAGE_EXPORT_DIRECTORY)exportDir)->AddressOfFunctions);
            for (DWORD i = 0; i < ((PIMAGE_EXPORT_DIRECTORY)exportDir)->NumberOfNames; i++)
            {
                char* fName = (char*)(moduleBase + nameArray[i]);
                hash = 0;
                while (*fName != 0)
                {
                    hash = hash ^ *fName;
                    hash = hash << 1;
                    fName++;
                }
                if (hash == 0x36dde502) {
                    WORD ordinal = nameOrdinal[i];
                    pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)(moduleBase + addressArray[ordinal]);
                }
                
            }
        }
        entry = ((PLIST_ENTRY)entry)->Flink;
    }
    
    //2. Tai DLL tu dang tho thanh image tai 1 vung nho khac trong memory.
    ULONG_PTR uHeader = uLibAddress + ((PIMAGE_DOS_HEADER)uLibAddress)->e_lfanew;
    // allocate memory for DLL to be loaded. Address is arbitrary, all memory is zeros and RWX.
    uBaseAddress = (ULONG_PTR)pVirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)uHeader)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    // Copy the header.
    ULONG_PTR uValueA = ((PIMAGE_NT_HEADERS)uHeader)->OptionalHeader.SizeOfHeaders;
    BYTE* uSrc = (BYTE*)uLibAddress;
    BYTE* uDes = (BYTE*)uBaseAddress;
    while (uValueA)
    {
        *uDes = *uSrc;
        uDes++;
        uSrc++;
        uValueA--;
    }
    //3. Load sections.
    // Vi tri section header table nam sau header: firstSec = &OptionalHeader + sizeofoptionalheader
    //uValueA is VA of firstsection
    uValueA = (ULONG_PTR)(&((PIMAGE_NT_HEADERS)uHeader)->OptionalHeader) + ((PIMAGE_NT_HEADERS)uHeader)->FileHeader.SizeOfOptionalHeader;
    ULONG_PTR uValueB = ((PIMAGE_NT_HEADERS)uHeader)->FileHeader.NumberOfSections;
    while (uValueB)
    {
        // uSrc is the offset of this section data
        uSrc = (BYTE*)(uLibAddress + ((PIMAGE_SECTION_HEADER)uValueA)->PointerToRawData);
        // uDes is the VA of this section image
        uDes = (BYTE*)(uBaseAddress + ((PIMAGE_SECTION_HEADER)uValueA)->VirtualAddress);
        // Copy each byte of source to destination
        for (SIZE_T i = 0; i < ((PIMAGE_SECTION_HEADER)uValueA)->SizeOfRawData; i++)
        {
            *uDes = *uSrc;
            uDes++;
            uSrc++;
        }
        // Get the next sextion
        uValueA += sizeof(IMAGE_SECTION_HEADER);
        uValueB--;
    }
    //4. Process import table
    // valueA = RVA of Import directory.
    uValueA = (ULONG_PTR)((PIMAGE_DATA_DIRECTORY)(((PIMAGE_NT_HEADERS)uHeader)->OptionalHeader.DataDirectory[1]).VirtualAddress);
    uValueA += uBaseAddress;
    // Duyet qua toan bo cac import module.
    while (((PIMAGE_IMPORT_DESCRIPTOR)uValueA)->Name)
    {
        // use LoadLibraryA
        uLibAddress = (ULONG_PTR)pLoadLibraryA((LPCSTR)(uBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uValueA)->Name));
        // Lay VA cua Import Address Table - FirstThunk.
        uValueB = (((PIMAGE_IMPORT_DESCRIPTOR)uValueA)->FirstThunk + uBaseAddress);
        // Trong IAT co chua cac IMAGE_THUNK_DATA. Truy cap vao Thunk dau tien, chung dia chi IAT
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)uValueB;
        while (pThunk->u1.Function != 0)
        {
            // Kiem tra xem nhap theo ordinal hay theo name.
            if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal))
            {
                LPCSTR ordinal = (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal);
                DWORD_PTR funcAddr = (DWORD_PTR)pGetProcAdrress((HMODULE)uValueA, ordinal);
                pThunk->u1.Function = funcAddr; // Ghi dia chi vao Thunk.
            }
            else
            {
                // Neu load bang name, IMAGE_THUNK_DATA chua mot con tro tro den cau truc IMAGE_IMPORT_BY_NAME.
                PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)(pThunk->u1.AddressOfData + uBaseAddress); // Day la RVA
                //functionName += uBaseAddress;   // Cong them BaseImage de tro toi dung vi tri.
                // Lay dia chi voi getProcAddress va tham so IMAGE_IMPORT_BY_NAME->Name.
                DWORD_PTR funcAddr = (DWORD_PTR)pGetProcAdrress((HMODULE)uLibAddress, functionName->Name);
                pThunk->u1.Function = funcAddr; // Ghi vao vung nho dia chi ham.
            }
            pThunk++;   // Sang Thunk ke tiep.
           
        }
        // Da duyet xong module nay, sang module tiep theo trong IMAGE_IMPORT_DESCRIPTOR
        uValueA += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    //5. Relocation 
    // Qua trinh xu ly Relocation bao gom doc cac bang gia tri relocation va cong delta ImageBase
    // Tinh toan base address delta.
    ULONG_PTR uDelta = uBaseAddress - ((PIMAGE_NT_HEADERS)uHeader)->OptionalHeader.ImageBase;
    // Lay dia chi cua relocation directory
    PIMAGE_DATA_DIRECTORY pReloc = &((PIMAGE_NT_HEADERS)uHeader)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (pReloc->Size != 0)
    {
        // uValueA = dia chi Relocation Block dau tien.
        uValueA = uBaseAddress + pReloc->VirtualAddress;
        while (((PIMAGE_BASE_RELOCATION)uValueA)->SizeOfBlock)
        {
            // Lay dia chi cua relocation block nay.
            uValueB = uBaseAddress + ((PIMAGE_BASE_RELOCATION)uValueA)->VirtualAddress;
            ULONG_PTR numEntry = (((PIMAGE_BASE_RELOCATION)uValueA)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))/sizeof(IMAGE_RELOC);
            PIMAGE_RELOC pEntry = (PIMAGE_RELOC)(uValueA + sizeof(IMAGE_BASE_RELOCATION));
            while (numEntry--)
            {

                // Tien hanh relocation toan bo gia tri trong cac entry type-offset.
                if (pEntry->type == IMAGE_REL_BASED_DIR64)
                    *(ULONG_PTR*)(uValueB + pEntry->offset) += uDelta;  // Gia tri tai BaseImage + pageRVA + offset duoc update.
                else if (pEntry->type == IMAGE_REL_BASED_HIGHLOW)
                    *(DWORD*)(uValueB + pEntry->offset) += (DWORD)uDelta;
                else if (pEntry->type == IMAGE_REL_BASED_HIGH)
                    *(WORD*)(uValueB + pEntry->offset) += HIWORD(uDelta);
                else if (pEntry->type == IMAGE_REL_BASED_LOW)
                    *(WORD*)(uValueB + pEntry->offset) += LOWORD(uDelta);

                // Next Entry.
                pEntry++;
            }
            // Next block of the Relocation Table.
            uValueA = uValueA + ((PIMAGE_BASE_RELOCATION)uValueA)->SizeOfBlock;
        }
    }

    // 6. Goi image entry point.
    // Dia chi entry point cua DLL = ImageBase + RVA entry point.
    uValueA = (uBaseAddress + ((PIMAGE_NT_HEADERS)uHeader)->OptionalHeader.AddressOfEntryPoint);
    // flush the instruction cache to avoid stale code being used which was updated by relocation.
    pNtFlushInstructionCache((HANDLE)-1, NULL, 0);
    // Goi entry point.
    ((DLLMAIN)uValueA)((HINSTANCE)uBaseAddress, DLL_PROCESS_ATTACH, NULL);
    // End DLL.
}
