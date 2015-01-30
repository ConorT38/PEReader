/*
Author:Ciaran Strutt
Date:30/01/2015
Description:PE File reader
*/

#include <Windows.h>
#include <stdio.h>

#define EXIT_FILE_ERROR -5
#define EXIT_MAPPING_ERROR -6
#define HANDLE_EXISTS -7

void walk_pe_file(void *);

int main()
{
	HANDLE fileHandle,fileMapping;
	void * start_memory_addr;
	char * fileName = malloc(MAX_PATH);
	printf("Enter path to file: ");
	scanf("%s",fileName);
	fileHandle = CreateFile(fileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
	if(fileHandle == INVALID_HANDLE_VALUE)
	{
		printf("Opening handle to file failed! \n");
		CloseHandle(fileHandle);
		return EXIT_FILE_ERROR;
	}
	fileMapping = CreateFileMapping(fileHandle,0,PAGE_READONLY | SEC_COMMIT,0,0,0);
	if(fileMapping == NULL)
	{
		printf("Opening handle for file mapping failed! \n");
		CloseHandle(fileHandle);
		return EXIT_MAPPING_ERROR;
	}
	start_memory_addr = MapViewOfFile(fileMapping, FILE_MAP_READ,0,0,0);
	if(start_memory_addr == NULL)
	{
		printf("Mapping file into memory failed! \n");
		CloseHandle(fileMapping);
		CloseHandle(fileHandle);
		return EXIT_MAPPING_ERROR;
	}
	
	walk_pe_file(start_memory_addr);
}

void walk_pe_file(void * base)
{
	int i = 0;

	IMAGE_DOS_HEADER * DOSheader = base;
	IMAGE_NT_HEADERS * PEHeader;

	if(DOSheader -> e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Not a valid PE file! \n");
	}
	printf("DOS header signature %.8x \n",DOSheader -> e_magic);
	printf("Header size: %.8x  \n",DOSheader -> e_cparhdr);
	printf("Relocations: %.8x \n",DOSheader -> e_crlc);
	printf("Pointer to PE Header: %.8x \n",DOSheader -> e_lfanew);

	PEHeader = (IMAGE_NT_HEADERS * )((BYTE *)base + DOSheader -> e_lfanew);

	if(PEHeader -> Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Invalid PE File! \n");
	}

	printf("Number of sections: %.8x \n",PEHeader -> FileHeader.NumberOfSections);
	printf("Size of optional header: %.8x \n",PEHeader -> FileHeader.SizeOfOptionalHeader);
	printf("Magic: %.8x \n", PEHeader -> OptionalHeader.Magic);
	printf("Size of .code: %.8x \n",PEHeader -> OptionalHeader.SizeOfCode); 
	printf("Size of .data: %.8x \n",PEHeader -> OptionalHeader.SizeOfUninitializedData);
	printf("Size of .bss: %.8x \n",PEHeader -> OptionalHeader.SizeOfInitializedData);
	printf("RVA to entry point: %.8x \n",PEHeader -> OptionalHeader.AddressOfEntryPoint);
	printf("RVA to start of .code: %.8x \n", PEHeader -> OptionalHeader.BaseOfCode);
	printf("RVA to start of .data: %.8x \n", PEHeader -> OptionalHeader.BaseOfData);
	printf("Preferred load address: %.8x \n", PEHeader -> OptionalHeader.ImageBase);
	printf("Section alignment in memory: %.8x \n", PEHeader -> OptionalHeader.SectionAlignment);
	printf("File Alignment: %.8x \n", PEHeader -> OptionalHeader.FileAlignment);
	printf("Offset from start of file to first section: %.8x \n", PEHeader -> OptionalHeader.SizeOfHeaders);
	printf("Number of RVA's: %.8x \n", IMAGE_NUMBEROF_DIRECTORY_ENTRIES); //More reliable

	for(i; i < sizeof(PEHeader -> OptionalHeader.DataDirectory); i++)
	{
		printf("RVA %.8x \n",PEHeader -> OptionalHeader.DataDirectory[i]);
	}
}