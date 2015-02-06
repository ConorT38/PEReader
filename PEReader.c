/*
Author:Ciaran Strutt
Date:30/01/2015
Description:PE File reader
*/

#include <Windows.h>
#include <stdio.h>

//Custom error codes
#define EXIT_FILE_ERROR -5
#define EXIT_MAPPING_ERROR -6
#define HANDLE_EXISTS -7
#define MALLOC_ERROR -8

void * getdosheaderHandle(void *);
void * getpeheaderHandle(void *,IMAGE_DOS_HEADER *);
void menu(IMAGE_DOS_HEADER *,IMAGE_NT_HEADERS *);
void walk_dos_header(IMAGE_DOS_HEADER *,int);
void walk_pe_header(IMAGE_NT_HEADERS *,int);

int main()
{
	IMAGE_DOS_HEADER * DOSheader;
	IMAGE_NT_HEADERS * PEHeader;
	HANDLE fileHandle,fileMapping; 
	void * start_memory_addr; //Base address of PE file (DOS Header)
	char * fileName = malloc(MAX_PATH); 
	if(fileName == NULL)
	{
		printf("Memory allocation error! \n");
		return MALLOC_ERROR;
	}
	printf("Enter path to file: ");
	scanf("%s",fileName); 
	fileHandle = CreateFile(fileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL); //Get access to the requsted file and return a pointer to fileHandle
	if(fileHandle == INVALID_HANDLE_VALUE)
	{
		printf("Opening handle to file failed! \n");
		CloseHandle(fileHandle);
		return EXIT_FILE_ERROR;
	}
	fileMapping = CreateFileMapping(fileHandle,0,PAGE_READONLY | SEC_COMMIT,0,0,0); //We also need a handle to an area of memory to map the files contents
	if(fileMapping == NULL)
	{
		printf("Opening handle for file mapping failed! \n");
		CloseHandle(fileHandle);
		return EXIT_MAPPING_ERROR;
	}
	start_memory_addr = MapViewOfFile(fileMapping, FILE_MAP_READ,0,0,0); //Attempt to map the contents of the file to the address pointed to by fileMapping
	if(start_memory_addr == NULL)
	{
		printf("Mapping file into memory failed! \n");
		CloseHandle(fileMapping);
		CloseHandle(fileHandle);
		return EXIT_MAPPING_ERROR;
	}
				//Casted as function is returning void *
	DOSheader = (IMAGE_DOS_HEADER *)getdosheaderHandle(start_memory_addr); //Pass the address of where our file is mapped in memory
	PEHeader = (IMAGE_NT_HEADERS *)getpeheaderHandle(start_memory_addr,DOSheader);

	menu(DOSheader,PEHeader);
}

void menu(IMAGE_DOS_HEADER * DOSheader,IMAGE_NT_HEADERS * PEHeader)
{

}

void walk_pe_header(IMAGE_NT_HEADERS * PEHeader,int choice)
{
	if(choice == 1)
	{
		printf("Signature: %.8x \n",PEHeader -> Signature);
	}
}

void walk_dos_header(IMAGE_DOS_HEADER * DOSheader, int choice)
{
	if(choice == 1)
	{
		printf("Signature: %.8x \n",DOSheader -> e_magic);
	}
	else if(choice == 2)
	{
		printf("Size: %.8x \n",DOSheader -> e_cparhdr);
	}
	else if(choice == 3)
	{
		printf("Relocations: %.8x \n",DOSheader -> e_crlc);
	}
	else if(choice == 4)
	{
		printf("RVA to PE Header: %.8x \n",DOSheader -> e_lfanew);
	}
	else if(choice == 5)
	{
		return;
	}
	else
	{
		printf("Not an option! \n");
	}
	
}

void * getpeheaderHandle(void * base, IMAGE_DOS_HEADER * DOSheaderRVA)
{
	void * PEHeader = (IMAGE_NT_HEADERS * )((BYTE *)base + DOSheaderRVA -> e_lfanew); //Calcuate the absolute address of the PE Header, BASE + RVA 
	//Triple brackets is because -> operator has highger percedance than casting
	if(((IMAGE_NT_HEADERS *)PEHeader) -> Signature != IMAGE_NT_SIGNATURE) //Similar to the DOS Header check, check if the PE Header signature PE\0\0 is present
	{
		printf("Invalid PE File! \n");
	}
	return PEHeader;
}

void * getdosheaderHandle(void * base)
{
	void * DOSheader = base;

	if(((IMAGE_DOS_HEADER *)DOSheader) -> e_magic != IMAGE_DOS_SIGNATURE) //Check if the DOS header contains a valid MZ signature
	{
		printf("Not a valid PE file! \n");
	}
	
	return DOSheader;

	/*
	int i = 0;

	IMAGE_DOS_HEADER * DOSheader = base; //Mostly used to check the MZ signature is present and grab the offset to the start of the PE file
	IMAGE_NT_HEADERS * PEHeader; //Pointer to the PE header, like DOSHeader but contains more valuable information about the executable file
	IMAGE_SECTION_HEADER * sectionHeader; 

	if(DOSheader -> e_magic != IMAGE_DOS_SIGNATURE) //Check if the DOS header contains a valid MZ signature
	{
		printf("Not a valid PE file! \n");
	}
	printf("DOS header signature %.8x \n",DOSheader -> e_magic);
	printf("Header size: %.8x  \n",DOSheader -> e_cparhdr);
	printf("Relocations: %.8x \n",DOSheader -> e_crlc);
	printf("Pointer to PE Header: %.8x \n",DOSheader -> e_lfanew); //RVA to PE Header

	PEHeader = (IMAGE_NT_HEADERS * )((BYTE *)base + DOSheader -> e_lfanew); //Calcuate the absolute address of the PE Header, BASE + RVA 

	if(PEHeader -> Signature != IMAGE_NT_SIGNATURE) //Similar to the DOS Header check, check if the PE Header signature PE\0\0 is present
	{
		printf("Invalid PE File! \n");
	}

	//Output explains the following
	printf("Number of sections: %.8x \n",PEHeader -> FileHeader.NumberOfSections);
	printf("Size of optional header: %.8x \n",PEHeader -> FileHeader.SizeOfOptionalHeader);
	printf("Magic: %.8x \n", PEHeader -> OptionalHeader.Magic);
	printf("Size of .code: %.8x \n",PEHeader -> OptionalHeader.SizeOfCode); 
	printf("Size of .data: %.8x \n",PEHeader -> OptionalHeader.SizeOfUninitializedData); //shows the size of the data file
	printf("Size of .bss: %.8x \n",PEHeader -> OptionalHeader.SizeOfInitializedData);
	printf("RVA to entry point: %.8x \n",PEHeader -> OptionalHeader.AddressOfEntryPoint);
	printf("RVA to start of .code: %.8x \n", PEHeader -> OptionalHeader.BaseOfCode);
	printf("RVA to start of .data: %.8x \n", PEHeader -> OptionalHeader.BaseOfData);
	printf("Preferred load address: %.8x \n", PEHeader -> OptionalHeader.ImageBase);
	printf("Section alignment in memory: %.8x \n", PEHeader -> OptionalHeader.SectionAlignment);
	printf("File Alignment: %.8x \n", PEHeader -> OptionalHeader.FileAlignment);
	printf("Offset from start of file to first section: %.8x \n", PEHeader -> OptionalHeader.SizeOfHeaders);
	printf("Number of RVA's: %.8x \n", IMAGE_NUMBEROF_DIRECTORY_ENTRIES); //More reliable

	sectionHeader = PEHeader -> FileHeader.SizeOfOptionalHeader + 1; //Sections are right after the end of the optionalheader, so the size of the optional header points to the end

	for(i; i < 10; i++) //There is normally 10-14 sections there could be more though, will fix this later so it isn't hardcoded, testing for now
	{
		printf("RVA %.8x \n",PEHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT + i]); //add 1 to the define which starts 0 so third iteration would be 0 + 3, could just use i but this way is more clear
	}
	*/

}