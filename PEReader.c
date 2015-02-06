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
	fflush(stdin); 
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
	char main_menu_choice = '\0';
	char menu_sub_choice = '\0';
	while(main_menu_choice != '5')
	{
		printf("1. DOS header options \n");
		printf("2. PE header options \n");
		printf("5. Quit \n");
		scanf("%c",&main_menu_choice);
		fflush(stdin);

		if(main_menu_choice == '5')
		{
			printf("Goodbye! \n");
			exit(0);
		}

		while(menu_sub_choice != '5')
		{
			if(main_menu_choice == '1')
			{
				printf("DOS header options \n");
				printf("1. Signature \n");
				printf("2. Size \n");
				printf("3. Relocations \n");
				printf("4. RVA to PE header \n");
				printf("5. Back \n");
				scanf("%c",&menu_sub_choice);
				fflush(stdin);
				walk_dos_header(DOSheader,menu_sub_choice);
			}
			else if(main_menu_choice == '2')
			{
				printf("PE header options \n");
				printf("1. Signature \n");
				printf("2. Number of sections \n");
				printf("3. Optional header size \n");
				printf("4. Entry point \n");
				printf("5. Back \n");
				scanf("%c",&menu_sub_choice);
				fflush(stdin);
				walk_pe_header(PEHeader,menu_sub_choice);
			}
			
		}
		main_menu_choice = '\0';
		menu_sub_choice = '\0';
	}
	
}

void walk_pe_header(IMAGE_NT_HEADERS * PEHeader,int choice)
{
	if(choice == '1')
	{
		printf("Signature: %.8x \n",PEHeader -> Signature);
	}
	else if(choice == '2')
	{
		printf("Number of sections: %.8x \n",PEHeader -> FileHeader.NumberOfSections);
	}
	else if(choice == '3')
	{
		printf("Size of optional header: %.8x \n",PEHeader -> FileHeader.SizeOfOptionalHeader);
	}
	else if(choice == '4')
	{
		printf("RVA to entry point: %.8x \n",PEHeader -> OptionalHeader.AddressOfEntryPoint);
	}
	else if(choice == '5')
	{
		printf("Returning to main menu \n");
	}
	else
	{
		printf("Not an option! \n");
	}
}

void walk_dos_header(IMAGE_DOS_HEADER * DOSheader, int choice)
{
	if(choice == '1')
	{
		printf("Signature: %.8x \n",DOSheader -> e_magic);
	}
	else if(choice == '2')
	{
		printf("Size: %.8x \n",DOSheader -> e_cparhdr);
	}
	else if(choice == '3')
	{
		printf("Relocations: %.8x \n",DOSheader -> e_crlc);
	}
	else if(choice == '4')
	{
		printf("RVA to PE Header: %.8x \n",DOSheader -> e_lfanew);
	}
	else if(choice == '5')
	{
		printf("Returning to main menu \n");
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
}