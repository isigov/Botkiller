#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <iostream>

using namespace std;

bool Injection(DWORD pid)
{
	IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
	IMAGE_NT_HEADERS *nt_header= (IMAGE_NT_HEADERS*)malloc(sizeof(IMAGE_NT_HEADERS));
	MODULEENTRY32 mEntry;
	DWORD baseAddr;

	HANDLE handle = OpenProcess(PROCESS_VM_READ, false, pid);

	if(handle == NULL)
		return false;
	
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

	if(snapshot == NULL)
		return false;

	mEntry.dwSize = sizeof(MODULEENTRY32);

	if(Module32First(snapshot, &mEntry))
		baseAddr = (DWORD)mEntry.modBaseAddr;
	else
		return false;

	//Load PE information from memory
	SIZE_T bytesRead;
	ReadProcessMemory(handle, (LPCVOID)baseAddr, dos_header, sizeof(IMAGE_DOS_HEADER), &bytesRead);
	IMAGE_DOS_HEADER dos = *dos_header;

	ReadProcessMemory(handle, (LPCVOID)(baseAddr + dos.e_lfanew), nt_header, sizeof(IMAGE_NT_HEADERS), &bytesRead);
	IMAGE_NT_HEADERS nt = *nt_header;

	IMAGE_SECTION_HEADER *sections = new IMAGE_SECTION_HEADER[nt.FileHeader.NumberOfSections];
	for(unsigned int i = 0; i < nt.FileHeader.NumberOfSections; i++)
	{
		ReadProcessMemory(handle, (LPCVOID)(baseAddr + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i)), &sections[i], sizeof(IMAGE_SECTION_HEADER), &bytesRead);
		//ReadProcessMemory(handle, (LPCVOID)(baseAddr + dos.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i)), &sections[i], sizeof(IMAGE_SECTION_HEADER), &bytesRead);
	}

	//Load PE information from file

	HANDLE hFile = CreateFile(mEntry.szExePath, GENERIC_READ, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == NULL)
		return false;

	DWORD fSize = GetFileSize(hFile, 0);
	HANDLE hMap = CreateFileMapping(hFile, 0, PAGE_READONLY, 0, fSize, 0);
	if(hMap == NULL)
		return false;

	DWORD mappedFile = (DWORD)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, fSize);
	if(mappedFile == 0)
		return false;

	IMAGE_DOS_HEADER *dos_header2 = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
	IMAGE_NT_HEADERS *nt_header2= (IMAGE_NT_HEADERS*)malloc(sizeof(IMAGE_NT_HEADERS));

	memcpy(dos_header2, (void*)mappedFile, sizeof(IMAGE_DOS_HEADER));
	IMAGE_DOS_HEADER dos2 = *dos_header2;
	memcpy(nt_header2, (void*)(mappedFile + dos2.e_lfanew), sizeof(IMAGE_NT_HEADERS));
	IMAGE_NT_HEADERS nt2 = *nt_header2;

	IMAGE_SECTION_HEADER *sections2 = new IMAGE_SECTION_HEADER[nt2.FileHeader.NumberOfSections];
	for(unsigned int i = 0; i < nt2.FileHeader.NumberOfSections; i++)
	{
		LPVOID section[sizeof(IMAGE_SECTION_HEADER)];
		memcpy(section, (void*)(mappedFile + dos2.e_lfanew + sizeof(IMAGE_NT_HEADERS) + (sizeof(IMAGE_SECTION_HEADER) * i)), sizeof(IMAGE_SECTION_HEADER));
		memcpy((void*)&sections2[i], section, sizeof(IMAGE_SECTION_HEADER));
	}

	//Compares the information

	if(nt.FileHeader.NumberOfSections != nt2.FileHeader.NumberOfSections)
	{
		free(dos_header);
		free(dos_header2);
		free(nt_header);
		free(nt_header2);
		CloseHandle(snapshot);
		CloseHandle(handle);
		CloseHandle(hFile);
		CloseHandle(hMap);
		return true;
	}

	for(unsigned int i = 0; i < nt2.FileHeader.NumberOfSections; i++)
	{
		if(sections[i].SizeOfRawData != sections2[i].SizeOfRawData)
		{
			free(dos_header);
			free(dos_header2);
			free(nt_header);
			free(nt_header2);
			CloseHandle(snapshot);
			CloseHandle(handle);
			CloseHandle(hFile);
			CloseHandle(hMap);
			return true;
		}
	}
	free(dos_header);
	free(dos_header2);
	free(nt_header);
	free(nt_header2);
	CloseHandle(snapshot);
	CloseHandle(handle);
	CloseHandle(hFile);
	CloseHandle(hMap);
	return false;
}