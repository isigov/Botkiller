#include "stdafx.h"
#include "Botkiller.h"
#include "Injection.h"
#include "TcpConnections.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <WinSock2.h>
#include <ntstatus.h>
#include <Wtsapi32.h>
#include <WinCrypt.h>

using namespace std;

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Psapi.lib")

WCHAR* wordTostr(DWORD word);
void GetDebugPrivileges();
bool IsProcessSystem(DWORD pid);
HANDLE startConsole();
void WriteToConsole(HANDLE stdOut, WCHAR* output);
vector<MIB_TCPROW_OWNER_PID> GetTcpConnectionsForPID(DWORD pid);
WCHAR* CharToW(char* input);
char* WcharToC(WCHAR* input);
DWORD blacklistedConnection(char* ip, u_short port);
void TerminateProc(DWORD pid, WCHAR* pName);
void CleanRegistry(WCHAR* pName);
void RetrieveSystemHandles(HANDLE console);
int ScanProcessMemory(DWORD pid, HANDLE stdOut);
int	iFind(char *buffer, int bufferSize, char *match, int iMatchLen);
char* find(char *buffer, int bufferSize, char *match, int iMatchLen);
int CheckProcessPages(HANDLE hProcess, LPVOID Address);
int CheckDrivers(HANDLE stdOut);

#define MAX_NAME 256
#define MAX_VALUE_NAME 16383
#define SYSTEM_HANDLE_INFORMATION_WORD 16
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

const DWORD dwSigsASCII = 4;
const DWORD dwSigsUnicode = 1;
const DWORD CONNECTION_IS_SUICIDE = 10;
const DWORD CONNECTION_IS_DANGEROUS = 20;
const DWORD CONNECTION_IS_HAZARDOUS = 30;
const DWORD CONNECTION_IS_SAFE = 40;

typedef NTSTATUS (NTAPI *pNtQuerySystemInformation)(IN DWORD info_class, OUT LPVOID out, IN DWORD size, OUT PDWORD out_size);
typedef NTSTATUS (NTAPI *pZwQuerySystemInformation)(IN DWORD info_class, OUT LPVOID out, IN DWORD size, OUT PDWORD out_size);
typedef NTSTATUS (NTAPI *pNtLockVirtualMemory)(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN OUT PULONG NumberOfBytesToLock, IN ULONG LockOption);

typedef NTSTATUS (NTAPI *pNtDuplicateObject)(
  IN HANDLE               SourceProcessHandle,
  IN HANDLE              SourceHandle,
  IN HANDLE               TargetProcessHandle,
  OUT PHANDLE             TargetHandle,
  IN ACCESS_MASK          DesiredAccess OPTIONAL,
  IN ULONG              InheritHandle,
  IN ULONG                Options);

typedef NTSTATUS (NTAPI *pNtQueryObject)(  
  IN HANDLE               ObjectHandle,
  IN DWORD ObjectInformationClass,
  OUT PVOID               ObjectInformation,
  IN ULONG                Length,
  OUT PULONG              ResultLength);

typedef struct _CLIENT_ID
{
     PVOID UniqueProcess;
     PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef NTSTATUS (NTAPI *pNtOpenProcess)(OUT PHANDLE, IN ACCESS_MASK, IN PVOID, IN PVOID);
typedef NTSTATUS (NTAPI *pNtTerminateProcess)(IN HANDLE, OUT NTSTATUS);

typedef struct _SYSTEM_HANDLE_ENTRY {
     ULONG  OwnerPid;
     BYTE   ObjectType;
     BYTE   HandleFlags;
     USHORT HandleValue;
     PVOID  ObjectPointer;
     ULONG  AccessMask;
 } SYSTEM_HANDLE_ENTRY, *PSYSTEM_HANDLE_ENTRY;

typedef struct _UNICODE_STRING {
    USHORT Length;        /* bytes */
    USHORT MaximumLength; /* bytes */
    PWSTR  Buffer;
  } UNICODE_STRING, *PUNICODE_STRING;

 typedef struct _SYSTEM_HANDLE_INFORMATION {
     ULONG               Count;
     SYSTEM_HANDLE_ENTRY Handle[1];
 } SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

 typedef struct _OBJECT_NAME_INFORMATION {

  _UNICODE_STRING                   NameBuffer;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

 typedef enum _POOL_TYPE {
  NonPagedPool                    = 0,
  PagedPool                       = 1,
  NonPagedPoolMustSucceed         = 2,
  DontUseThisType                 = 3,
  NonPagedPoolCacheAligned        = 4,
  PagedPoolCacheAligned           = 5,
  NonPagedPoolCacheAlignedMustS   = 6 
} POOL_TYPE;

 typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

 typedef struct _OBJECT_TYPE_INFORMATION {
  UNICODE_STRING          TypeName;
  ULONG                   TotalNumberOfHandles;
  ULONG                   TotalNumberOfObjects;
  WCHAR                   Unused1[8];
  ULONG                   HighWaterNumberOfHandles;
  ULONG                   HighWaterNumberOfObjects;
  WCHAR                   Unused2[8];
  ACCESS_MASK             InvalidAttributes;
  GENERIC_MAPPING         GenericMapping;
  ACCESS_MASK             ValidAttributes;
  BOOLEAN                 SecurityRequired;
  BOOLEAN                 MaintainHandleCount;
  USHORT                  MaintainTypeList;
  POOL_TYPE               PoolType;
  ULONG                   DefaultPagedPoolCharge;
  ULONG                   DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef LONG    KPRIORITY;



typedef struct _VM_COUNTERS {
    SIZE_T        PeakVirtualSize;
    SIZE_T        VirtualSize;
    ULONG        PageFaultCount;
    SIZE_T        PeakWorkingSetSize;
    SIZE_T        WorkingSetSize;
    SIZE_T        QuotaPeakPagedPoolUsage;
    SIZE_T        QuotaPagedPoolUsage;
    SIZE_T        QuotaPeakNonPagedPoolUsage;
    SIZE_T        QuotaNonPagedPoolUsage;
    SIZE_T        PagefileUsage;
    SIZE_T        PeakPagefileUsage;
} VM_COUNTERS;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	KPRIORITY BasePriority;
	ULONG ContextSwitchCount;
	LONG State;
	LONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryDelta;
	ULONG ThreadCount;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromProcessId;
	ULONG HandleCount;
	ULONG Reserved2[2];
	VM_COUNTERS VmCounters;
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct SYSTEM_MODULE {
    ULONG Reserved[2];
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT Index;
    USHORT Unknow;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    char ImageName[256];    
};


typedef struct _SYSTEM_MODULE_INFORMATION {
  ULONG                ModulesCount;
  SYSTEM_MODULE        Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

BOOL debugMode = true;

int main()
{	
	HANDLE console;
	if(debugMode)
	{
		console = startConsole();
		WriteToConsole(console, L"[+] Initalizing Terminator++...\n\n");
	}
	else
	{
		ShowWindow(GetConsoleWindow(), SW_HIDE);
		FreeConsole();
	}
	GetDebugPrivileges();
	MessageBox(NULL, L"pause", NULL, NULL);
	pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
	int status = NtQuerySystemInformation(NULL, NULL, NULL, NULL);
	if(status == 0x12345)
		MessageBox(NULL, L"YAY ME!", NULL, NULL);
	else
		MessageBox(NULL, wordTostr(status), NULL, NULL);
	TerminateProc(5972, NULL);
	HANDLE hMutex;
	if(OpenMutex(MUTEX_ALL_ACCESS, false, L"Terminator++") != NULL)
	{
		WriteToConsole(console, L"[-] Another instance of Terminator++ is running. Exiting...\n\n");
		return 0;
	}
	else
	{
		hMutex = CreateMutex(NULL, false, L"Terminator++");
	}
	WriteToConsole(console, L"[+] Scanning for potential rootkits...\n");
	CheckDrivers(console);
	WriteToConsole(console, L"[+] Checking processes...\n\n");
	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(PROCESSENTRY32);
	BOOL working = true;
	WCHAR pFileName[MAX_PATH];
	if(Process32FirstW(handle, &pEntry))
	{
			if(!IsProcessSystem(pEntry.th32ProcessID))
			{
				BOOL doing = true;
				wsprintf(pFileName, L"[+] Checking Process \"%s\"...\n", pEntry.szExeFile);
				WriteToConsole(console, pFileName);
				while(working)
				{
					if(doing && ScanProcessMemory(pEntry.th32ProcessID, console) == 0)
					{
						HANDLE mod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pEntry.th32ProcessID);
						MODULEENTRY32 mEntry;
						mEntry.dwSize = sizeof(MODULEENTRY32);
						Module32First(mod, &mEntry);
						WCHAR* fileName = mEntry.szExePath;
						if(Injection(pEntry.th32ProcessID))
						{
							wsprintf(pFileName, L"[-] Process \"%s\" has been PE spoofed (RunPE)!\n[+] Attemping to terminate process \"%s\"...\n", pEntry.szExeFile, pEntry.szExeFile);
							WriteToConsole(console, pFileName);
							TerminateProc(pEntry.th32ProcessID, pEntry.szExeFile);
							wsprintf(pFileName, L"[+] Termination signal sent to process \"%s\"!\n", pEntry.szExeFile);
							WriteToConsole(console, pFileName);
							wsprintf(pFileName, L"[+] Successfully removed process \"%s\" from the registry!\n", pEntry.szExeFile);
							WriteToConsole(console, pFileName);
							CleanRegistry(fileName);
						}
						else
						{
							wsprintf(pFileName, L"[+] Process \"%s\" is clear of PE spoofers.\n", pEntry.szExeFile);
							WriteToConsole(console, pFileName);
							wsprintf(pFileName, L"[+] Checking process \"%s\" for thread hijacking...\n", pEntry.szExeFile);
							WriteToConsole(console, pFileName);
							int iAmount = 0;
							if(iAmount > 0)
							{
								wsprintf(pFileName, L"[-] Process \"%s\" has %d hijacked threads.\n", pEntry.szExeFile, iAmount);
								WriteToConsole(console, pFileName);
								TerminateProc(pEntry.th32ProcessID, pEntry.szExeFile);
								wsprintf(pFileName, L"[+] Termination signical sent to process \"%s\"!\n", pEntry.szExeFile);
								WriteToConsole(console, pFileName);
								CleanRegistry(fileName);
								wsprintf(pFileName, L"[+] Successfully removed process \"%s\" from the registry!\n", pEntry.szExeFile);
								WriteToConsole(console, pFileName);
							}
							else
							{
							wsprintf(pFileName, L"[+] Checking Process \"%s\" active TCP connections...\n", pEntry.szExeFile);
							WriteToConsole(console, pFileName);
							vector<MIB_TCPROW_OWNER_PID> rows = GetTcpConnectionsForPID(pEntry.th32ProcessID);
							if(rows.size() == 0)
							{
								wsprintf(pFileName, L"[+] Process \"%s\" does not have any active TCP connections\n", pEntry.szExeFile);
								WriteToConsole(console, pFileName);
							}
							else
							{
							
								for(unsigned int i = 0; i < rows.size(); i++)
								{
									in_addr addr, addr2;
									addr.s_addr = rows[i].dwLocalAddr;
									addr2.s_addr = rows[i].dwRemoteAddr;
									wsprintf(pFileName, L"[+] Connection #%d: Source: %s:%d Destination: %s:%d\n", i + 1, CharToW(inet_ntoa(addr)), htons(rows[i].dwLocalPort), CharToW(inet_ntoa(addr2)), htons(rows[i].dwRemotePort));
									WriteToConsole(console, pFileName);
									if(blacklistedConnection(NULL, htons(rows[i].dwRemotePort)) == 1)
									{
										wsprintf(pFileName, L"[-] Detected Connection #%d as malicious!\n[+] Attempting to close connection and terminate process \"%s\"...\n", i, pEntry.szExeFile);
										WriteToConsole(console, pFileName);
										if(CloseConnection(rows[i]) == 0)
										{
											wsprintf(pFileName, L"[+] Successfully closed Connection #%d!\n[+] Attempting to terminate process \"%s\"...\n", i, pEntry.szExeFile);
											WriteToConsole(console, pFileName);
										}
										else
										{
											wsprintf(pFileName, L"[-] Unable to close the Connection #%d!\n[+] Attempting to terminate process \"%s\"...\n", i, pEntry.szExeFile);
											WriteToConsole(console, pFileName);
										}
										TerminateProc(pEntry.th32ProcessID, pEntry.szExeFile);
										wsprintf(pFileName, L"[+] Termination signical sent to process \"%s\"!\n", pEntry.szExeFile);
										WriteToConsole(console, pFileName);
										CleanRegistry(fileName);
										wsprintf(pFileName, L"[+] Successfully removed process \"%s\" from the registry!\n", pEntry.szExeFile);
										WriteToConsole(console, pFileName);
										break;
									}
								}
							}
						}
						}
						wsprintf(pFileName, L"\n\n");
						WriteToConsole(console, pFileName);
					}
					working = Process32NextW(handle, &pEntry);
					if(working)
					{
							if(pEntry.th32ProcessID == GetCurrentProcessId()) //Skip our process
							{
								doing = false;
							}
							else
							{
								wsprintf(pFileName, L"[+] Checking Process \"%s\"...\n", pEntry.szExeFile);
								WriteToConsole(console, pFileName);
								if(!IsProcessSystem(pEntry.th32ProcessID))
								{
									wsprintf(pFileName, L"[+] Opened Process \"%s\"!\n", pEntry.szExeFile);
									WriteToConsole(console, pFileName);
									doing = true;
								}
								else
								{
									wsprintf(pFileName, L"[-] Error: Process \"%s\" is a system process!\n\n", pEntry.szExeFile);
									WriteToConsole(console, pFileName);
									doing = false;
								}
							}
					}
				}
			}
	}
	system("PAUSE");
	ReleaseMutex(hMutex);
}

WCHAR* wordTostr(DWORD word)
{
	WCHAR* dest = new WCHAR[500];
	swprintf_s(dest, 500, L"%d", word);
	return dest;
}

void GetDebugPrivileges()
{
	HANDLE hToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
	LUID debugValue;
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &debugValue);
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = debugValue;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	AdjustTokenPrivileges(hToken, false, &tp, sizeof(tp), NULL, NULL);
	CloseHandle(hToken);
}

bool IsProcessSystem(DWORD pid)
{
	if(pid == 0)
		return false; //We want to skip SYSTEM_IDLE_PROCESS
	HANDLE handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
	HANDLE hToken;
	SID_NAME_USE type;
	PTOKEN_USER sid;
	DWORD retLen = 0;
	char lpName[MAX_NAME];
	char lpDomain[MAX_NAME];
	DWORD dwSize = MAX_NAME;

	if(!OpenProcessToken(handle, TOKEN_QUERY, &hToken))
	{
		CloseHandle(handle);
		return true;
	}
	GetTokenInformation(hToken, TokenUser, NULL, retLen, &retLen);
	sid = (PTOKEN_USER)malloc(retLen);
	if(!GetTokenInformation(hToken, TokenUser, sid, retLen, &retLen))
	{
		free(sid);
		CloseHandle(handle);
		CloseHandle(hToken);
		return true;
	}
	if(!LookupAccountSid(NULL, sid->User.Sid, (LPWSTR)lpName, &dwSize, (LPWSTR)lpDomain, &dwSize, &type))
	{
		free(sid);
		CloseHandle(handle);
		CloseHandle(hToken);
		return true;
	}

	char lpUserName[MAX_NAME];
	DWORD dwUserName = sizeof(lpUserName);
	GetUserNameA(lpUserName, &dwUserName);
	
	if(strcmp(WcharToC((WCHAR*)lpName), lpUserName))
	{
		free(sid);
		CloseHandle(handle);
		CloseHandle(hToken);
		return true;
	}
	else
	{
		free(sid);
		CloseHandle(handle);
		CloseHandle(hToken);
		return false;
	}
}

HANDLE startConsole()
{
	AllocConsole();
	SetConsoleTitle(L"Terminator++: Debug Mode");
	HANDLE stdOut = GetStdHandle(STD_OUTPUT_HANDLE);
	COORD location = {80, 25};
	SetConsoleScreenBufferSize(stdOut, location);
	return stdOut;
}

void WriteToConsole(HANDLE stdOut, WCHAR* output)
{
	if(debugMode && stdOut != NULL)
	{
		DWORD written;
		WriteConsole(stdOut, (void*)output, lstrlenW(output), &written, NULL);
	}
}

vector<MIB_TCPROW_OWNER_PID> GetTcpConnectionsForPID(DWORD pid)
{
	vector<MIB_TCPROW_OWNER_PID> Allrows = GetTcpConnections();
	vector<MIB_TCPROW_OWNER_PID> PIDrows;
	for(unsigned int i = 0; i < Allrows.size(); i++)
	{
		if(Allrows[i].dwOwningPid == pid)
			PIDrows.push_back(Allrows[i]);
	}
	return PIDrows;
}

WCHAR* CharToW(char* input)
{
	size_t origsize = strlen(input) + 1;
    const size_t newsize = MAX_NAME;
    size_t convertedChars = 0;
    wchar_t* wcstring = new wchar_t[newsize];
    mbstowcs_s(&convertedChars, wcstring, origsize, input, _TRUNCATE);
	return wcstring;
}

char* WcharToC(WCHAR* input)
{
	size_t origsize = wcslen(input) + 1;
    const size_t newsize = MAX_NAME;
    size_t convertedChars = 0;
    char* nstring = new char[newsize];
    wcstombs_s(&convertedChars, nstring, origsize, input, _TRUNCATE);
	return nstring;
}

DWORD blacklistedConnection(char* ip, u_short port)
{
	DWORD connection_status = 40;
	switch(port)
	{
	case 21:
		//FTP traffic port
		connection_status = CONNECTION_IS_HAZARDOUS;
		break;
	case 80:
		//Web traffic port
		connection_status = CONNECTION_IS_SAFE;
		break;
	case 6667:
		//Default IRC port
		connection_status = CONNECTION_IS_DANGEROUS;
		break;
	}

	if(connection_status <= 20)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

void TerminateProc(DWORD pid, WCHAR* pName)
{
	HMODULE ntdll = LoadLibraryA("ntdll.dll");
	pNtOpenProcess NtOpenProcess = (pNtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
	pNtTerminateProcess NtTerminateProcess = (pNtTerminateProcess)GetProcAddress(ntdll, "NtTerminateProcess");

	CLIENT_ID CID;
	CID.UniqueProcess = (PVOID)pid;
	CID.UniqueThread = 0;
	HANDLE hProcess;
	OBJECT_ATTRIBUTES attr = { NULL };

	NtOpenProcess(&hProcess, PROCESS_TERMINATE, &attr, &CID);
	if(hProcess != NULL)
		NtTerminateProcess(hProcess, STATUS_SUCCESS);
	/*HANDLE handle = OpenProcess(PROCESS_TERMINATE, false, pid);
	TerminateProcess(handle, 0);*/
	CloseHandle(hProcess);
}

void CleanRegistry(WCHAR* pName)
{
	HKEY hKey;
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Active Setup\\Installed Components"), 0, KEY_ALL_ACCESS, &hKey);
	if(hKey != NULL)
	{
		TCHAR szName[MAX_VALUE_NAME];
		DWORD szLen = MAX_VALUE_NAME;
		FILETIME time;
		DWORD index = 0;
		while(RegEnumKeyEx(hKey, index, szName, &szLen, NULL, NULL, NULL, &time) == ERROR_SUCCESS)
		{
			MessageBox(NULL, szName, TEXT(""), NULL);
			index++;
			szLen = MAX_VALUE_NAME;

			HKEY subKey;
			RegOpenKeyEx(hKey, szName, 0, KEY_ALL_ACCESS, &subKey);
			TCHAR szName2[MAX_VALUE_NAME];
			DWORD szLen2 = MAX_VALUE_NAME;
			DWORD index2 = 0;
			BYTE* data = (BYTE*)malloc(MAX_VALUE_NAME);
			DWORD dataLen = MAX_VALUE_NAME;
			while(RegEnumValue(subKey, index2, szName2, &szLen2, NULL, NULL, data, &dataLen) == ERROR_SUCCESS)
			{
				if(!strcmp(WcharToC(szName2), "StubPath") && !lstrcmpW((TCHAR*)data, pName))
				{
					RegDeleteValue(subKey, L"StubPath");
				}
				index2++;
				szLen2 = MAX_VALUE_NAME;
				dataLen = MAX_VALUE_NAME;
				szName2[0] = '\0';
			}

		}
	}
	RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_ALL_ACCESS, &hKey);
	if(hKey != NULL)
	{

			TCHAR szName2[MAX_VALUE_NAME];
			DWORD szLen2 = MAX_VALUE_NAME;
			DWORD index2 = 0;
			BYTE* data = (BYTE*)malloc(MAX_VALUE_NAME);
			DWORD dataLen = MAX_VALUE_NAME;
			while(RegEnumValue(hKey, index2, szName2, &szLen2, NULL, NULL, data, &dataLen) == ERROR_SUCCESS)
			{
				if(!lstrcmpW((TCHAR*)data, pName))
				{
					RegDeleteValue(hKey, szName2);
				}
				index2++;
				szLen2 = MAX_VALUE_NAME;
				dataLen = MAX_VALUE_NAME;
				szName2[0] = '\0';
			}
	}
	RegOpenKeyEx(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), 0, KEY_ALL_ACCESS, &hKey);
	if(hKey != NULL)
	{

			TCHAR szName2[MAX_VALUE_NAME];
			DWORD szLen2 = MAX_VALUE_NAME;
			DWORD index2 = 0;
			BYTE* data = (BYTE*)malloc(MAX_VALUE_NAME);
			DWORD dataLen = MAX_VALUE_NAME;
			while(RegEnumValue(hKey, index2, szName2, &szLen2, NULL, NULL, data, &dataLen) == ERROR_SUCCESS)
			{
				if(!lstrcmpW((TCHAR*)data, pName))
				{
					RegDeleteValue(hKey, szName2);
				}
				index2++;
				szLen2 = MAX_VALUE_NAME;
				dataLen = MAX_VALUE_NAME;
				szName2[0] = '\0';
			}
	}
}

void RetrieveSystemHandles(HANDLE console)
{
	HMODULE ntdll = LoadLibrary(L"ntdll.dll");
	pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	pNtDuplicateObject NtDuplicateObject = (pNtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
	pNtQueryObject NtQueryObject = (pNtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	ULONG len = sizeof(_SYSTEM_HANDLE_INFORMATION);
	_SYSTEM_HANDLE_INFORMATION* buffer;
	while(status == STATUS_INFO_LENGTH_MISMATCH)
	{
		buffer = (_SYSTEM_HANDLE_INFORMATION*)malloc(len);
		status = NtQuerySystemInformation(16, buffer, len, NULL);
		if(status == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(buffer);
			len *= 2;
		}
		else
		{
			break;
		}
	}
	DWORD handleCount = buffer->Count;
	for(unsigned int i = 0; i < handleCount; i++)
	{
		HANDLE inHandle;
		DWORD pid = buffer->Handle[i].OwnerPid;
		HANDLE outHandle = (HANDLE)buffer->Handle[i].HandleValue;
		HANDLE processHandle = OpenProcess(PROCESS_DUP_HANDLE, false, pid);
		status = NtDuplicateObject(processHandle, outHandle, GetCurrentProcess(), &inHandle, 0, 0, DUPLICATE_SAME_ACCESS);
		if(status == STATUS_SUCCESS)
		{
			POBJECT_NAME_INFORMATION info = 0;
			POBJECT_TYPE_INFORMATION typeInfo = 0;
			DWORD len = 0;

			//Query the handle name (if any)
			status = NtQueryObject(inHandle, 1, 0, 0, &len);
			info = (POBJECT_NAME_INFORMATION)malloc(len);
			status = NtQueryObject(inHandle, 1, info, len, &len);

			if(status == STATUS_SUCCESS)
			{
				//Query the handle type
				status = NtQueryObject(inHandle, 2, 0, 0, &len);
				typeInfo = (POBJECT_TYPE_INFORMATION)malloc(len);
				status = NtQueryObject(inHandle, 2, typeInfo, len, &len);
				if(status == STATUS_SUCCESS && wcsstr(typeInfo->TypeName.Buffer, L"Mutant") && lstrlenW(info->NameBuffer.Buffer) > 0) //List Mutexes
				{
					LPWSTR lpMutexName = info->NameBuffer.Buffer;
					lpMutexName = lpMutexName + 18; //Skipping \BaseNamedObjects\ :D
					WCHAR* pFileName = new WCHAR[MAX_NAME];
					wsprintf(pFileName, L"%s\n", lpMutexName);
					//WriteToConsole(console, pFileName);
					//system("PAUSE");
					
				}
				else if(wcsstr(typeInfo->TypeName.Buffer, L"File"))
				{
					WCHAR* pFileName = new WCHAR[MAX_NAME];
					wsprintf(pFileName, L"File: %s\n", info->NameBuffer.Buffer);
					WriteToConsole(console, pFileName);
					system("PAUSE");
				}
			}
		}
	}
}

int ScanProcessMemory(DWORD pid, HANDLE stdOut)
{
	char* stringsA[dwSigsASCII];
	stringsA[0] = "C:\\Users\\Mike\\Desktop\\Blackshades"; //Blackshades ASCII
	stringsA[1] = "system64.exe"; //Albertino RAT ASCII
	stringsA[2] = "get_RTFirefox"; //iRtehLeet Stealer ASCII
	stringsA[3] = "D:\\turkojan4\\completed\\Server\\Kol.pas"; //Turkojan ASCII

	char* namesA[dwSigsASCII];
	namesA[0] = "Blackshades";
	namesA[1] = "Albertino RAT";
	namesA[2] = "iRtehLeet Stealer";
	namesA[3] = "Turkojan 4";

	char* stringsW[dwSigsUnicode];
	stringsW[0] = "5bhj432t5jbbfsdajfbsdhasbfjadbfj";

	char* namesW[dwSigsUnicode];
	namesW[0] = "y7356y56g365g3frgstrhtrghr5y65";

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if(hProcess == NULL)
		return 0;

	SYSTEM_INFO si = { 0 };
	GetSystemInfo(&si);
	LPVOID currentAddress = 0;

	HMODULE ntdll = LoadLibrary(L"ntdll.dll");
	pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
	/*char* dllPath = "C:\\NewDLL.dll";
	LPVOID pointer = VirtualAllocEx(hProcess, NULL, strlen(dllPath) * sizeof(char), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProcess, pointer, dllPath, strlen(dllPath) * sizeof(char), NULL);
	LPVOID address = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	DWORD threadID = 0;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)address, pointer, NULL, &threadID);*/

	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	ULONG len = sizeof(PSYSTEM_PROCESS_INFORMATION);
	PSYSTEM_PROCESS_INFORMATION buffer;
	while(status == STATUS_INFO_LENGTH_MISMATCH)
	{
		buffer = (PSYSTEM_PROCESS_INFORMATION)malloc(len);

		status = NtQuerySystemInformation(5, buffer, len, NULL);
		if(status == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(buffer);
			len *= 2;
		}
		else
		{
			break;
		}
	}
	while(1)
	{
		if(buffer->ProcessId == pid)
		{
			for(unsigned int i = 0; i < buffer->ThreadCount; i++)
			{
					if(CheckProcessPages(hProcess, buffer->Threads[i].StartAddress) > 0)
					{
						CloseHandle(hProcess);
						WCHAR* pFileName = new WCHAR[500];
						HANDLE mod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
						MODULEENTRY32 mEntry;
						mEntry.dwSize = sizeof(MODULEENTRY32);
						Module32First(mod, &mEntry);
						WriteToConsole(stdOut, L"[-] Process has a malicous thread running!\n[+] Attempting to terminate process...\n");
						TerminateProc(pid, mEntry.szExePath);
						wsprintf(pFileName, L"[+] Termination signical sent to process \"%s\"!\n", mEntry.szModule);
						WriteToConsole(stdOut, pFileName);
						CleanRegistry(mEntry.szExePath);
						wsprintf(pFileName, L"[+] Successfully removed process \"%s\" from the registry!\n", mEntry.szModule);
						WriteToConsole(stdOut, pFileName);
						CloseHandle(mod);
						system("PAUSE");
						return 1;
					}
			}
			break;
		}
		else
		{
			buffer = (PSYSTEM_PROCESS_INFORMATION)(((ULONG)buffer) + buffer->NextEntryDelta);
		}
	}
	while(currentAddress < si.lpMaximumApplicationAddress)
	{
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		VirtualQueryEx(hProcess, currentAddress, &mbi, sizeof(mbi));
		DWORD iUnReadable = 0;
		iUnReadable |= (mbi.State == MEM_FREE);
		iUnReadable |= (mbi.State == MEM_RESERVE);
		iUnReadable |= (mbi.Protect & PAGE_WRITECOPY);
		iUnReadable |= (mbi.Protect & PAGE_EXECUTE);
		iUnReadable |= (mbi.Protect & PAGE_GUARD);
		iUnReadable |= (mbi.Protect & PAGE_NOACCESS);
		if(!iUnReadable)
		{
			DWORD bufferSize = 30000;
			if(mbi.RegionSize > bufferSize)
			{
				DWORD loop = 0, offset = 0, extra = 0, bytesToRead = mbi.RegionSize;
				while(1)
				{
					if(bytesToRead < bufferSize)
					{
						extra = bytesToRead;
						offset = (loop * bufferSize) + extra;
					}
					else
					{
						loop++;
						offset = (loop * bufferSize);
					}

					LPVOID buffer;
					if(extra == 0)
					{
						buffer = malloc(bufferSize);
						ReadProcessMemory(hProcess, (LPVOID)((DWORD)mbi.BaseAddress + offset), buffer, bufferSize, 0);
						for(unsigned int i = 0; i < dwSigsASCII; i++)
						{
							unsigned short szConverted[180];
							strcpy((char*)szConverted, stringsA[i]);
							int sLen = strlen(stringsA[i]);
							if(iFind((char*)buffer, bufferSize, (char*)szConverted, sLen) > 0)
							{
								WCHAR* pFileName = new WCHAR[MAX_NAME];
								wsprintf(pFileName, L"[-] Found signature for %s at: 0x%x\n", CharToW(namesA[i]), (DWORD)mbi.BaseAddress + offset);
								WriteToConsole(stdOut, pFileName);
								system("PAUSE");
							}
						}
						/*for(unsigned int i = 0; i < dwSigsUnicode; i++)
						{
							unsigned short szConverted[180];
							int sLen = strlen(stringsW[i]);
							mbstowcs((WCHAR*)szConverted, stringsW[i], 180);
							sLen *= sizeof(WCHAR);
							if(iFind((char*)buffer, bufferSize, (char*)szConverted, sLen) > 0)
							{
								WCHAR* pFileName = new WCHAR[MAX_NAME];
								wsprintf(pFileName, L"[-] Found signature for %s at: 0x%x\n", CharToW(namesW[i]), (DWORD)mbi.BaseAddress + offset);
								WriteToConsole(stdOut, pFileName);
								system("PAUSE");
							}
						}*/
						free(buffer);
						bytesToRead -= bufferSize;
						if(bytesToRead <= 0)
							break;
					}
					else
					{
						buffer = malloc(extra);
						ReadProcessMemory(hProcess, (LPVOID)((DWORD)mbi.BaseAddress + offset), buffer, extra, 0);
						for(unsigned int i = 0; i < dwSigsASCII; i++)
						{
							unsigned short szConverted[180];
							strcpy((char*)szConverted, stringsA[i]);
							int sLen = strlen(stringsA[i]);
							if(iFind((char*)buffer, extra, (char*)szConverted, sLen) > 0)
							{
								WCHAR* pFileName = new WCHAR[MAX_NAME];
								wsprintf(pFileName, L"[-] Found signature for %s at: 0x%x\n", CharToW(namesA[i]), (DWORD)mbi.BaseAddress + offset);
								WriteToConsole(stdOut, pFileName);
								system("PAUSE");
							}
						}
						/*for(unsigned int i = 0; i < dwSigsUnicode; i++)
						{
							unsigned short szConverted[180];
							int sLen = strlen(stringsW[i]);
							mbstowcs((WCHAR*)szConverted, stringsW[i], 180);
							sLen *= sizeof(WCHAR);
							if(iFind((char*)buffer, extra, (char*)szConverted, sLen) > 0)
							{
								WCHAR* pFileName = new WCHAR[MAX_NAME];
								wsprintf(pFileName, L"[-] Found signature for %s at: 0x%x\n", CharToW(namesW[i]), (DWORD)mbi.BaseAddress + offset);
								WriteToConsole(stdOut, pFileName);
								system("PAUSE");
							}
						}*/
						free(buffer);
						bytesToRead -= extra;
						break;
					}
				}
			}
		}
		currentAddress = (LPVOID)((DWORD)mbi.BaseAddress + (DWORD)mbi.RegionSize);
	}
	CloseHandle(hProcess);
	return 0;
}
int	iFind(char *buffer, int bufferSize, char *match, int iMatchLen)
{
	char *sptr = find(buffer, bufferSize, match, iMatchLen);
	if(sptr)
		return (sptr - buffer);
	return -1;
}

char *find(char *buffer, int bufferSize, char *match, int iMatchLen)
{
	char	*sptr0, *sptr1;
	char	*mptr0, *mptr1;
	int	pos, mpos, matchSize, length;

	if(bufferSize <= 0) return NULL;
	if(buffer == NULL) return NULL;
   if(match == NULL) return NULL;
	pos = 0;
	sptr0 = buffer;
	mptr0 = match;
	matchSize = iMatchLen;
	while(pos < bufferSize)
	{
		if(*sptr0 == *mptr0)
		{
			mpos = 1;
			sptr1 = sptr0 + 1;
			mptr1 = mptr0 + 1;
			length = matchSize;
			if((bufferSize - pos) < matchSize) return NULL;
			while(--length > 0)
			{
				if(*sptr1++ != *mptr1++) break;
			}
			if(length == 0) return sptr0;
		}
		++pos;
		++sptr0;
	}
	return NULL;
}

int CheckProcessPages(HANDLE hProcess, LPVOID Address)
{
	if(hProcess == NULL)
		return 0;
	SYSTEM_INFO sysInfo = { 0 };
	GetSystemInfo(&sysInfo);
	DWORD currentAddress = 0;
	while(currentAddress < (DWORD)sysInfo.lpMaximumApplicationAddress)
	{
		MEMORY_BASIC_INFORMATION memInfo = { 0 };
		if(!VirtualQueryEx(hProcess, (LPVOID)currentAddress, &memInfo, sizeof(memInfo)))
			return 0;
		if((DWORD)memInfo.BaseAddress == (DWORD)Address)
		{
			IMAGE_DOS_HEADER *dos_header = (IMAGE_DOS_HEADER*)malloc(sizeof(IMAGE_DOS_HEADER));
			if(ReadProcessMemory(hProcess, memInfo.BaseAddress, dos_header, sizeof(IMAGE_DOS_HEADER), NULL) && dos_header->e_magic == 23117)
				return 1;
		}
		currentAddress = (DWORD)memInfo.BaseAddress + memInfo.RegionSize;
	}
	return 0;
}

int CheckDrivers(HANDLE stdOut)
{
	HMODULE ntdll = LoadLibraryA("ntdll.dll");
	pNtQuerySystemInformation NtQuerySystemInformation = (pNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

	NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
	ULONG len = sizeof(_SYSTEM_MODULE_INFORMATION);
	_SYSTEM_MODULE_INFORMATION* buffer;
	while(status == STATUS_INFO_LENGTH_MISMATCH)
	{
		buffer = (_SYSTEM_MODULE_INFORMATION*)malloc(len);
		status = NtQuerySystemInformation(11, buffer, len, NULL);
		if(status == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(buffer);
			len *= 2;
		}
		else
		{
			break;
		}
	}
	for(unsigned int i = 0; i < buffer->ModulesCount; i++)
	{
		char* driverName = new char[MAX_PATH];
		GetDeviceDriverFileNameA(buffer->Modules[i].Base, driverName, MAX_PATH);
		char* driverFile = new char[MAX_NAME];
		char* Temp = new char[MAX_NAME];
		GetDeviceDriverBaseNameA(buffer->Modules[i].Base, Temp, MAX_NAME);
		for(unsigned int z = 0; z < strlen(Temp); z++)
		{
			if(z == strlen(Temp) - 4)
			{
				driverFile[z] = '\0';
				break;
			}
			else
			{
				driverFile[z] = Temp[z];
			}
		}
		free(Temp);
		//MessageBox(NULL, L"rc 3", NULL, NULL);
		if(strstr(driverName, "\\SystemRoot\\System32\\") && !strstr(driverName, "\\drivers\\") && !strstr(driverName, "\\Drivers\\") && !strstr(driverName, "\\DRIVERS\\"))
		{
			free(driverName);
			driverName = new char[MAX_PATH];
			strcpy(driverName, "C:\\Windows\\System32\\");
			char* cTemp = new char[MAX_NAME];
			GetDeviceDriverBaseNameA(buffer->Modules[i].Base, cTemp, MAX_NAME);
			strcpy(driverName + 20, cTemp);
			free(cTemp);
			cTemp = NULL;
		}
		else if(strstr(driverName, "\\SystemRoot\\"))
		{
			free(driverName);
			driverName = new char[MAX_PATH];
			strcpy(driverName, "C:\\Windows\\System32\\drivers\\");
			char* cTemp = new char[MAX_NAME];
			GetDeviceDriverBaseNameA(buffer->Modules[i].Base, cTemp, MAX_NAME);
			strcpy(driverName + 28, cTemp);
			free(cTemp);
			cTemp = NULL;
		}
		else if(strstr(driverName, "\\WINDOWS\\"))
		{
			free(driverName);
			driverName = new char[MAX_PATH];
			char* cTemp = new char[MAX_NAME];
			GetDeviceDriverBaseNameA(buffer->Modules[i].Base, cTemp, MAX_NAME);
			if(strstr(cTemp, ".sys") || strstr(cTemp, ".SYS"))
			{		
				strcpy(driverName, "C:\\Windows\\System32\\DRIVERS\\");
				strcpy(driverName + 28, cTemp);
			}
			else
			{
				strcpy(driverName, "C:\\Windows\\System32\\");
				strcpy(driverName + 20, cTemp);
			}
			free(cTemp);
			cTemp = NULL;
		}
		else if(!strstr(driverName, "\\"))
		{
			free(driverName);
			driverName = new char[MAX_PATH];
			strcpy(driverName, "C:\\Windows\\System32\\drivers\\");
			char* cTemp = new char[MAX_NAME];
			GetDeviceDriverBaseNameA(buffer->Modules[i].Base, cTemp, MAX_NAME);
			strcpy(driverName + 28, cTemp);
			free(cTemp);
			cTemp = NULL;
		}
		else if(strstr(driverName, "\\C:\\"))
		{
			char* cTemp = new char[MAX_NAME];
			strcpy(cTemp, driverName + 4);
			free(driverName);
			driverName = new char[MAX_PATH];
			strcpy(driverName, cTemp);
			free(cTemp);
			cTemp = NULL;
		}
		if(GetFileAttributesA(driverName) == 0xFFFFFFFF ? true : false)
		{
			SC_HANDLE scHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
			SC_HANDLE hDriver = OpenServiceA(scHandle, driverFile, SERVICE_ALL_ACCESS);
			char* pFileName = new char[200];
			sprintf(pFileName, "[-] Detected a potential rootkit: %s\n[+] Attempting to remove the rootkit...\n", driverName);
			WriteToConsole(stdOut, CharToW(pFileName));
			if(hDriver != NULL)
			{
				SERVICE_STATUS out;
				if(!ControlService(hDriver, SERVICE_CONTROL_STOP, &out))
				{
					sprintf(pFileName, "[-] Failed to remove rootkit %s because Windows is being a bitch!\n", driverName);
					WriteToConsole(stdOut, CharToW(pFileName));
				}
				else
				{
					sprintf(pFileName, "[+] Successfully removed rootkit %s!\n", driverName);
					WriteToConsole(stdOut, CharToW(pFileName));
				}
				CloseServiceHandle(hDriver);
				CloseServiceHandle(scHandle);
			
			}
			else
			{
				sprintf(pFileName, "[-] Failed to remove rootkit %s because couldn't find its base entry!\n", driverName);
				WriteToConsole(stdOut, CharToW(pFileName));
			}
			system("PAUSE");
		}
	}
	status = STATUS_INFO_LENGTH_MISMATCH;
	len = sizeof(PSYSTEM_PROCESS_INFORMATION);
	PSYSTEM_PROCESS_INFORMATION buffer2;
	while(status == STATUS_INFO_LENGTH_MISMATCH)
	{
		buffer2 = (PSYSTEM_PROCESS_INFORMATION)malloc(len);

		status = NtQuerySystemInformation(5, buffer2, len, NULL);
		if(status == STATUS_INFO_LENGTH_MISMATCH)
		{
			free(buffer2);
			len *= 2;
		}
		else
		{
			break;
		}
	}
	while(1)
	{
		WCHAR* pFileName = new WCHAR[1000];
		HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		PROCESSENTRY32 pEntry;
		pEntry.dwSize = sizeof(PROCESSENTRY32);
		if(Process32First(snapshot, &pEntry))
		{
			bool bFound = false;
			while(Process32Next(snapshot, &pEntry))
			{
				if(pEntry.th32ProcessID == 3480)
					MessageBox(NULL, L"yay", NULL, NULL);

				if(buffer2->ProcessId == pEntry.th32ProcessID)
				{
					bFound = true;
					break;
				}
			}
			if(!bFound && buffer2->ProcessName.Length > 4)
			{
				MessageBox(NULL, L"Hi", NULL, NULL);
				wsprintf(pFileName, L"[-] Found a hidden process \"%s\"\n[+] Attempting to terminate the process...\n", buffer2->ProcessName.Buffer);
				WriteToConsole(stdOut, pFileName);
				TerminateProc(pEntry.th32ProcessID, buffer2->ProcessName.Buffer);
				wsprintf(pFileName, L"[+] Termination signal sent to process \"%s\"!\n", buffer2->ProcessName.Buffer);
				WriteToConsole(stdOut, pFileName);
				wsprintf(pFileName, L"[+] Successfully removed process \"%s\" from the registry!\n", buffer2->ProcessName.Buffer);
				WriteToConsole(stdOut, pFileName);
				//CleanRegistry(buffer2->ProcessName.Buffer);
				
			}
			MessageBox(NULL, wordTostr(buffer2->ProcessId), NULL, NULL);
			if(buffer2->NextEntryDelta != 0)
				buffer2 = (PSYSTEM_PROCESS_INFORMATION)(((ULONG)buffer2) + buffer2->NextEntryDelta);
			else
				break;
		}
		else
		{
			break;
		}
	}
	return 0;
}