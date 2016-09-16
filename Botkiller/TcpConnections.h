#include <iostream> //std returns a random error which is not recognized by the compiler without this :)
#include <vector>
#include <IPHlpApi.h> //IPHlpApi.lib is also required
#include <iostream>
#include <fstream>

using namespace std;

#define AF_INET 2 //IPv4 connections

DWORD CloseConnection(MIB_TCPROW_OWNER_PID pointer);

vector<MIB_TCPROW_OWNER_PID> GetTcpConnections()
{
	//Checking to see how much memory GetExtendedTcpTable requires, getSize is returned with the actual size.
	vector<MIB_TCPROW_OWNER_PID> list; //The list which we will use to store each row
	MIB_TCPTABLE_OWNER_PID *pointer = (MIB_TCPTABLE_OWNER_PID*)malloc(1);
	DWORD getSize = 1;
	GetExtendedTcpTable(pointer, &getSize, true, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0);
	free(pointer); //Fixes memory leaks :D
	pointer = (MIB_TCPTABLE_OWNER_PID*)malloc(getSize); //Allocate the memory
	GetExtendedTcpTable(pointer, &getSize, true, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0); //Retrieve the actual information
	for(unsigned int i = 0; i < pointer->dwNumEntries; i++)
	{	
		list.push_back(pointer->table[i]);
	}
	free(pointer);
	return list;
}

DWORD CloseConnection(MIB_TCPROW_OWNER_PID pointer)
{
	MIB_TCPROW row;
	row.dwLocalAddr = pointer.dwLocalAddr;
	row.dwLocalPort = pointer.dwLocalPort;
	row.dwRemoteAddr = pointer.dwRemoteAddr;
	row.dwRemotePort = pointer.dwRemotePort;
	row.dwState = MIB_TCP_STATE_DELETE_TCB;
	return (SetTcpEntry(&row));
}