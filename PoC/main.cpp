// TestJig.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <Subauth.h>
#include <assert.h>

#include <iostream>

#include "../DLLPasswordFilterImplant/crypt.h"

extern "C" {

	__declspec(dllexport) BOOLEAN WINAPI InitializeChangeNotify(void);
	__declspec(dllexport) BOOLEAN WINAPI PasswordFilter(PUNICODE_STRING AccountName, PUNICODE_STRING FullName, PUNICODE_STRING Password, BOOLEAN SetOperation);
	__declspec(dllexport) NTSTATUS WINAPI PasswordChangeNotify(PUNICODE_STRING UserName, ULONG RelativeId, PUNICODE_STRING NewPassword);


}

wchar_t STR[] = L"HELLO";
int main()
{
	std::cout << "Hello World!\n";

	wchar_t* buf = new wchar_t[10];
	memcpy(buf, &STR, sizeof(STR));

	// Lol penible.
	UNICODE_STRING acc;
	acc.Buffer = buf;
	acc.Length = 10; acc.MaximumLength = 20;
	InitializeChangeNotify();
	assert(PasswordFilter(&acc, &acc, &acc, 1));

	if (PasswordFilter(&acc, &acc, &acc, 1)) {
		PasswordChangeNotify(&acc, 123, &acc);
	}
}