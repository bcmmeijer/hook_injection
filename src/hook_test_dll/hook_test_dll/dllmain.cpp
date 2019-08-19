// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#define PATH L"C:\\hook_test_dll.dll"

extern "C" __declspec(dllexport) LRESULT CALLBACK HookProcedure(int Code, WPARAM wParam, LPARAM lParam);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved){
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		MessageBoxA(NULL, "asd", "asd", MB_OK);
    return TRUE;
}

LRESULT CALLBACK HookProcedure(int Code, WPARAM wParam, LPARAM lParam) {
	return CallNextHookEx(NULL, Code, wParam, lParam);
}


