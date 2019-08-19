#include <Windows.h>
#include <iostream>

void __exit() {
	std::cout << "[*] Error: 0x" << std::hex << GetLastError() << std::endl;
	exit(0);
}

int main(int argc, char** argv) {
	OPENFILENAME	dll;
	char			szFile[260];
	HMODULE			hDllHandle = NULL;
	HANDLE			dwHookAddr = 0;
	HHOOK			hHook;

	ZeroMemory(&dll, sizeof(dll));
	ZeroMemory(szFile, sizeof(szFile));
	dll.lStructSize = sizeof(dll);
	dll.lpstrFile = szFile;
	dll.lpstrFile[0] = '\0';
	dll.nMaxFile = sizeof(szFile);
	dll.lpstrFilter = "dll\0*.dll";
	dll.nFilterIndex = 1;
	dll.lpstrFileTitle = NULL;
	dll.nMaxFileTitle = 0;
	dll.lpstrInitialDir = NULL;
	dll.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
	if (!GetOpenFileName(&dll)) {
		std::cout << "[-]t\Could not open the selected file.\n";
		std::cout << "[*]\tError: " << GetLastError() << std::endl;
		return EXIT_FAILURE;
	}
	std::cout << "[*] Selected file: " << dll.lpstrFile << std::endl;

	hDllHandle = LoadLibraryA(dll.lpstrFile);
	if (!hDllHandle)
		__exit();
	
	dwHookAddr = GetProcAddress(hDllHandle, "HookProcedure");
	if(!dwHookAddr)
		__exit();
	std::cout << "HookProcedure addr: " << dwHookAddr << std::endl;
	hHook = SetWindowsHookEx(WH_KEYBOARD, (HOOKPROC)dwHookAddr, hDllHandle, 0);
	if(!hHook)
		__exit();

	std::cout << "[*] Created hook\n";
	MSG msg;
	while (GetMessage(&msg, NULL, 0, 0) > 0) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
		if (GetAsyncKeyState(VK_SPACE))
			break;
	}
	UnhookWindowsHookEx(hHook);
	std::cout << "[*] Removed hook\n";
	return 0;
}