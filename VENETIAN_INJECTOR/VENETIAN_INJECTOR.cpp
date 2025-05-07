//necessary libraries
#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <TlHelp32.h>

#include "utils.h"

#define PROCESSENTRY32

DWORD inject_utils::GetProcessIdByName(const std::wstring& processName);

bool Inject(DWORD pID, const std::string& dllPath) {
	//proc handle
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pID);
	if (!hProcess) {
		return false;
	}

	//alloc memory on target process
	size_t pathLen = (dllPath.length() + 1) * sizeof(char);
	LPVOID dllPathAddress = VirtualAllocEx(
		hProcess,
		NULL,
		pathLen,
		MEM_COMMIT,
		PAGE_READWRITE
	);
	if (!dllPathAddress) {
		return false;
	}

	//write dllPath into allocated memory
	if (!WriteProcessMemory(
		hProcess,
		dllPathAddress,
		dllPath.c_str(),
		pathLen,
		NULL
	)) {
		VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	//get LoadLibraryA addr
	LPVOID loadLibraryAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

	//create a thread that call LoadLibraryA
	HANDLE thread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)loadLibraryAddress,
		dllPathAddress,
		0,
		NULL
	);
	if (!thread) {
		VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return false;
	}

	//wait the thread to end
	WaitForSingleObject(hProcess, INFINITE);

	//clean
	VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
	CloseHandle(hProcess);
	return false;

	return true;
}

int main() {
	//get necessary info from the user
	std::wstring processName;
	std::string dllPath;

	//get info
	std::cout << "Hello, please enter the process name" << std::endl;
	std::getline(std::wcin, processName);
	std::cout << "Now, enter the path of the DLL you want to inject" << std::endl;
	std::getline(std::cin, dllPath);

	//checks if process exists
	DWORD processID = inject_utils::GetProcessIdByName(processName);
	if (processID == 0) {
		std::cout << "Process not found!" << std::endl;
		return 1;
	}

	//injects dll
	if (Inject(processID, dllPath)) {
		std::cout << "Succesfully injected!" << std::endl;
	}
	else {
		std::cout << "Failed to inject DLL!" << GetLastError() << std::endl;
	}

	return 0;
}