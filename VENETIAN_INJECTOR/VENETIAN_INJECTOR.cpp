//necessary libraries
#include <Windows.h>
#include <string>
#include <iostream>
#include <vector>
#include <TlHelp32.h>

DWORD GetProcessIdByName(const std::wstring& processName) {
	DWORD pid = 0;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (snapshot == INVALID_HANDLE_VALUE)
		return 0;

	PROCESSENTRY32W pe;
	pe.dwSize = sizeof(PROCESSENTRY32W);

	if (Process32FirstW(snapshot, &pe)) {
		do {
			std::wstring exeName = pe.szExeFile;

			if (processName == exeName) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32NextW(snapshot, &pe));
	}

	CloseHandle(snapshot);
	return pid;
}

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
	WaitForSingleObject(thread, INFINITE);
	CloseHandle(thread);

	//clean
	VirtualFreeEx(hProcess, dllPathAddress, 0, MEM_RELEASE);
	CloseHandle(hProcess);

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
	DWORD processID = GetProcessIdByName(processName);
	if (processID == 0) {
		std::cout << "Process not found!" << std::endl;
		Sleep(200);
		return 1;
	}

	//injects dll
	if (Inject(processID, dllPath)) {
		std::cout << "Succesfully injected!" << std::endl;
		Sleep(200);
	}
	else {
		std::cout << "Failed to inject DLL! " << GetLastError() << std::endl;
		Sleep(1000);
	}

	return 0;
}