#pragma warning(disable : 4996)

#include <metahost.h>
#include <comutil.h>
#include <Psapi.h>
#include <tchar.h>
#include <fstream>
#include <iostream>
#include <vector>
#include <evntprov.h>

using namespace std;

#pragma comment(lib, "mscoree.lib")

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import <mscorlib.tlb> raw_interfaces_only			\
    	high_property_prefixes("_get","_put","_putref")		\
    	rename("ReportEvent", "InteropServices_ReportEvent")	\
	rename("or", "InteropServices_or")
using namespace mscorlib;
#pragma endregion

std::pair<PVOID, DWORD> GetShellcodeFromFile(LPCSTR Filename) {
	HANDLE hFile = CreateFileA(Filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, 0, NULL); // Open the DLL
	DWORD FileSize = GetFileSize(hFile, NULL);
	PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	// Read the DLL
	ReadFile(hFile, FileBuffer, FileSize, NULL, NULL);
	return std::pair<PVOID, DWORD>(FileBuffer, FileSize);
}

int main()
{
	LPCSTR Filename = "G:\\Dropbox\\GitHub\\mez-0\\InMemoryNET\\ConsoleApp1\\ConsoleApp1\\bin\\Debug\\ConsoleApp1.exe";
	std::pair<PVOID, DWORD> shellcodePair = GetShellcodeFromFile(Filename);
	PVOID shellcodeBytes = shellcodePair.first;
	DWORD shellcodeBytesLength = shellcodePair.second;

	string arguments = "args!";
	int argsSize = arguments.length();

	ICLRMetaHost* pMetaHost = NULL;
	ICLRRuntimeInfo* pRuntimeInfo = NULL;
	ICorRuntimeHost* pRuntimeHost = NULL;
	IUnknownPtr pAppDomainThunk = NULL;
	_AppDomainPtr pDefaultAppDomain = NULL;
	_AssemblyPtr pAssembly = NULL;
	_MethodInfoPtr pMethodInfo = NULL;
	SAFEARRAY* safeArrayArgs = NULL;
	BOOL bLoadable;

	/* Get ICLRMetaHost instance */

	if (CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (VOID**)&pMetaHost) != S_OK) {
		printf("[!] Failed: CLRCreateInstance()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: CLRCreateInstance()\n");
	}

	if (pMetaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (VOID**)&pRuntimeInfo) != S_OK) {
		printf("[!] Failed: pMetaHost->GetRuntime()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: pMetaHost->GetRuntime()\n");
	}

	if (pRuntimeInfo->IsLoadable(&bLoadable) != S_OK) {
		printf("[!] Failed: pRuntimeInfo->IsLoadable()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: pRuntimeInfo->IsLoadable()\n");
	}

	/* Get ICorRuntimeHost instance */

	if (pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (VOID**)&pRuntimeHost) != S_OK) {
		printf("[!] Failed: pRuntimeInfo->GetInterface()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: pRuntimeInfo->GetInterface()\n");
	}
	if (pRuntimeHost->Start() != S_OK) {
		printf("[!] Failed: pRuntimeHost->Start()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: pRuntimeHost->Start()\n");
	}

	if (pRuntimeHost->GetDefaultDomain(&pAppDomainThunk) != S_OK) {
		printf("[!] Failed: pRuntimeHost->GetDefaultDomain()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: pRuntimeHost->GetDefaultDomain()\n");
	}

	if (pAppDomainThunk->QueryInterface(__uuidof(_AppDomain), (VOID**)&pDefaultAppDomain) != S_OK) {
		printf("[!] Failed: pAppDomainThunk->QueryInterface()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: pAppDomainThunk->QueryInterface()\n");
	}

	SAFEARRAYBOUND rgsabound[1];
	rgsabound[0].cElements = shellcodeBytesLength;
	rgsabound[0].lLbound = 0;
	SAFEARRAY* pSafeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);
	void* pvData = NULL;

	if (SafeArrayAccessData(pSafeArray, &pvData) != S_OK) {
		printf("[!] Failed: SafeArrayAccessData()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: SafeArrayAccessData()\n");
	}

	memcpy(pvData, shellcodeBytes, shellcodeBytesLength);

	if (SafeArrayUnaccessData(pSafeArray) != S_OK) {
		printf("[!] Failed: SafeArrayUnaccessData()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: SafeArrayUnaccessData()\n");
	}

	if (pDefaultAppDomain->Load_3(pSafeArray, &pAssembly) != S_OK) {
		printf("[!] Failed: pDefaultAppDomain->Load_3()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: pDefaultAppDomain->Load_3()\n");
	}

	if (pAssembly->get_EntryPoint(&pMethodInfo) != S_OK) {
		printf("[!] Failed: pAssembly->get_EntryPoint()\n");
		return 2;
	}
	else {
		printf("[+] Succeeded: pAssembly->get_EntryPoint()\n\n");
	}

	VARIANT retVal;
	VARIANT vtPsa;
	VARIANT obj;


	// totally stole this: https://github.com/Hnisec/execute-assembly/blob/master/execute-assembly/execute-assembly.cpp
	if (argsSize > 0)
	{
		vtPsa.vt = VT_ARRAY | VT_BSTR;
		SAFEARRAYBOUND argsBound[1];
		argsBound[0].lLbound = 0;
		size_t argsLength = arguments.data() != NULL ? argsSize : 0;
		argsBound[0].cElements = argsLength;
		vtPsa.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);
		safeArrayArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
		LPWSTR* szArglist;
		int nArgs;
		wchar_t* wtext = (wchar_t*)malloc((sizeof(wchar_t) * argsSize + 1));
		mbstowcs(wtext, (char*)arguments.data(), argsSize + 1);
		szArglist = CommandLineToArgvW(wtext, &nArgs);
		vtPsa.parray = SafeArrayCreateVector(VT_BSTR, 0, nArgs);
		for (long i = 0; i < nArgs; i++)
		{
			BSTR strParam1 = SysAllocString(szArglist[i]);
			SafeArrayPutElement(vtPsa.parray, &i, strParam1);
		}
		long iEventCdIdx(0);
		SafeArrayPutElement(safeArrayArgs, &iEventCdIdx, &vtPsa);
		ZeroMemory(&vtPsa, sizeof(VARIANT));
	}
	else
	{
		// I dont know why i cant just pass a LONG 0, but i had to do all this? seems wrong
		vtPsa.vt = VT_ARRAY | VT_BSTR;
		SAFEARRAYBOUND argsBound[1];
		argsBound[0].lLbound = 0;
		size_t argsLength = arguments.data() != NULL ? argsSize : 0;
		argsBound[0].cElements = argsLength;
		vtPsa.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);

		LONG idx[1];
		idx[0] = 0;

		SAFEARRAYBOUND paramsBound[1];
		paramsBound[0].lLbound = 0;
		paramsBound[0].cElements = 1;
		safeArrayArgs = SafeArrayCreate(VT_VARIANT, 1, paramsBound);
		SafeArrayPutElement(safeArrayArgs, idx, &vtPsa);
		ZeroMemory(&vtPsa, sizeof(VARIANT));
	}

	ZeroMemory(&retVal, sizeof(VARIANT));
	ZeroMemory(&obj, sizeof(VARIANT));
	obj.vt = VT_NULL;

	if (pMethodInfo->Invoke_3(obj, safeArrayArgs, &retVal) != S_OK) {
		printf("[!] Failed: pMethodInfo->Invoke_3() failed\n");
		return 2;
	}
	else {
		printf("\n[+] Succeeded: pMethodInfo->Invoke_3() succeeded\n");
	}

	return 0;
}
