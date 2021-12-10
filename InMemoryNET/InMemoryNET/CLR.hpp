#include "base64.hpp"
#include <metahost.h>
#include <windows.h>
#include <string>
#include <vector>
#include <shellapi.h>
#include <system_error>

#pragma comment(lib, "mscoree.lib")

// Import mscorlib.tlb (Microsoft Common Language Runtime Class Library).
#import <mscorlib.tlb> raw_interfaces_only			\
    	high_property_prefixes("_get","_put","_putref")		\
    	rename("ReportEvent", "InteropServices_ReportEvent")	\
	rename("or", "InteropServices_or")
using namespace mscorlib;
#pragma endregion

#define DEBUG

#ifdef DEBUG
#define debug_print(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#else
#define debug_print(fmt, ...)
#endif

namespace CLRManager
{
	class CLR
	{
		std::pair<PVOID, DWORD> GetShellcodeFromFile(LPCSTR Filename)
		{
			HANDLE hFile = CreateFileA(Filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL); // Open the DLL
			DWORD FileSize = GetFileSize(hFile, NULL);
			PVOID FileBuffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			// Read the DLL
			ReadFile(hFile, FileBuffer, FileSize, NULL, NULL);
			return std::pair<PVOID, DWORD>(FileBuffer, FileSize);
		}

	public:
		BOOL execute_assembly(std::string netB64, std::string argsB64)
		{
			if (netB64.empty())
			{
				return FALSE;
			}

			std::vector<unsigned char> assembly = base64::from_base64_vector(netB64);
			std::string args = base64::from_base64(argsB64);
			std::wstring wNetVersion;

			hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pCLRMetaHost));
			debug_print("CLRCreateInstance(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCLRMetaHost->GetRuntime(L"v4.0.30319", IID_PPV_ARGS(&pCLRRuntimeInfo));
			debug_print("pCLRMetaHost->GetRuntime(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCLRRuntimeInfo->IsLoadable(&isLoadable);
			debug_print("pCLRRuntimeInfo->IsLoadable(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCLRRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&pCorRuntimeHost));
			debug_print("pCLRRuntimeInfo->GetInterface(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCorRuntimeHost->Start();
			debug_print("pCorRuntimeHost->Start(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCorRuntimeHost->GetDefaultDomain(&spAppDomainThunk);
			debug_print("pCorRuntimeHost->GetDefaultDomain(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&spDefaultAppDomain));
			debug_print("spAppDomainThunk->QueryInterface(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			SAFEARRAYBOUND rgsabound[1] = {};
			rgsabound[0].lLbound = 0;
			rgsabound[0].cElements = assembly.size();

			SAFEARRAY* safeArray = SafeArrayCreate(VT_UI1, 1, rgsabound);

			PVOID pvData = NULL;

			hr = SafeArrayAccessData(safeArray, &pvData);
			debug_print("SafeArrayAccessData(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			memcpy(pvData, assembly.data(), assembly.size());
			
			hr = SafeArrayUnaccessData(safeArray);
			debug_print("SafeArrayUnaccessData(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = spDefaultAppDomain->Load_3(safeArray, &spAssembly);
			debug_print("spDefaultAppDomain->Load_3(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = spAssembly->get_EntryPoint(&pMethodInfo);
			debug_print("spAssembly->get_EntryPoint(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			// totally stole this: https://github.com/Hnisec/execute-assembly/blob/master/execute-assembly/execute-assembly.cpp
			if (!args.empty())
			{
				vtPsa.vt = VT_ARRAY | VT_BSTR;
				SAFEARRAYBOUND argsBound[1];
				argsBound[0].lLbound = 0;
				size_t argsLength = args.data() != NULL ? args.size() : 0;
				argsBound[0].cElements = argsLength;
				vtPsa.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);
				safeArrayArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
				LPWSTR* szArglist;
				int nArgs;
				wchar_t* wtext = (wchar_t*)malloc((sizeof(wchar_t) * args.size() + 1));
				mbstowcs(wtext, (char*)args.data(), args.size() + 1);
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
				size_t argsLength = args.data() != NULL ? args.size() : 0;
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

			hr = pMethodInfo->Invoke_3(obj, safeArrayArgs, &retVal);
			debug_print("pMethodInfo->Invoke_3(): %s (0x%x)\n", std::system_category().message(hr).c_str(), hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
			return TRUE;
		}

	private:
		ICLRRuntimeInfo* pCLRRuntimeInfo = NULL;
		ICorRuntimeHost* pCorRuntimeHost = NULL;
		ICLRMetaHost* pCLRMetaHost = NULL;
		_MethodInfoPtr	 pMethodInfo = NULL;
		_AssemblyPtr	 spAssembly = NULL;
		IUnknownPtr		 spAppDomainThunk = NULL;
		_AppDomainPtr	 spDefaultAppDomain = NULL;
		SAFEARRAY* safeArrayArgs = NULL;
		VARIANT			 retVal, obj, vtPsa;
		BOOL			 isLoadable = FALSE;
		HRESULT			 hr;

		void cleanup(SAFEARRAY* pSafeArray, ICorRuntimeHost* pCorRuntimeHost, ICLRRuntimeInfo* pCLRRuntimeInfo, ICLRMetaHost* pCLRMetaHost) {
			if (pCLRMetaHost)
			{
				pCLRMetaHost->Release();
				pCLRMetaHost = NULL;
			}
			if (pCLRRuntimeInfo)
			{
				pCLRRuntimeInfo->Release();
				pCLRRuntimeInfo = NULL;
			}
			if (pSafeArray)
			{
				SafeArrayDestroy(pSafeArray);
				pSafeArray = NULL;
			}
			if (pCorRuntimeHost) {
				pCorRuntimeHost->Stop();
				pCorRuntimeHost->Release();
			}
			return;
		}

	};
}