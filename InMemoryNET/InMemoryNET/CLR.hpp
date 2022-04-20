#include <metahost.h>
#include <windows.h>
#include <string>
#include <shellapi.h>

#pragma comment(lib, "mscoree.lib")

#import <mscorlib.tlb> raw_interfaces_only			\
    	high_property_prefixes("_get","_put","_putref")		\
    	rename("ReportEvent", "InteropServices_ReportEvent")	\
	rename("or", "InteropServices_or")
using namespace mscorlib;
#pragma endregion

namespace CLRManager
{
	class CLR
	{
	public:
		BOOL execute_assembly(std::vector<unsigned char>assembly, std::string args)
		{

			std::wstring wNetVersion = L"v4.0.30319";

			hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_PPV_ARGS(&pCLRMetaHost));
			printf("[*] CLRCreateInstance(): 0x%x\n", hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCLRMetaHost->GetRuntime(wNetVersion.c_str(), IID_PPV_ARGS(&pCLRRuntimeInfo));
			printf("[*] pCLRMetaHost->GetRuntime(): 0x%x\n", hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCLRRuntimeInfo->IsLoadable(&isLoadable);
			printf("[*] pCLRRuntimeInfo->IsLoadable(): 0x%x\n", hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCLRRuntimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&pCorRuntimeHost));
			printf("[*] pCLRRuntimeInfo->GetInterface(): 0x%x\n", hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCorRuntimeHost->Start();
			printf("[*] pCorRuntimeHost->Start(): 0x%x\n", hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = pCorRuntimeHost->GetDefaultDomain(&spAppDomainThunk);
			printf("[*] pCorRuntimeHost->GetDefaultDomain(): 0x%x\n", hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = spAppDomainThunk->QueryInterface(IID_PPV_ARGS(&spDefaultAppDomain));
			printf("[*] spAppDomainThunk->QueryInterface(): 0x%x\n", hr);

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
			printf("[*] SafeArrayAccessData(): 0x%x\n", hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			std::memcpy(pvData, assembly.data(), assembly.size());

			hr = SafeArrayUnaccessData(safeArray);
			printf("[*] SafeArrayUnaccessData(): 0x%x\n", hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = spDefaultAppDomain->Load_3(safeArray, &spAssembly);
			printf("[*] spDefaultAppDomain->Load_3(): 0x%x\n", hr);

			if (FAILED(hr))
			{
				cleanup(safeArrayArgs, pCorRuntimeHost, pCLRRuntimeInfo, pCLRMetaHost);
				return FALSE;
			}

			hr = spAssembly->get_EntryPoint(&pMethodInfo);
			printf("[*] spAssembly->get_EntryPoint(): 0x%x\n", hr);

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
			printf("[*] pMethodInfo->Invoke_3(): 0x%x\n", hr);

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
		ICLRMetaHost*	 pCLRMetaHost = NULL;
		_MethodInfoPtr	 pMethodInfo = NULL;
		_AssemblyPtr	 spAssembly = NULL;
		IUnknownPtr		 spAppDomainThunk = NULL;
		_AppDomainPtr	 spDefaultAppDomain = NULL;
		SAFEARRAY*		 safeArrayArgs = NULL;
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