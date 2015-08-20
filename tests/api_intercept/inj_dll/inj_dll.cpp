// inj_dll.cpp : Defines the entry point for the DLL application.
//
/////////////////////////////////////////////////////////////////////////////
#include "stdafx.h"
#include "detours.h"
#include "inj_dll.h"

#include "boost/format.hpp"
#include "c:/work/workcrypto/stcrypt/trunk/stcrypt-csp/stcrypt-crypto-alg-ids.h "

#include <WinCrypt.h>

/////////////////////////////////////////////////////////////////////////////

extern "C"{
	//HCRYPTPROV __cdecl I_CryptGetDefaultCryptProv(ALG_ID algid);
};
typedef 	HCRYPTPROV (WINAPI *I_CryptGetDefaultCryptProv_TYPE)(ALG_ID algid);

I_CryptGetDefaultCryptProv_TYPE  real_I_CryptGetDefaultCryptProv;

HCRYPTPROV WINAPI injected_I_CryptGetDefaultCryptProv(ALG_ID algid){
		//MessageBox(NULL,"aaa","INFO",MB_OK);
		std::string const msg = (boost::format("Process id %2%\n[injected_I_CryptGetDefaultCryptProv] unknown ALG_ID is %1%") % algid % GetCurrentProcessId()).str();;
		MessageBox(NULL,msg.c_str(),"INFO",MB_OK);
		
		if(algid==0 || algid==13347){
			HCRYPTPROV our_csp = 0;
			if( !CryptAcquireContext(&our_csp, 0, STCRYPT_PROVIDER_NAME_A, STCRYPT_PROVIDER_TYPE, 0) ){
				MessageBox(0, "CryptAcquireContext() have failed", "ERROR", MB_OK);
				return real_I_CryptGetDefaultCryptProv(algid);
			} else {
				return our_csp;
			}

		} else {
			return real_I_CryptGetDefaultCryptProv(algid);
		}
		//return real_I_CryptGetDefaultCryptProv(algid);
}


/////////////////////////////////////////////////////////////////////////////
__declspec(dllexport) void dummy_1 (){
	CertCloseStore(0,0);
}

extern "C" __declspec(dllexport) LRESULT CALLBACK  CallWndProc( int nCode,  WPARAM wParam, LPARAM lParam )
{
	return NULL;
	//return CallNextHookEx(hook, nCode, wParam, lParam );
}
//#pragma comment(linker, "/export:CallWndProc")


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		 real_I_CryptGetDefaultCryptProv = (I_CryptGetDefaultCryptProv_TYPE)GetProcAddress(GetModuleHandle("crypt32"), "I_CryptGetDefaultCryptProv");

		 DetourTransactionBegin();
		 DetourUpdateThread(GetCurrentThread());
		 if(DetourAttach(&(PVOID&)real_I_CryptGetDefaultCryptProv, injected_I_CryptGetDefaultCryptProv)!=NO_ERROR )
			 MessageBox(0, "DetourAttach() have failed", "ERROR", MB_OK);;
		 DetourTransactionCommit();


		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)real_I_CryptGetDefaultCryptProv, injected_I_CryptGetDefaultCryptProv);
		DetourTransactionCommit();

		break;
	}
    return TRUE;
}
/////////////////////////////////////////////////////////////////////////////

