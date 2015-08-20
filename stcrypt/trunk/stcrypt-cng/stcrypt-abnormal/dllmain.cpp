// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-abnormal.hpp"

#include "../stcrypt-cng/stcrypt-debug.hpp"
#include "../stcrypt-cng/stcrypt-exceptions.hpp"

#include <boost/thread/once.hpp>
//================================================================================================================================================
BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call,LPVOID lpReserved )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		try{ stcrypt::logger::unload_for_thread();}catch(...){assert(false);}
		break;
	case DLL_PROCESS_DETACH:
		try{stcrypt::logger::before_unload();}catch(...){assert(false);}
		break;
	}
	return TRUE;
}

//================================================================================================================================================
namespace {

	boost::once_flag init_called = BOOST_ONCE_INIT;

}

LRESULT CALLBACK  stcrypt_abnormal_wnd_hook ( int nCode,  WPARAM wParam, LPARAM lParam ){

	try{

		boost::call_once(&stcrypt::abnormal::initialize, init_called);

	}catch(...){

	}

	return CallNextHookEx(0, nCode, wParam, lParam);
}
//================================================================================================================================================

