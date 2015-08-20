// stcrypt-abnormal-controller.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "../stcrypt-cng/util-scope-exit.hpp"
#include "../stcrypt-cng/stcrypt-debug.hpp"
#include "../stcrypt-cng/stcrypt-exceptions.hpp"
#include "../stcrypt-abnormal/stcrypt-abnormal_common.hpp"

#include <boost/format.hpp>
#include <boost/scope_exit.hpp>
#include <boost/thread/tss.hpp>

#include <iostream>

int _tmain(int argc, _TCHAR* argv[])
{

	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_DELAY_FREE_MEM_DF);
	//_CrtSetBreakAlloc(247);

	BOOST_SCOPE_EXIT((argc)){ try{ stcrypt::logger::before_unload(); } catch(...){}; } BOOST_SCOPE_EXIT_END

	try{

		STCRYPT_CHECK(argc==2);

		auto const term_event = CreateEvent(0, true, false, STCRYPT_ABNORMAL_TERM_EVENT_NAME);
		STCRYPT_CHECK_WIN(term_event);
		STCRYPT_SCOPE_EXIT([term_event](){ STCRYPT_CHECK_WIN(CloseHandle(term_event)); });

		HINSTANCE const dll_inst = LoadLibrary( argv[1] );
		STCRYPT_CHECK_WIN( dll_inst );
		STCRYPT_SCOPE_EXIT([dll_inst](){ STCRYPT_CHECK_WIN(FreeLibrary(dll_inst)); });

		auto const hook_proc = reinterpret_cast<HOOKPROC>( GetProcAddress(dll_inst, "stcrypt_abnormal_wnd_hook") );
		STCRYPT_CHECK_WIN( hook_proc );

		STCRYPT_CHECK_WIN( ResetEvent(term_event) );

		auto const hook = SetWindowsHookEx(WH_CALLWNDPROC, hook_proc, dll_inst ,0); 
		STCRYPT_CHECK_WIN( hook );

		//MessageBox(0, L"", L"", MB_OK);
		//Sleep(2*1000);

		std::cout << "ENTER to unload\n";
		getchar();

		STCRYPT_CHECK_WIN( UnhookWindowsHookEx (hook) );
		STCRYPT_CHECK_WIN( SetEvent(term_event) );
		
	} catch(std::exception const& e) {
		std::cerr << boost::format("ERROR: %1%\n") % e.what();
	}

	return 0;
}

