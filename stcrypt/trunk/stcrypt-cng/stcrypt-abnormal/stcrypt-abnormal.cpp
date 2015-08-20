// FILE: stcrypt-abnormal.cpp
//
// (c) GIE 2011-02-21  17:40
// (c) Andrey Mnatsakanov 2010-10-07  15:25
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-abnormal_common.hpp"

#include "../stcrypt-cng/stcrypt-debug.hpp"
#include "../stcrypt-cng/stcrypt-exceptions.hpp"
#include "../stcrypt-cng/util-scope-exit.hpp"

#include "detours.h"

#include <boost/static_assert.hpp>
#include <boost/thread.hpp>
#include <boost/array.hpp>
#include <boost/algorithm/string/compare.hpp>
#include <boost/range.hpp>
#include <boost/range/algorithm/find_end.hpp>
//================================================================================================================================================
namespace stcrypt { namespace abnormal { 

	namespace {

		boost::iterator_range<wchar_t const*> file_name_from_path(wchar_t const*const path, size_t const path_size){

			auto const fname_only_idx = [&]()->unsigned int{
				assert(path_size);

				for(unsigned int i = path_size-1; i>0; --i){
					if( path[i]==L'\\' || path[i]==L'/') {
						return i+1;
					}
				}

				return 0;
			}();	


			return boost::make_iterator_range(&path[0]+fname_only_idx, &path[0]+path_size);

		}

	} //end anon ns

	namespace {

		HANDLE bg_thread_h=0;

		HANDLE global_term_event = 0;
		HANDLE local_term_event = 0;

		CRITICAL_SECTION share_data_lock={0};

		//
		//
		//

		template 
		<
			class Range1T,
			class Range2T
		>
		bool is_equal_case_insensitive(Range1T const& sq1, Range2T const& sq2){
			return boost::equal(sq1, sq2, boost::is_iequal() );
		}

		template <size_t N> 
		boost::iterator_range<wchar_t const*> make_range_from_string_literal(wchar_t const (&str_lit)[N]){
			BOOST_STATIC_ASSERT(N>0);

			return boost::make_iterator_range( &str_lit[0], &str_lit[0]+N-1);
		}
		//
		//
		//


		template
		<
			class OrigFuncPtrT,
			OrigFuncPtrT new_func
		>
		void attach__(HMODULE const module_handle, OrigFuncPtrT& orig_func){

			STCRYPT_CHECK( DetourTransactionBegin()==NO_ERROR );
			STCRYPT_SCOPE_EXIT([](){STCRYPT_CHECK(DetourTransactionCommit()==NO_ERROR);});

			STCRYPT_CHECK(DetourUpdateThread(GetCurrentThread())==NO_ERROR);
			STCRYPT_CHECK(DetourAttach( (void**)&orig_func , new_func)==NO_ERROR);
		}

		template
		<
			class OrigFuncPtrT,
			OrigFuncPtrT new_func
		>
		void attach__(HMODULE const module_handle, OrigFuncPtrT& orig_func, char const*const func_name){

			orig_func = reinterpret_cast<OrigFuncPtrT>( GetProcAddress(module_handle, func_name) );
			STCRYPT_CHECK_WIN( orig_func );

			STCRYPT_CHECK( DetourTransactionBegin()==NO_ERROR );
			STCRYPT_SCOPE_EXIT([](){STCRYPT_CHECK(DetourTransactionCommit()==NO_ERROR);});

			STCRYPT_CHECK(DetourUpdateThread(GetCurrentThread())==NO_ERROR);
			STCRYPT_CHECK(DetourAttach( (void**)&orig_func , new_func)==NO_ERROR);
		}

		template
		<
			class OrigFuncPtrT,
			OrigFuncPtrT new_func
		>
		void detach__(OrigFuncPtrT &orig_func){

			STCRYPT_CHECK( DetourTransactionBegin()==NO_ERROR );
			STCRYPT_SCOPE_EXIT([](){STCRYPT_CHECK(DetourTransactionCommit()==NO_ERROR);});

			STCRYPT_CHECK(DetourUpdateThread(GetCurrentThread())==NO_ERROR);
			STCRYPT_CHECK(DetourDetach( (void**)&orig_func, new_func)==NO_ERROR);
		}


		//
		// MegaFunction
		// 
		//
		wchar_t const outlmime_str[]=L"OUTLMIME.DLL";

		namespace mnaza_c {

			#define INJECTED_FUNC(func_name) injected_##func_name
			#define REAL_FUNC(func_name) real_##func_name
			#define REAL_FUNC_DEF(func_name) INJECTOR_FUNC_TYPE(func_name) REAL_FUNC(func_name)
			#define DEBUG_MESSAGE(msg) do{ try{ CSP_LOG_TRACE STCRYPT_LOG_A_STRING(msg); }catch(...){}; }while(false)
			#define INJECTOR_FUNC_TYPE(func_name) func_name##_TYPE

			typedef HRESULT (WINAPI *INJECTOR_FUNC_TYPE(MegaFunction))(LPCSTR *ppzProtocol, DWORD *rez, LPCSTR **ppzoutProtocol);

			REAL_FUNC_DEF(MegaFunction)=0;

			HRESULT WINAPI INJECTED_FUNC(MegaFunction)(
				LPCSTR *ppzProtocol,
				DWORD *rez,
				LPCSTR **ppzoutProtocol)
			{
 				DEBUG_MESSAGE("MegaFunction() execute");

				*rez=1;
				if(ppzoutProtocol!=NULL)
					*ppzoutProtocol=ppzProtocol;
				return S_OK;
			}


 			void attach__MegaFunction(HMODULE const handle){
				CSP_LOG_TRACE

				DWORD const shift=0xE035/*0xE0BC*/;

				REAL_FUNC(MegaFunction) = (INJECTOR_FUNC_TYPE(MegaFunction))(reinterpret_cast<BYTE*>( GetProcAddress(handle, "DllGetClassObject") )+shift);

				STCRYPT_CHECK( REAL_FUNC(MegaFunction) );

 				attach__<decltype(REAL_FUNC(MegaFunction)), INJECTED_FUNC(MegaFunction)>(handle, REAL_FUNC(MegaFunction) );
 			}

			void detach__MegaFunction(){
				CSP_LOG_TRACE

				detach__<decltype(REAL_FUNC(MegaFunction)), INJECTED_FUNC(MegaFunction)>(REAL_FUNC(MegaFunction) );
				REAL_FUNC(MegaFunction) = 0;
			}

			bool is_attached__MegaFunction(){

				auto const outlmime_dll = GetModuleHandleW(outlmime_str);
				if(!outlmime_dll) {

					if(REAL_FUNC(MegaFunction)!=0){
						STCRYPT_LOG_W_STRING(L"OUTLMIME is not loaded but found address, possible cause: unloaded by host");

						REAL_FUNC(MegaFunction) = 0;
					}

					return false;
				} else {
					return (REAL_FUNC(MegaFunction)!=0);
				}

			}

			#undef INJECTED_FUNC
			#undef REAL_FUNC
			#undef DEBUG_MESSAGE
			#undef REAL_FUNC_DEF
			#undef INJECTOR_FUNC_TYPE

		}// end mnaza_c
		



		//
		// Load library
		//
		
		typedef HMODULE (WINAPI *LoadLibraryW_t)(__in LPCWSTR lpLibFileName);
		typedef HMODULE (WINAPI *LoadLibraryA_t)(__in LPCSTR lpLibFileName);

		LoadLibraryA_t load_library_a_orig = 0;
		LoadLibraryW_t load_library_w_orig = 0;


		HMODULE WINAPI load_library_w(__in LPCWSTR lpLibFileName){
				try{

					STCRYPT_CHECK(lpLibFileName);

					STCRYPT_LOG_PRINT_W_EX("Loading DLL: ", lpLibFileName);
					
					if( is_equal_case_insensitive(
						file_name_from_path(lpLibFileName, wcslen(lpLibFileName) ),  
						make_range_from_string_literal(outlmime_str) )) 
					{
						STCRYPT_LOG_W_STRING("Detected loading of dll to be patched.");

						EnterCriticalSection(&share_data_lock);
						STCRYPT_SCOPE_EXIT([](){ LeaveCriticalSection(&share_data_lock); });

						if( GetModuleHandleW(outlmime_str) ){

							STCRYPT_LOG_W_STRING(L"Not patching OUTLMIME, should be patched on init.");
							return load_library_w_orig( lpLibFileName );

						} else {
							auto const orig_call_result = load_library_w_orig( lpLibFileName );
							try{

								STCRYPT_LOG_W_STRING(L"Patching OUTLMIME!");
								mnaza_c::attach__MegaFunction( orig_call_result );

							}catch(...){
								return orig_call_result;
							}
							return orig_call_result;
						}

						assert(false);

					} else {
						return load_library_w_orig( lpLibFileName );
					}


				}catch(...){
					return load_library_w_orig( lpLibFileName ); // on any exception just call original
				}

				assert(false);

		}



		void attach__load_library_w(HMODULE const kernel32_handle){
			attach__<decltype(load_library_w_orig), load_library_w>(kernel32_handle, load_library_w_orig, "LoadLibraryW");
		}
		void detach__load_library_w(){
			detach__<decltype(load_library_w_orig), load_library_w>(load_library_w_orig);
		}

		//
		//exit process
		//
		typedef VOID (WINAPI *ExitProcess_t)(__in UINT uExitCode);

		ExitProcess_t exit_process_orig = 0;

		VOID WINAPI exit_proccess(__in UINT uExitCode);

		void attach__exit_process(HMODULE const kernel32_handle){
			attach__<decltype(exit_process_orig), exit_proccess>(kernel32_handle, exit_process_orig, "ExitProcess");
		}
		void detach__exit_process(){
			detach__<decltype(exit_process_orig), exit_proccess>(exit_process_orig);
		}

		VOID WINAPI exit_proccess(__in UINT uExitCode){
			
			try { 

				CSP_LOG_TRACE

				STCRYPT_CHECK_WIN( SetEvent(local_term_event) );

				if( WaitForSingleObject(bg_thread_h, INFINITE)!=WAIT_OBJECT_0 ){
					STCRYPT_LOG_PRINT_W_EX(L"ERROR: ", "WaitForSingleObject() on bg thread have failed.");
				}

				STCRYPT_CHECK_WIN( CloseHandle(local_term_event) );
				STCRYPT_CHECK_WIN( CloseHandle(global_term_event) );

			}catch(...){};

			return exit_process_orig( uExitCode );
		}


	}

//================================================================================================================================================
	DWORD WINAPI bg_thread_proc( __in  LPVOID lpParameter ){ 


		//ref self (lock from unloading)
		auto const dll_module = LoadLibraryW(STCRYPT_ABNORMAL_DLL_NAME);
		STCRYPT_CHECK_WIN(dll_module);

		STCRYPT_SCOPE_EXIT([dll_module](){ //self unref library, so it can be unloaded
			FreeLibraryAndExitThread(dll_module, 0 ); 
		});

		STCRYPT_SCOPE_EXIT([](){ 
			DeleteCriticalSection(&share_data_lock);
		});

		auto const kernel32_handle = GetModuleHandle(L"kernel32");
		STCRYPT_CHECK_WIN(kernel32_handle);

		// attached in init
		STCRYPT_SCOPE_EXIT([](){ detach__exit_process(); });

		attach__load_library_w(kernel32_handle); 
		STCRYPT_SCOPE_EXIT([](){ detach__load_library_w(); });

		STCRYPT_SCOPE_EXIT([](){ 
			
			EnterCriticalSection(&share_data_lock);
			STCRYPT_SCOPE_EXIT([](){ LeaveCriticalSection(&share_data_lock); });

			if(mnaza_c::is_attached__MegaFunction() ){
				mnaza_c::detach__MegaFunction();

				STCRYPT_LOG_W_STRING(L"Detached MegaFunction().");
			}
		});

		// waiting for term signals
		STCRYPT_CHECK( global_term_event );
		STCRYPT_CHECK( local_term_event );
		boost::array<HANDLE,2> handles= {{global_term_event, local_term_event}};

		auto const wait_result = WaitForMultipleObjects( handles.size(), handles.data(), false, INFINITE);
		STCRYPT_CHECK_WIN( wait_result==WAIT_OBJECT_0 || wait_result==WAIT_OBJECT_0+1 );

		if(wait_result==WAIT_OBJECT_0){
			STCRYPT_LOG_W_STRING(L"Got global term signal");
		}

		if(wait_result==WAIT_OBJECT_0+1){
			STCRYPT_LOG_W_STRING(L"Got local term signal");
		}

		return 0;

	}
//================================================================================================================================================
	bool is_our_patient(){

		wchar_t module_file_name[2*1024];
		auto const module_file_name_length = GetModuleFileNameW(0 /*curernt proc exe mod*/, &module_file_name[0], sizeof(module_file_name)-1 );
		STCRYPT_CHECK_WIN( module_file_name_length );
		module_file_name[module_file_name_length]=0;

		auto const& module_file_name_as_range = file_name_from_path(module_file_name, module_file_name_length);

		auto const is_our_patiend_f
		= is_equal_case_insensitive( 
			module_file_name_as_range,  
			make_range_from_string_literal(L"stcrypt-abnormal-controller.exe") )

		|| is_equal_case_insensitive( 
			module_file_name_as_range,  
			make_range_from_string_literal(L"outlook.exe") );

		if(is_our_patiend_f){
			STCRYPT_LOG_PRINT_W_EX(L"DETECTED PATIENT: ", module_file_name);

		}

		return is_our_patiend_f;

	}

	
//================================================================================================================================================
	void initialize(){
		BOOST_STATIC_ASSERT( sizeof(PVOID)==sizeof(load_library_w_orig) );

		if( !is_our_patient() ) return; //Not our patient, abort install

		auto const outlmime_handle = GetModuleHandleW(outlmime_str);
		if( outlmime_handle ){
			STCRYPT_LOG_W_STRING(L"'OUTLMIME' found on Init. Patching OUTLMIME!");
			mnaza_c::attach__MegaFunction( outlmime_handle );
		} 

		STCRYPT_CHECK(!global_term_event);
		global_term_event = OpenEvent(SYNCHRONIZE, false, STCRYPT_ABNORMAL_TERM_EVENT_NAME);
		STCRYPT_CHECK_WIN( global_term_event );

		local_term_event  = CreateEvent(0, true, false /*no term sign*/, 0 /*anon*/);
		STCRYPT_CHECK_WIN( local_term_event );

		InitializeCriticalSection(&share_data_lock);

		// possible race --> [create_thread |race| attach_exit_process]
		// if process terminates before attach_exit_process we terminate without any thread clean-up code

		bg_thread_h = CreateThread(0, 0, bg_thread_proc, 0/*param*/, 0, 0);
		STCRYPT_CHECK_WIN( bg_thread_h );

		auto const kernel32_handle = GetModuleHandle(L"kernel32");
		STCRYPT_CHECK_WIN(kernel32_handle);
		attach__exit_process(kernel32_handle); 


	}
} }
//================================================================================================================================================
