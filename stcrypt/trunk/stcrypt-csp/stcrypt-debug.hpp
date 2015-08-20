//================================================================================================================================================
// FILE: stcrypt-debug.h
// (c) GIE 2009-11-02  13:26
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_DEBUG_2009_11_02_13_26
#define H_GUARD_STCRYPT_DEBUG_2009_11_02_13_26
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include <boost/format.hpp>

#ifdef STCRYPT_CNG
#include "../stcrypt-cng/stcrypt-cng/stcrypt-debug-logger.hpp"
#endif

#include <assert.h>
//================================================================================================================================================
#ifdef STCRYPT_UNIT_TEST
#define STCRYPT_PRIVATE public
#define STCRYPT_PROTECTED public
#else
#define STCRYPT_PRIVATE private
#define STCRYPT_PROTECTED protected
#endif
//================================================================================================================================================
#ifdef NDEBUG
	/*release*/
	#define STCRYPT_TRACE_API_ENTRY_CALL
	#define STCRYPT_CHECKED_BUILD
#else
	/*debug*/
	#define STCRYPT_DEBUG
	#define STCRYPT_CHECKED_BUILD
	#define STCRYPT_TRACE_API_ENTRY_CALL
#endif

#define STCRYPT_DEBUG_KEYS_W_COOKIES
//================================================================================================================================================
#ifdef STCRYPT_CNG
	#define	STCRYPT_LOG_W_STRING(x) do{ auto const log = ::stcrypt::logger::get_logger(); if(log)log->log(x); } while(false)
	#define	STCRYPT_LOG_A_STRING(x) do{ auto const log = ::stcrypt::logger::get_logger(); if(log)log->log(x); } while(false)
	#define STCRYPT_LOG_INC_LEVEL()  do{ auto const log = ::stcrypt::logger::get_logger(); if(log)log->inc_level(); } while(false)
	#define STCRYPT_LOG_DEC_LEVEL()  do{ auto const log = ::stcrypt::logger::get_logger(); if(log)log->dec_level(); } while(false)
#else

    namespace stcrypt { namespace debug {
        inline
        void simple_log_str(wchar_t const*const msg){
            wprintf(L"[%s]\n", msg);
        }

		inline
		void simple_log_str(std::wstring const& msg){
			wprintf(L"[%s]\n", msg.c_str());
		}
    } }

	#define	STCRYPT_LOG_W_STRING(x) ::stcrypt::debug::simple_log_str(x)
	#define	STCRYPT_LOG_A_STRING(x) printf( x.c_str() )
	#define STCRYPT_LOG_INC_LEVEL()  (void)0
	#define STCRYPT_LOG_DEC_LEVEL()  (void)0
#endif

#define STCRYPT_LOG_PRINT_EX(pref,m)	\
	do {								\
		std::string const& msg = (::boost::format("%1% %2%\n") % pref % m).str();	\
		/*OutputDebugStringA(msg.c_str());*/\
		STCRYPT_LOG_A_STRING( msg );			\
	} while(false)						\
	/**/

#define STCRYPT_LOG_PRINT_W_EX(pref,m)	\
	do {								\
		std::wstring const& msg = (::boost::wformat(L"%1% %2%\n") % pref % m).str();	\
		/*OutputDebugStringW(msg.c_str());*/\
		STCRYPT_LOG_W_STRING( msg );			\
	} while(false)						\
	/**/


namespace stcrypt {
	unsigned int const debug_key_cookie=0xBADF00d1;
}

namespace CPS_DEBUG_TRACER {
	struct tracer {
		tracer(char const * const func): m_func( func ) {
			STCRYPT_LOG_PRINT_EX("{{{", m_func);
			STCRYPT_LOG_INC_LEVEL();
		}
		~tracer(){
			STCRYPT_LOG_DEC_LEVEL();
			STCRYPT_LOG_PRINT_EX("}}}", m_func);
		}
	private: 
		char const * const m_func;
	};
}

//================================================================================================================================================
#ifdef STCRYPT_TRACE_API_ENTRY_CALL
	#ifndef CSP_LOG_TRACE
	#define CSP_LOG_TRACE	\
		::CPS_DEBUG_TRACER::tracer CPS_TRACER_UIURFW52(__FUNCTION__);
	#endif
#else
	#define CSP_LOG_TRACE
#endif

#define STCRYPT_TRACE_CALL CSP_LOG_TRACE

#ifdef STCRYPT_CNG
	#define STCRYPT_LOG_DIAGNOSTIC(e)	  STCRYPT_LOG_A_STRING( boost::diagnostic_information(e) )
	#define STCRYPT_LOG_EXCEPTION_WHAT(e) STCRYPT_LOG_A_STRING( (::boost::format("[EXCEPTION][%1%]") % e.what()).str() )
	#define STCRYPT_LOG_SIMPLE_MSG(m)	  STCRYPT_LOG_A_STRING(m)
#else
	#ifdef STCRYPT_DEBUG
		#define STCRYPT_LOG_DIAGNOSTIC(e) printf("[STCRYPT] %s\n", boost::diagnostic_information(e).c_str() ) 
		#define STCRYPT_LOG_EXCEPTION_WHAT(e) printf("[EXCEPTION][%s]\n", e.what() );
		#define STCRYPT_LOG_SIMPLE_MSG(m) printf("[%s]\n", m);
	#else
		#define STCRYPT_LOG_DIAGNOSTIC(e) ((void)e)
		#define STCRYPT_LOG_EXCEPTION_WHAT(e) ((void)e)
		#define STCRYPT_LOG_SIMPLE_MSG(m)
	#endif 
#endif

//================================================================================================================================================
#endif
//================================================================================================================================================
