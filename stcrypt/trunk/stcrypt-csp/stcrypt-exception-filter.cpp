//================================================================================================================================================
// FILE: stcrypt-exception-filter.cpp
// (c) GIE 2009-11-02  13:18
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
//#include "stcrypt_exception_filter.hpp"
//================================================================================================================================================
#include "stcrypt-debug.hpp"
#include "stcrypt-exceptions.hpp"
//================================================================================================================================================
#include <stdexcept>
//================================================================================================================================================
#ifdef STCRYPT_DEBUG
	#define STCRYPT_LOG_DIAGNOSTIC(e) printf("[STCRYPT] %s\n", boost::diagnostic_information(e).c_str() ) 
#else
	#define STCRYPT_LOG_DIAGNOSTIC(e) (e)
#endif
//================================================================================================================================================
#define STCRYPT_CPP_EXCEPTION_ENTRY(cpp_exception, map_to_code)	\
		} catch(cpp_exception const& e) {\
		STCRYPT_LOG_DIAGNOSTIC(e);\
		return map_to_code; \
		/**/

//================================================================================================================================================
namespace stcrypt {

//================================================================================================================================================
	DWORD csp_exception_filter()
	{
		try { 
			throw; 
		} catch(std::bad_alloc const&) {
			return NTE_NO_MEMORY;

		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_data, NTE_BAD_DATA);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_signature, NTE_BAD_SIGNATURE);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_len, NTE_BAD_LEN);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::more_data, ERROR_MORE_DATA);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::no_more_items, ERROR_NO_MORE_ITEMS);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::no_crypt_dll_found, NTE_PROVIDER_DLL_FAIL);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::badflags, NTE_BAD_FLAGS);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::badtype, NTE_BAD_TYPE);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::badalg, NTE_BAD_ALGID);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::keyset_exists, NTE_EXISTS);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_keyset_entry, NTE_KEYSET_ENTRY_BAD);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_keyset, NTE_BAD_KEYSET);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_key, NTE_BAD_KEY);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::no_key, NTE_NO_KEY);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::keyset_notdef, NTE_KEYSET_NOT_DEF);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::hash_finilized, NTE_BAD_HASH_STATE);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_hash, NTE_BAD_HASH);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_permissions, NTE_PERM);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::unimplemented, ERROR_CALL_NOT_IMPLEMENTED);
		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::invalid_parameter, ERROR_INVALID_PARAMETER);
		

		STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_key_op, NTE_BAD_KEY);

		} catch(stcrypt::exception::cryptoapi_error const& e){
			STCRYPT_LOG_DIAGNOSTIC(e);

			DWORD const * const errcode = boost::get_error_info<stcrypt::exception::cryptoapi_einfo>(e);

			if(errcode)
				return *errcode;
			else {
				assert(!"got cryptoapi_error() without error code");
				return NTE_FAIL;
			}

		} catch(boost::exception const& e) {
			STCRYPT_LOG_DIAGNOSTIC(e);
			return  NTE_FAIL ;

		} catch(std::exception const &e)  { 
			printf("[EXCEPTION][%s]\n", e.what() );
			return NTE_FAIL ;

		} catch(...) { 
			printf("[UNHANDLED EXCEPTIONs]\n"); 
			return NTE_FAIL;
		}

		return ERROR_SUCCESS;
	}

}
//================================================================================================================================================
