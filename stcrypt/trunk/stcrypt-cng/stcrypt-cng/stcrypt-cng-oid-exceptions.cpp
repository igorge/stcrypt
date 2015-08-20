//================================================================================================================================================
// FILE: stcrypt-cng-oid-exceptions.cpp
// (c) GIE 2010-09-14  18:36
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-oid-exceptions.hpp"
//================================================================================================================================================
namespace stcrypt {

#define STCRYPT_CNG_OID_FUNC_CPP_EXCEPTION_ENTRY(cpp_exception, map_to_code)	\
} catch(cpp_exception const& e) {\
	STCRYPT_LOG_DIAGNOSTIC(e);\
	return map_to_code; \
	/**/ 

	DWORD cng_oid_funcs_exception_filter(){
		try { 
			throw; 
		} catch(std::bad_alloc const&) {
			return ERROR_NOT_ENOUGH_MEMORY;

			STCRYPT_CNG_OID_FUNC_CPP_EXCEPTION_ENTRY(stcrypt::exception::small_buffer, STATUS_BUFFER_TOO_SMALL);
			STCRYPT_CNG_OID_FUNC_CPP_EXCEPTION_ENTRY(stcrypt::exception::signature_verification_failed, ERROR_INVALID_DATA);

		} catch(boost::exception const& e) {
			STCRYPT_LOG_DIAGNOSTIC(e);
			return  ERROR_UNHANDLED_EXCEPTION;

		} catch(std::exception const &e)  { 
			STCRYPT_LOG_EXCEPTION_WHAT(e);
			return  ERROR_UNHANDLED_EXCEPTION;

		} catch(...) { 
			STCRYPT_LOG_SIMPLE_MSG("UNHANDLED EXCEPTION"); 
			return  ERROR_UNHANDLED_EXCEPTION;
		}

		return STATUS_SUCCESS;

	}


}
//================================================================================================================================================
