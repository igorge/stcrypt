//================================================================================================================================================
// FILE: stcrypt-cng-oid-exceptions.h
// (c) GIE 2010-09-14  18:36
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_OID_EXCEPTIONS_2010_09_14_18_36
#define H_GUARD_STCRYPT_CNG_OID_EXCEPTIONS_2010_09_14_18_36
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-debug.hpp"
#include "stcrypt-exceptions.hpp"
//================================================================================================================================================
#define CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_BEGIN try {
#define CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_END	\
	} catch(...) {										\
		return ::stcrypt::impl::cng_od_exception_filter_guard_on_exception();	\
	}																			\
	return ::stcrypt::impl::cng_od_exception_filter_guard_on_ok();				\
	/**/

namespace stcrypt {

	DWORD cng_oid_funcs_exception_filter();

	namespace exception {

		struct oid : virtual stcrypt::exception::root {};
		struct encdec_object : virtual oid {};
		struct encode_object : virtual encdec_object {};
		struct decode_object : virtual encdec_object {};

	}

}



namespace stcrypt { namespace impl {

	inline BOOL cng_od_exception_filter_guard_on_exception()throw() // no throw
	{
		try{

			auto const err_code = ::stcrypt::cng_oid_funcs_exception_filter();
			STCRYPT_LOG_PRINT_EX("SetLastError()", err_code);
			SetLastError(err_code);
			return FALSE;

		}catch(...){
			assert(!"Error while handling an error on guard!");
			SetLastError(ERROR_INTERNAL_ERROR);
			return FALSE;
		}

		return TRUE;
	}

	inline BOOL cng_od_exception_filter_guard_on_ok()throw() // no throw
	{
		try{

			STCRYPT_LOG_PRINT_EX("SetLastError()", ERROR_SUCCESS);
			SetLastError(ERROR_SUCCESS);
			return TRUE;

		}catch(...){
			assert(!"Error while handling an error on guard!");
			SetLastError(ERROR_INTERNAL_ERROR);
			return FALSE;
		}

		return TRUE;
	}

} }


//================================================================================================================================================
#endif
//================================================================================================================================================
