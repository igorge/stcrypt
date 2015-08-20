//================================================================================================================================================
// FILE: stcrypt-cng-exception-filter.h
// (c) GIE 2010-08-10  14:37
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_EXCEPTION_FILTER_2010_08_10_14_37
#define H_GUARD_STCRYPT_CNG_EXCEPTION_FILTER_2010_08_10_14_37
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"
#include "stcrypt-debug.hpp"
#include "stcrypt-cng-status.hpp"
//================================================================================================================================================
#define CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN	try {
#define CNG_CSP_CPP_EXCEPTION_GUARD_END	\
	} catch(...){		\
		NTSTATUS const err_code = ::stcrypt::cng_csp_exception_filter();	\
		STCRYPT_LOG_PRINT_EX("NTSTATUS", err_code);					    	\
		return err_code;											\
	}	                                                            \
	STCRYPT_LOG_PRINT_EX("NTSTATUS", STATUS_SUCCESS);          \
	return STATUS_SUCCESS;                                                    \
	/**/

#define CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN try {
#define CNG_CSP_N_CPP_EXCEPTION_GUARD_END \
	} catch(...){		\
		SECURITY_STATUS const err_code = ::stcrypt::cng_csp_n_exception_filter();	\
		STCRYPT_LOG_PRINT_EX("SECURITY_STATUS", err_code);					    	\
		return err_code;											\
	}	                                                            \
	STCRYPT_LOG_PRINT_EX("SECURITY_STATUS", ERROR_SUCCESS);          \
	return ERROR_SUCCESS;                                                    \
	/**/

namespace stcrypt {
	NTSTATUS cng_csp_exception_filter();
	SECURITY_STATUS cng_csp_n_exception_filter();
}
//================================================================================================================================================
#endif
//================================================================================================================================================
