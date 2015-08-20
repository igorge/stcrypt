//================================================================================================================================================
// FILE: stcrypt-cng-exception-filter.cpp
// (c) GIE 2010-08-10  14:37
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-debug.hpp"
#include "stcrypt-cng-exception-filter.hpp"
//================================================================================================================================================
//================================================================================================================================================
#define STCRYPT_CPP_EXCEPTION_ENTRY(cpp_exception, map_to_code)	\
		} catch(cpp_exception const& e) {\
		STCRYPT_LOG_DIAGNOSTIC(e);\
		return map_to_code; \
		/**/ 

namespace stcrypt {

	NTSTATUS cng_csp_exception_filter(){

		try { 
			throw; 
		} catch(std::bad_alloc const&) {
			return STATUS_NO_MEMORY;

			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::key_import_failed, STATUS_NOT_SUPPORTED);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::invalid_blob_type, STATUS_NOT_SUPPORTED);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::signature_verification_failed, STATUS_INVALID_SIGNATURE);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_signature_size, STATUS_INVALID_PARAMETER);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_signature, STATUS_INVALID_PARAMETER);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::invalid_cng_handle_op, STATUS_NOT_SUPPORTED);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::small_buffer, STATUS_BUFFER_TOO_SMALL);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::hash_finilized, STATUS_INVALID_PARAMETER);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::hmac_not_supported, STATUS_HMAC_NOT_SUPPORTED);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::invalid_parameter_handle, STATUS_INVALID_HANDLE);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::invalid_handle, STATUS_INVALID_HANDLE);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::invalid_parameter, STATUS_INVALID_PARAMETER);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::badalg, STATUS_NOT_SUPPORTED);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::invalid_prop, STATUS_NOT_SUPPORTED);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::unimplemented, STATUS_NOT_IMPLEMENTED);

		} catch(boost::exception const& e) {
			STCRYPT_LOG_DIAGNOSTIC(e);
			return  STATUS_UNSUCCESSFUL;

		} catch(std::exception const &e)  { 
			STCRYPT_LOG_EXCEPTION_WHAT(e);
			return  STATUS_UNSUCCESSFUL;

		} catch(...) { 
			STCRYPT_LOG_SIMPLE_MSG("UNHANDLED EXCEPTION"); 
			return  STATUS_UNSUCCESSFUL;
		}

		return STATUS_SUCCESS;

	}


	SECURITY_STATUS cng_csp_n_exception_filter(){

		try { 
			throw; 
		} catch(std::bad_alloc const&) {
			return NTE_NO_MEMORY;

			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::signature_verification_failed, NTE_BAD_SIGNATURE);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_keyset_entry, NTE_BAD_KEYSET);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::no_key, NTE_BAD_KEYSET);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::bad_keyset, NTE_BAD_KEYSET);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::keyset_exists, NTE_EXISTS);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::unimplemented, NTE_NOT_SUPPORTED);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::invalid_parameter_handle, NTE_INVALID_HANDLE);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::invalid_parameter, NTE_INVALID_PARAMETER);
			STCRYPT_CPP_EXCEPTION_ENTRY(stcrypt::exception::no_more_items, NTE_NO_MORE_ITEMS);

		} catch(boost::exception const& e) {
			STCRYPT_LOG_DIAGNOSTIC(e);
			return  NTE_INTERNAL_ERROR;

		} catch(std::exception const &e)  { 
			STCRYPT_LOG_EXCEPTION_WHAT(e);
			return  NTE_INTERNAL_ERROR;

		} catch(...) { 
			STCRYPT_LOG_SIMPLE_MSG("UNHANDLED EXCEPTION"); 
			return  NTE_INTERNAL_ERROR;
		}

		return ERROR_SUCCESS;

	}

}
//================================================================================================================================================
