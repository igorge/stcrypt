//================================================================================================================================================
// FILE: stcrypt-cng-revocation-provider.cpp
// (c) GIE 2011-02-08  04:05
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
//#include "stcrypt-cng-revocation-provider.hpp"
//================================================================================================================================================
#include "stcrypt-cng-dll-utils.hpp"
#include "stcrypt-cng-oid-exceptions.hpp"
#include "stcrypt-cng-register-exception.hpp"

//================================================================================================================================================
namespace stcrypt {

	void revocation_provider_register(){
		CSP_LOG_TRACE

		if ( !CryptRegisterDefaultOIDFunction(X509_ASN_ENCODING, CRYPT_OID_VERIFY_REVOCATION_FUNC, CRYPT_REGISTER_FIRST_INDEX, self_dll_path().c_str()) ) {
			auto const last_error = GetLastError();
			if (last_error!=ERROR_FILE_EXISTS){
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_func_registration_failed() << exception::error_str_einfo(CRYPT_OID_VERIFY_REVOCATION_FUNC) << exception::getlasterror_einfo(last_error) );
			} else {
				STCRYPT_LOG_A_STRING("WARN: Revocation provider already registered");
			}
		}

	}

	void revocation_provider_unregister(){
		CSP_LOG_TRACE
		//STCRYPT_UNIMPLEMENTED();
	}

}
//================================================================================================================================================
