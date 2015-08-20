//================================================================================================================================================
// FILE: stcrypt-cng-revocation-provider-dllmain.cpp
// (c) GIE 2011-02-08  03:56
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
//#include "stcrypt-cng-revocation-provider-dllmain.hpp"
//================================================================================================================================================
#include "stcrypt-cng-oid-exceptions.hpp"
#include "stcrypt-cng-revocation-provider_exception.hpp"

#include <WinCrypt.h>
//================================================================================================================================================
namespace stcrypt {

	namespace {

		void set_abort_status(CERT_REVOCATION_STATUS* const status, decltype(status->dwIndex) const cert_index = 0 ){

			if(status){
				status->dwError = CRYPT_E_NO_REVOCATION_CHECK;
				status->dwIndex = cert_index;
				status->dwReason = CRL_REASON_UNSPECIFIED;
			}

		}

	} // end anon ns



	void cert_verify_revocation(CERT_CONTEXT const& ctx){
		STCRYPT_UNIMPLEMENTED();
	}

}

	BOOL
	WINAPI
	STCRYPT_CertVerifyRevocation(
	__in DWORD dwEncodingType,
	__in DWORD dwRevType,
	__in DWORD cContext,
	__in_ecount(cContext) PVOID rgpvContext[],
	__in DWORD dwFlags,
	__in_opt PCERT_REVOCATION_PARA pRevPara,
	__inout PCERT_REVOCATION_STATUS pRevStatus
	){

		unsigned int current_cert = 0;

		try{

			{// DISABLED
				stcrypt::set_abort_status(pRevStatus, current_cert);
				SetLastError( CRYPT_E_NO_REVOCATION_CHECK );
				return FALSE;
			}

			CSP_LOG_TRACE

			STCRYPT_CHECK( dwRevType==CERT_CONTEXT_REVOCATION_TYPE );
			STCRYPT_CHECK( cContext>0 );
			STCRYPT_CHECK( rgpvContext );
			
			std::for_each( &rgpvContext[0], &rgpvContext[0]+cContext, [&](void * const cert_context_ptr){
				stcrypt::cert_verify_revocation( *static_cast<CERT_CONTEXT*>( cert_context_ptr ) );
				++current_cert;
			});

		}catch(stcrypt::exception::cert_revoc::abort_check const&){
			stcrypt::set_abort_status(pRevStatus, current_cert);
			SetLastError( CRYPT_E_NO_REVOCATION_CHECK );
			return FALSE;

		}catch(...){ // on any other exception we report that we failed to check cert validity
			stcrypt::set_abort_status(pRevStatus, current_cert);
			SetLastError( CRYPT_E_NO_REVOCATION_CHECK );
			return FALSE;
		}

		SetLastError(ERROR_SUCCESS);
		return TRUE;

}

//CRYPT_OID_VERIFY_REVOCATION_FUNC

//================================================================================================================================================
