//================================================================================================================================================
// FILE: strcypt-cng-register.cpp
// (c) GIE 2010-08-10  16:12
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
//#include "strcypt-cng-register.hpp"

#include "stcrypt-runas.hpp"
#include "stcrypt-cng-revocation-provider_if.hpp"
#include "stcrypt-cng-oid-func-register.hpp"
#include "stcrypt-cng-algs-register.hpp"
#include "stcrypt-cng-oid-register.hpp"

#include "stcrypt-debug.hpp"
#include "stcrypt-exceptions.hpp"
#include "stcrypt-cng-status.hpp"
//================================================================================================================================================

STDAPI DllRegisterServer()
{
	CSP_LOG_TRACE

	try {

		stcrypt::runas_trustedinstaller( [](){
		
			stcrypt::cng_register_algorithms();
			stcrypt::cng_register_oids();
			stcrypt::cng_register_oid_funcs();

			stcrypt::revocation_provider_register();

		});

	} catch(boost::exception const& e) {
		STCRYPT_LOG_DIAGNOSTIC(e);
		return E_FAIL;

	} catch(std::exception const &e)  { 
		STCRYPT_LOG_EXCEPTION_WHAT(e);
		return E_FAIL;

	} catch(...) { 
		STCRYPT_LOG_SIMPLE_MSG("UNHANDLED EXCEPTION"); 
		return E_FAIL;
	}
	return S_OK;
}

STDAPI DllUnregisterServer()
{
	CSP_LOG_TRACE

	try {

		stcrypt::revocation_provider_unregister();

		stcrypt::cng_unregister_oid_funcs();
		stcrypt::cng_unregister_oids();
		stcrypt::cng_unregister_algorithms();

	} catch(boost::exception const& e) {
		STCRYPT_LOG_DIAGNOSTIC(e);
		return E_FAIL;

	} catch(std::exception const &e)  { 
		STCRYPT_LOG_EXCEPTION_WHAT(e);
		return E_FAIL;

	} catch(...) { 
		STCRYPT_LOG_SIMPLE_MSG("UNHANDLED EXCEPTION"); 
		return E_FAIL;
	}
	return S_OK;
}

//================================================================================================================================================
