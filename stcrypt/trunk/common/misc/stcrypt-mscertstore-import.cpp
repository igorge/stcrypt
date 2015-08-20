//================================================================================================================================================
// FILE: stcrypt-mscertstore-import.cpp
// (c) GIE 2010-04-15  12:59
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-mscertstore-import.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-exceptions.hpp"

#include "boost/scope_exit.hpp"
//================================================================================================================================================
namespace stcrypt {


	void import_into_ms_store(char const* const blob, size_t const blob_size){
		
		CERT_BLOB ms_cert_blob = {blob_size, reinterpret_cast<BYTE*>(const_cast<char*>(blob) ) };

		PCCERT_CONTEXT ms_cert_ctx = NULL;

		if (!CryptQueryObject (
			CERT_QUERY_OBJECT_BLOB,
			&ms_cert_blob,
			CERT_QUERY_CONTENT_FLAG_ALL,
			CERT_QUERY_FORMAT_FLAG_ALL,
			0,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			(const void ** )(&ms_cert_ctx) ) ) 
		STCRYPT_UNEXPECTED1("CryptQueryObject have failed");

		BOOST_SCOPE_EXIT( (ms_cert_ctx) ){
			BOOL const r = CertFreeCertificateContext(ms_cert_ctx);
			assert(r!=0);
		} BOOST_SCOPE_EXIT_END

		HCERTSTORE const ms_cert_store = CertOpenStore (
			CERT_STORE_PROV_SYSTEM,
			0,
			0,
			/* CERT_STORE_OPEN_EXISTING_FLAG | */
			CERT_SYSTEM_STORE_CURRENT_USER, //CERT_SYSTEM_STORE_LOCAL_MACHINE,
			L"ADDRESSBOOK");
		if(ms_cert_store==0) STCRYPT_UNEXPECTED1("CertOpenStore have failed");

		BOOST_SCOPE_EXIT( (ms_cert_store) ){
			BOOL const r = CertCloseStore (ms_cert_store,0);
			assert(r!=0);
		} BOOST_SCOPE_EXIT_END

			if (!CertAddCertificateContextToStore (
				ms_cert_store,
				ms_cert_ctx,
				CERT_STORE_ADD_ALWAYS,
				NULL))
			STCRYPT_UNEXPECTED1("CertAddCertificateContextToStore have failed");



	}

}
//================================================================================================================================================
