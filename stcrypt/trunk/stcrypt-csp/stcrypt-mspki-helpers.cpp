//================================================================================================================================================
// FILE: stcrypt-mspki-helpers.cpp
// (c) GIE 2010-04-22  17:54
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-mspki-helpers.hpp"
//================================================================================================================================================
namespace stcrypt { namespace mspki {

	void cert_str_to_name(std::wstring const& cert_str, cert_name_blob_t& cert_name){

		CERT_NAME_BLOB& cert_name_blob = cert_name.m_blob;
		std::vector<BYTE>& data = cert_name.m_storage;

		cert_name_blob = CERT_NAME_BLOB();

		DWORD const p_encoding_type = X509_ASN_ENCODING;
		DWORD const p_str_type = CERT_X500_NAME_STR;

		if( CertStrToNameW(
			p_encoding_type, 
			cert_str.c_str(), 
			p_str_type, 
			NULL,
			0, 
			&cert_name_blob.cbData, 
			NULL) ==0){
				STCRYPT_THROW_EXCEPTION(mspki::exception::str_to_name_failed());
		}

		data.resize(cert_name_blob.cbData);
		cert_name_blob.pbData = &data[0];
		if( !CertStrToNameW(p_encoding_type, cert_str.c_str(), 
			p_str_type, NULL, &data[0], &cert_name_blob.cbData, NULL) ){
			STCRYPT_THROW_EXCEPTION(mspki::exception::str_to_name_failed());
		} 


	}
	
} }
//================================================================================================================================================
