//================================================================================================================================================
// FILE: ms_cert_sign.h
// (c) GIE 2011-02-04  02:55
//
//================================================================================================================================================
#ifndef H_GUARD_MS_CERT_SIGN_2011_02_04_02_55
#define H_GUARD_MS_CERT_SIGN_2011_02_04_02_55
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "ms_cert_store_utils.hpp"

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
//================================================================================================================================================
namespace ms_cert {

	inline 	
	std::vector<unsigned char> create_req_blob(stcrypt::cert_name_t const& name, NCRYPT_KEY_HANDLE const subject_public_key, boost::optional<stcrypt::cert_name_t const&> const& issuer = boost::none){

		auto const& subject_name_2 = name.x500_string();
		auto const subject_name = subject_name_2.c_str();

		wchar_t const*const dummy_issuer_name = L"";

		boost::uuids::uuid const serial_and_unique_id( (boost::uuids::random_generator()()) );

		std::vector<BYTE> serial_blob_data;
		serial_blob_data.reserve( serial_and_unique_id.static_size() );
		std::copy(serial_and_unique_id.begin(), serial_and_unique_id.end(), std::back_inserter(serial_blob_data) );


 		CERT_INFO	cert_info={0};
 
 		cert_info.dwVersion = CERT_V3;
 
		cert_info.SerialNumber.pbData = serial_blob_data.data();
		cert_info.SerialNumber.cbData = serial_blob_data.size();

		cert_info.SubjectUniqueId.pbData = serial_blob_data.data();
		cert_info.SubjectUniqueId.cbData = serial_blob_data.size();

		CRYPT_ALGORITHM_IDENTIFIER signature_alg={OID_G34311_DSTU4145_SIGN,0};

		cert_info.SignatureAlgorithm = signature_alg;

 		SYSTEMTIME cs;
 		GetSystemTime(&cs);
 		{auto const r = SystemTimeToFileTime(&cs, &cert_info.NotBefore); assert(r);}
 		cs.wYear += 1; 
 		{auto const r = SystemTimeToFileTime(&cs, &cert_info.NotAfter); assert(r);}

		std::vector<unsigned char> subject_name_blob_data;
		std::vector<unsigned char> issuer_name_blob_data;

		ms_cert::cert_str_to_name_blob(subject_name, cert_info.Subject, subject_name_blob_data);

		if(issuer){
			auto const& issuer_x500_string = issuer->x500_string();
			ms_cert::cert_str_to_name_blob(issuer_x500_string.c_str(), cert_info.Issuer, issuer_name_blob_data);
		} else {
			ms_cert::cert_str_to_name_blob(dummy_issuer_name, cert_info.Issuer, issuer_name_blob_data);
		}
 
  		DWORD pub_key_size;
  		if( !CryptExportPublicKeyInfoEx(subject_public_key, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, OID_DSTU4145_PUBKEY, 0, 0, 0, &pub_key_size) ){
  			STCRYPT_UNEXPECTED();
 		}
		STCRYPT_CHECK(pub_key_size!=0);
		
		std::vector<unsigned char> subject_pub_key_info_data(pub_key_size);
		if( !CryptExportPublicKeyInfoEx(subject_public_key, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, OID_DSTU4145_PUBKEY, 0, 0,  static_cast<CERT_PUBLIC_KEY_INFO*>( static_cast<void*>(subject_pub_key_info_data.data())), &pub_key_size) ){
			STCRYPT_UNEXPECTED();
		}
		subject_pub_key_info_data.resize(pub_key_size);

		CERT_PUBLIC_KEY_INFO * subject_pub_key_info = static_cast<CERT_PUBLIC_KEY_INFO*>( static_cast<void*>( subject_pub_key_info_data.data() ) );
		cert_info.SubjectPublicKeyInfo = *subject_pub_key_info;

		DWORD cert_encoded_size = 0;
		STCRYPT_CHECK( CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &cert_info, 0, 0, 0, &cert_encoded_size)!=0 );
		STCRYPT_CHECK( cert_encoded_size!=0 );

		std::vector<unsigned char> cert_to_be_signed_blob(cert_encoded_size);
		STCRYPT_CHECK( CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &cert_info, 0, 0, cert_to_be_signed_blob.data(), &cert_encoded_size)!=0 );
		cert_to_be_signed_blob.resize( cert_encoded_size );

		return cert_to_be_signed_blob;
	}


}
//================================================================================================================================================
#endif
//================================================================================================================================================
