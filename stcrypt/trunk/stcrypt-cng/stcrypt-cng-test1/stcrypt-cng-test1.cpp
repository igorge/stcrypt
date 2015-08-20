// stcrypt-cng-test1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "../../stcrypt-csp-test/csp-test-common.hpp"
#include "../../stcrypt-csp/stcrypt-mspki-helpers.hpp"
#include "../stcrypt-cng/stcrypt-crypto-alg-ids.h"
#include "../stcrypt-cng/stcrypt-exceptions.hpp"
#include "../../common/libs/gieutils/gie/gie_auto_vector.hpp"

#include <boost/format.hpp>
#include <boost/scope_exit.hpp>
#include <boost/assign.hpp>
#include <boost/array.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/thread.hpp>
#include <boost/filesystem/path.hpp>

using boost::assign::operator +=;

#include <vector>
#include <fstream>
#include <stdint.h>

#define SECURITY_WIN32
#include <Security.h>
#include <Ntsecapi.h>
#include <Sddl.h>
#include <LsaLookup.h>
#include <Ntsecpkg.h>
#include <Psapi.h>

namespace stcrypt { namespace mspki2 {

	namespace exception {
		struct conversion_failed : virtual stcrypt::exception::root {};
		struct str_to_name_failed : virtual conversion_failed {};
	}

	template <class VectorT>
	void cert_str_to_name(wchar_t const*const cert_str, CERT_NAME_BLOB& cert_name_blob, VectorT& cert_name_blob_data){

		VectorT& data = cert_name_blob_data;

		cert_name_blob = CERT_NAME_BLOB();

		DWORD const p_encoding_type = X509_ASN_ENCODING;
		DWORD const p_str_type = CERT_X500_NAME_STR;

		if( CertStrToNameW(
			p_encoding_type, 
			cert_str, 
			p_str_type, 
			NULL,
			0, 
			&cert_name_blob.cbData, 
			NULL) ==0){
				STCRYPT_THROW_EXCEPTION(mspki::exception::str_to_name_failed());
		}

		data.resize(cert_name_blob.cbData);
		cert_name_blob.pbData = &data[0];
		if( !CertStrToNameW(p_encoding_type, cert_str, 
			p_str_type, NULL, &data[0], &cert_name_blob.cbData, NULL) ){
				STCRYPT_THROW_EXCEPTION(mspki::exception::str_to_name_failed());
		} 



	}

} }


void import_into_ms_store2(PCCERT_CONTEXT ms_cert_ctx, std::wstring const& cert_store_name ){




	HCERTSTORE const ms_cert_store = CertOpenStore (
		CERT_STORE_PROV_SYSTEM,
		0,
		0,
		/* CERT_STORE_OPEN_EXISTING_FLAG | */
		CERT_SYSTEM_STORE_CURRENT_USER, //CERT_SYSTEM_STORE_LOCAL_MACHINE,
		cert_store_name.c_str());

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

void save_cert_to_file(PCCERT_CONTEXT const ms_cert_ctx, std::wstring const& file_name_no_ext){

	std::wstring const file_name = file_name_no_ext +L".p7b";

	HCERTSTORE const ms_cert_store = CertOpenStore (
		CERT_STORE_PROV_MEMORY,
		0,
		0,
		0,
		0);
	if(ms_cert_store==0) {
		DWORD const errcode = GetLastError();
		std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 

		STCRYPT_UNEXPECTED1("CertOpenStore have failed");
	}

	BOOST_SCOPE_EXIT( (ms_cert_store) ){
		BOOL const r = CertCloseStore (ms_cert_store,0);
		assert(r!=0);
	} BOOST_SCOPE_EXIT_END

		if (!CertAddCertificateContextToStore (
			ms_cert_store,
			ms_cert_ctx,
			CERT_STORE_ADD_ALWAYS,
			NULL)){

				DWORD const errcode = GetLastError();
				std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 
				STCRYPT_UNEXPECTED1("CertAddCertificateContextToStore have failed");

		}

		HANDLE hFile;
		if (hFile = CreateFile(
			file_name.c_str(), // The file name
			GENERIC_WRITE, // Access mode: write to this file
			0, // Share mode
			NULL, // Uses the DACL created previously
			CREATE_ALWAYS, // How to create
			FILE_ATTRIBUTE_NORMAL, // File attributes
			NULL)) // Template
		{
		}
		else
		{
			STCRYPT_UNEXPECTED();
		}
		BOOST_SCOPE_EXIT( (hFile) ) {
			BOOL const r = CloseHandle(hFile); assert(r);
		}  BOOST_SCOPE_EXIT_END

			if(CertSaveStore(
				ms_cert_store, // Store handle
				PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
				//CERT_STORE_SAVE_AS_STORE, 
				CERT_STORE_SAVE_AS_PKCS7,
				CERT_STORE_SAVE_TO_FILE,
				hFile, // The handle of an open disk file
				0)) // dwFlags: No flags are needed here.
			{
				printf("Saved the memory store to disk. \n");
			} else {
				DWORD const errcode = GetLastError();
				std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 
			}



}


template <class Allocator>
std::vector<typename Allocator::value_type, Allocator> cert_create(wchar_t const*const issuer_name, wchar_t const*const subject_name, NCRYPT_KEY_HANDLE const issuer_priv_key, NCRYPT_KEY_HANDLE const subject_pub_key, unsigned char const*const issuer_id, size_t const issuer_id_size, Allocator const& alloc )
{
	assert(issuer_priv_key);
	assert(subject_pub_key);

	typedef gie::monotonic::fixed_storage<4*1024> fixed_stor_t;
	typedef gie::monotonic::allocator<BYTE, fixed_stor_t> byte_allocator_t;
	typedef std::vector<BYTE, byte_allocator_t>			  local_byte_array_t;

	typedef gie::monotonic::allocator<BYTE, fixed_stor_t, boost::alignment_of<CERT_PUBLIC_KEY_INFO>::value > cert_public_key_info_byte_allocator_t;
	typedef std::vector<BYTE, cert_public_key_info_byte_allocator_t>									     cert_public_key_info_local_byte_array_t;

	fixed_stor_t	local_stor;

	CRYPT_ALGORITHM_IDENTIFIER signature_alg={OID_G34311_DSTU4145_SIGN,0};

	//serial

	boost::uuids::uuid const serial_and_unique_id( (boost::uuids::random_generator()()) );

	local_byte_array_t serial_blob_data( (byte_allocator_t(local_stor)) );
	serial_blob_data.reserve( serial_and_unique_id.static_size() );
	std::copy(serial_and_unique_id.begin(), serial_and_unique_id.end(), std::back_inserter(serial_blob_data) );


	//uint64_t serial_number = 0;
	//boost::array<unsigned char, sizeof(serial_number)/*16*/> serial_blob_data;
	//auto const r = memcpy_s(serial_blob_data.data(), serial_blob_data.size(), &serial_number, sizeof(serial_number) ); assert(r==0);
	
	//issuer
	local_byte_array_t	issuer_data( (byte_allocator_t(local_stor)) );
	local_byte_array_t	subject_data( (byte_allocator_t(local_stor)) );


	CERT_INFO	cert_info={0};

	cert_info.dwVersion = CERT_V3;

	cert_info.SerialNumber.pbData = serial_blob_data.data();
	cert_info.SerialNumber.cbData = serial_blob_data.size();

	cert_info.SubjectUniqueId.pbData = serial_blob_data.data();
	cert_info.SubjectUniqueId.cbData = serial_blob_data.size();

	if(issuer_id){
		cert_info.IssuerUniqueId.pbData = const_cast<unsigned char*>( issuer_id );
		cert_info.IssuerUniqueId.cbData = issuer_id_size;
	} else {
		cert_info.IssuerUniqueId.pbData = serial_blob_data.data();
		cert_info.IssuerUniqueId.cbData = serial_blob_data.size();
	}

	cert_info.SignatureAlgorithm = signature_alg;

	stcrypt::mspki2::cert_str_to_name(issuer_name, cert_info.Issuer, issuer_data);

	SYSTEMTIME cs;
	GetSystemTime(&cs);
	{auto const r = SystemTimeToFileTime(&cs, &cert_info.NotBefore); assert(r);}
	cs.wYear += 1; 
	{auto const r = SystemTimeToFileTime(&cs, &cert_info.NotAfter); assert(r);}


	stcrypt::mspki2::cert_str_to_name(subject_name, cert_info.Subject, subject_data);

	//

	DWORD pub_key_size;
	if( !CryptExportPublicKeyInfoEx(subject_pub_key, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, OID_DSTU4145_PUBKEY, 0, 0, 0, &pub_key_size) ){
		STCRYPT_UNEXPECTED();
	}
	if( !pub_key_size ) STCRYPT_UNEXPECTED();

	cert_public_key_info_local_byte_array_t	subject_pub_key_info_data( (cert_public_key_info_byte_allocator_t(local_stor)) );
	subject_pub_key_info_data.resize(pub_key_size);

	if( !CryptExportPublicKeyInfoEx(subject_pub_key, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, OID_DSTU4145_PUBKEY, 0, 0,  static_cast<CERT_PUBLIC_KEY_INFO*>( static_cast<void*>(subject_pub_key_info_data.data())), &pub_key_size) ){
		STCRYPT_UNEXPECTED();
	}
	subject_pub_key_info_data.resize(pub_key_size);

	CERT_PUBLIC_KEY_INFO * subject_pub_key_info = static_cast<CERT_PUBLIC_KEY_INFO*>( static_cast<void*>( subject_pub_key_info_data.data() ) );

	//cert_info.SubjectPublicKeyInfo.Algorithm.Parameters
	cert_info.SubjectPublicKeyInfo = *subject_pub_key_info;


	DWORD encoded_cert_size = 0;
	if( !CryptSignAndEncodeCertificate(issuer_priv_key, 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &cert_info, &signature_alg, 0, 0, &encoded_cert_size) ){
		STCRYPT_UNEXPECTED();
	}

	std::vector<typename Allocator::value_type, Allocator> encoded_cert( alloc );
	encoded_cert.resize( encoded_cert_size );

	if( !CryptSignAndEncodeCertificate(issuer_priv_key, 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, &cert_info, &signature_alg, 0, encoded_cert.data(), &encoded_cert_size) ){
		STCRYPT_UNEXPECTED();
	}

	encoded_cert.resize( encoded_cert_size );

	return encoded_cert;

}

boost::tuple<NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE> open_or_create_dstu_key(wchar_t const*const key_name, NCRYPT_PROV_HANDLE const already_have_provider_handle = 0, DWORD const key_flags = 0){

	SECURITY_STATUS Status = 0;
	NCRYPT_PROV_HANDLE hProvider = 0;
	NCRYPT_KEY_HANDLE hKey = 0;

	if(!already_have_provider_handle){
		auto Status = NCryptOpenStorageProvider(&hProvider,
			CNG_STCRYPT_KEYSTORAGE,
			0);
		if (FAILED(Status)) STCRYPT_UNEXPECTED1("ERROR: NCryptOpenStorageProvider");
	} else {
		hProvider = already_have_provider_handle;
	}

	BOOST_SCOPE_EXIT((&hProvider)(already_have_provider_handle)) {
		if(hProvider && !already_have_provider_handle){
			auto const status = NCryptFreeObject (hProvider); 
			assert( !FAILED(status) );
		}
	} BOOST_SCOPE_EXIT_END


		// Create an RSA key exchange key-pair in the MS KSP
		// overwriting an existing key with the provided name.
		Status = NCryptCreatePersistedKey(hProvider,
		&hKey,
		/*NCRYPT_RSA_ALGORITHM,*/NCNG_DSTU4145,
		key_name,
		AT_KEYEXCHANGE,
		key_flags/*NCRYPT_OVERWRITE_KEY_FLAG*/);

	if (FAILED(Status) && Status != NTE_EXISTS ) {
		STCRYPT_UNEXPECTED1("ERROR: NCryptCreatePersistedKey");
	}

	BOOST_SCOPE_EXIT((&hKey)) {
		if( hKey ){
			auto const status = NCryptFreeObject (hKey); 
			assert( !FAILED(status) );
		}
	} BOOST_SCOPE_EXIT_END

	if(Status != NTE_EXISTS){
		Status = NCryptFinalizeKey(hKey, 0);
		if (FAILED(Status))  STCRYPT_UNEXPECTED1("ERROR: NCryptFinalizeKey : 0x%x\n");
	} else {
		Status = NCryptOpenKey(hProvider, &hKey, key_name, 0,0 );

		if (FAILED(Status)) {
			STCRYPT_UNEXPECTED1("ERROR: NCryptOpenKey");
		}
	}

	boost::tuple<NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE> tmp( boost::make_tuple(hProvider, hKey) );
	
	hKey = 0;
	hProvider = 0;

	return tmp;

}

PCCERT_CONTEXT cert_context_create(wchar_t const*const issuer_name, wchar_t const*const subject_name, NCRYPT_KEY_HANDLE const issuer_priv_key, NCRYPT_KEY_HANDLE const subject_pub_key, unsigned char const*const issuer_id = 0, size_t const issuer_id_size = 0){

	typedef gie::monotonic::fixed_storage<4*1024>			fixed_stor_t;
	typedef gie::monotonic::allocator<BYTE, fixed_stor_t>	byte_allocator_t;
	typedef std::vector<BYTE, byte_allocator_t>				local_byte_array_t;
	typedef std::vector<wchar_t, byte_allocator_t>			local_wchar_array_t;

	fixed_stor_t local_stor;

	auto const& cert_blob = cert_create( issuer_name, subject_name, issuer_priv_key, subject_pub_key, issuer_id, issuer_id_size, byte_allocator_t(local_stor) );

	PCCERT_CONTEXT tmp_ctx = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert_blob.data(), cert_blob.size() );
	if(!tmp_ctx){STCRYPT_UNEXPECTED();}

	local_wchar_array_t	key_container_name( local_stor );
	DWORD prop_size = 0;
	if( FAILED( NCryptGetProperty( subject_pub_key, NCRYPT_NAME_PROPERTY, 0, 0, &prop_size, 0) ) ){STCRYPT_UNEXPECTED();}
	assert(prop_size%sizeof(wchar_t)==0);
	key_container_name.resize( prop_size/sizeof(wchar_t) );
	if( FAILED( NCryptGetProperty( subject_pub_key, NCRYPT_NAME_PROPERTY, reinterpret_cast<PBYTE>( key_container_name.data() ), key_container_name.size()*sizeof(wchar_t), &prop_size, 0) ) ){STCRYPT_UNEXPECTED();}

	
	CRYPT_KEY_PROV_INFO key_prov_info = {0};
	key_prov_info.pwszContainerName = key_container_name.data();
	key_prov_info.pwszProvName = CNG_STCRYPT_KEYSTORAGE;
	key_prov_info.dwProvType = 0;
	key_prov_info.dwFlags = 0;
	key_prov_info.cProvParam = 0;
	key_prov_info.rgProvParam = 0;
	key_prov_info.dwKeySpec = 0;
	
	if( !CertSetCertificateContextProperty(tmp_ctx, CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info) ){
		STCRYPT_UNEXPECTED();
	}

	return tmp_ctx;
}


void msg_test(wchar_t const*const subject_str);


void cert_create_test(){

	typedef gie::monotonic::fixed_storage<4*1024> fixed_stor_t;
	typedef gie::monotonic::allocator<BYTE, fixed_stor_t> byte_allocator_t;
	typedef std::vector<BYTE, byte_allocator_t>				local_byte_array_t;

	fixed_stor_t local_stor;


	auto const prov_and_key = open_or_create_dstu_key(L"cert test container");

	BOOST_SCOPE_EXIT( (&prov_and_key) ){
		auto const prov = boost::get<0>(prov_and_key);
		auto const key = boost::get<1>(prov_and_key);

		if( prov ){auto const status = NCryptFreeObject (prov); assert( !FAILED(status) ); }
		if( key ){auto const status = NCryptFreeObject (key); assert( !FAILED(status) ); }
	} BOOST_SCOPE_EXIT_END;

	auto const subject_prov_and_key = open_or_create_dstu_key(L"subject cert test container", boost::get<0>(prov_and_key));

	BOOST_SCOPE_EXIT( (&subject_prov_and_key) ){
		auto const key = boost::get<1>(subject_prov_and_key);
		if( key ){auto const status = NCryptFreeObject (key); assert( !FAILED(status) ); }
	} BOOST_SCOPE_EXIT_END;

	wchar_t const*const issuer_name = 
		L"CN=\"STCRYPT Root CA\";"
		L"OU=\"Secure Technologies STCRYPT\";"
		L"C=\"UA\";"
		L"O=\"Secure Technologies\"";

	wchar_t const*const subject_name = 
		L"CN=\"J.Smith\";"
		L"L=\"Locality\";"
		L"O=\"Organization\";"
		L"OU=\"Organizational Unit\";"
		L"E=\"J.Smith.STCRYPT@gmail.com\";"
		L"C=\"UA\";"
		L"S=\"State or Province\";"
		L"STREET=\"Street adress\";"
		L"T=\"Title\";"
		L"G=\"Give Name\";"
		L"I=\"Initials\";"
		L"S=\"Sur name\";"
		L"DC=\"Comain Component\"";

	// root CA cert
	auto const cert_context = cert_context_create( issuer_name, issuer_name, boost::get<1>(prov_and_key), boost::get<1>(prov_and_key) );
	BOOST_SCOPE_EXIT( (&cert_context) ){
		BOOL const r = CertFreeCertificateContext(cert_context); assert(r);
	}BOOST_SCOPE_EXIT_END


	// subject cert
	auto const subject_cert_context = cert_context_create( issuer_name, subject_name, boost::get<1>(prov_and_key), boost::get<1>(subject_prov_and_key), cert_context->pCertInfo->IssuerUniqueId.pbData, cert_context->pCertInfo->IssuerUniqueId.cbData );
	BOOST_SCOPE_EXIT( (&subject_cert_context) ){
		BOOL const r = CertFreeCertificateContext(subject_cert_context); assert(r);
	}BOOST_SCOPE_EXIT_END

	save_cert_to_file(cert_context, L"c:\\temp\\manually_enc_self_cert");
	save_cert_to_file(subject_cert_context, L"c:\\temp\\manually_enc_subject_cert");
	
	import_into_ms_store2(cert_context, L"ROOT");
	import_into_ms_store2(subject_cert_context, L"ADDRESSBOOK");
	import_into_ms_store2(subject_cert_context, L"MY");

	//auto const& cert_blob = cert_create( issuer_name, subject_name, boost::get<1>(prov_and_key), boost::get<1>(prov_and_key), byte_allocator_t(local_stor) );

	//std::ofstream o_cert( "c:\\temp\\manually_enc_self_cert.cer", std::ios_base::out | std::ios_base::binary );
	//o_cert.write( reinterpret_cast<char const*>(cert_blob.data()), cert_blob.size() );
	//o_cert.flush();
	//if(o_cert.bad()) STCRYPT_UNEXPECTED();

}

void cert_test(){
	return;

	// check OIDs avaliability
	wchar_t cng_hash_alg_id[] = CNG_G34311_ALGORITHM;
	PCCRYPT_OID_INFO g34311_oid = CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, cng_hash_alg_id, 0);
	if(!g34311_oid) STCRYPT_UNEXPECTED();

	wchar_t cng_sym_alg_id[] = CNG_G28147_89;
	PCCRYPT_OID_INFO g28147_oid = CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, cng_sym_alg_id, 0);
	if(!g28147_oid) STCRYPT_UNEXPECTED();

	wchar_t cng_asym_alg_id[] = CNG_DSTU4145;
	PCCRYPT_OID_INFO dstu_oid = CryptFindOIDInfo(CRYPT_OID_INFO_CNG_ALGID_KEY, cng_asym_alg_id, 0);
	if(!dstu_oid) STCRYPT_UNEXPECTED();

	wchar_t const * cng_sign_alg_id[] = {CNG_G34311_ALGORITHM, CNG_DSTU4145};
 	PCCRYPT_OID_INFO sign_oid = CryptFindOIDInfo(CRYPT_OID_INFO_CNG_SIGN_KEY, cng_sign_alg_id, 0);
	if(!sign_oid) STCRYPT_UNEXPECTED();


	// create (if none exists) cert key
	wchar_t const*const cert_key_name = L"cert test container";
	do{
		NCRYPT_PROV_HANDLE hProvider = 0;
		NCRYPT_KEY_HANDLE hKey = 0;

		auto Status = NCryptOpenStorageProvider(&hProvider,
			CNG_STCRYPT_KEYSTORAGE,
			0);
		if (FAILED(Status)) STCRYPT_UNEXPECTED1("ERROR: NCryptOpenStorageProvider");

		BOOST_SCOPE_EXIT((hProvider)) {
			auto const status = NCryptFreeObject (hProvider); 
			assert( !FAILED(status) );
		} BOOST_SCOPE_EXIT_END


			// Create an RSA key exchange key-pair in the MS KSP
			// overwriting an existing key with the provided name.
			Status = NCryptCreatePersistedKey(hProvider,
			&hKey,
			/*NCRYPT_RSA_ALGORITHM,*/NCNG_DSTU4145,
			cert_key_name,
			AT_KEYEXCHANGE,
			0/*NCRYPT_OVERWRITE_KEY_FLAG*/);

		if (FAILED(Status)) {
			if( Status == NTE_EXISTS ) break;
			STCRYPT_UNEXPECTED1("ERROR: NCryptCreatePersistedKey");
		}

		BOOST_SCOPE_EXIT((hKey)) {
			auto const status = NCryptFreeObject (hKey); 
			assert( !FAILED(status) );
		} BOOST_SCOPE_EXIT_END

		Status = NCryptFinalizeKey(hKey, 0);
		if (FAILED(Status))  STCRYPT_UNEXPECTED1("ERROR: NCryptFinalizeKey : 0x%x\n");

	}while(false);
	//CryptExportPublicKeyInfo Function

	// test CryptExportPublicKeyInfo Function
	do {
		NCRYPT_PROV_HANDLE hProvider = 0;
		NCRYPT_KEY_HANDLE hKey = 0;

		auto Status = NCryptOpenStorageProvider(&hProvider,
			CNG_STCRYPT_KEYSTORAGE,
			0);
		if (FAILED(Status)) STCRYPT_UNEXPECTED1("ERROR: NCryptOpenStorageProvider");

		BOOST_SCOPE_EXIT((hProvider)) {
			auto const status = NCryptFreeObject (hProvider); 
			assert( !FAILED(status) );
		} BOOST_SCOPE_EXIT_END


		Status = NCryptOpenKey(hProvider, &hKey, cert_key_name, 0,0 );

		if (FAILED(Status)) {
			STCRYPT_UNEXPECTED1("ERROR: NCryptCreatePersistedKey");
		}

		BOOST_SCOPE_EXIT((hKey)) {
			auto const status = NCryptFreeObject (hKey); 
			assert( !FAILED(status) );
		} BOOST_SCOPE_EXIT_END

		DWORD ret_size = 0;
		if( !CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING,  0, &ret_size) ) {
			auto const errcode = GetLastError ();

			std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 

			STCRYPT_UNEXPECTED();
		}

		std::vector<BYTE> ret_data( ret_size );
		if( !CryptExportPublicKeyInfo(hKey, 0, X509_ASN_ENCODING,  reinterpret_cast<CERT_PUBLIC_KEY_INFO*>( ret_data.data() ), &ret_size) ) STCRYPT_UNEXPECTED();
		ret_data.resize(ret_size);
		CERT_PUBLIC_KEY_INFO  * const pub_key_info = reinterpret_cast<CERT_PUBLIC_KEY_INFO*>( ret_data.data() );

	} while(false);

	//

	stcrypt::mspki::cert_name_blob_t cert_name_blob;

	cert_str_to_name(
		L"CN=\"J.Smith\";"
		L"L=\"Locality\";"
		L"O=\"Organization\";"
		L"OU=\"Organizational Unit\";"
		L"E=\"J.Smith.STCRYPT@gmail.com\";"
		L"C=\"UA\";"
		L"S=\"State or Province\";"
		L"STREET=\"Street adress\";"
		L"T=\"Title\";"
		L"G=\"Give Name\";"
		L"I=\"Initials\";"
		L"S=\"Sur name\";"
		L"DC=\"Comain Component\""
		, cert_name_blob);


	SYSTEMTIME cs;
	GetSystemTime(&cs);
	cs.wYear += 1; 

	CRYPT_KEY_PROV_INFO pnfo = {
		const_cast<wchar_t*>( cert_key_name ),
		CNG_STCRYPT_KEYSTORAGE,
		0,
		0,
		0, 
		0, 
		AT_SIGNATURE
	};

	CRYPT_ALGORITHM_IDENTIFIER alg={OID_G34311_DSTU4145_SIGN,0};
	PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(  // TODO: this function never frees internally allocated hash provider?!
		0, //*hProv, 
		&cert_name_blob.m_blob,
		0 ,
		&pnfo, // pKeyProvInfo 
		&alg, //pSignatureAlgorithm 
		0, //start time
		&cs, //end time
		0 //extensions
		);

	if(!cert){ 
		auto const errcode = GetLastError();
		std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 
		STCRYPT_UNEXPECTED1("failed to create certificate");
	}


	BOOST_SCOPE_EXIT( (cert) ) {
		BOOL const r = CertFreeCertificateContext(cert); assert(r);
	}  BOOST_SCOPE_EXIT_END


	{
		import_into_ms_store2(cert, L"ADDRESSBOOK");
		import_into_ms_store2(cert, L"MY");
		import_into_ms_store2(cert, L"ROOT");

	}

	{ // export to file

		auto & ms_cert_ctx = cert;


		HCERTSTORE const ms_cert_store = CertOpenStore (
			CERT_STORE_PROV_MEMORY,
			0,
			0,
			0,
			0);
		if(ms_cert_store==0) {
			DWORD const errcode = GetLastError();
			std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 

			STCRYPT_UNEXPECTED1("CertOpenStore have failed");
		}

		BOOST_SCOPE_EXIT( (ms_cert_store) ){
			BOOL const r = CertCloseStore (ms_cert_store,0);
			assert(r!=0);
		} BOOST_SCOPE_EXIT_END

			if (!CertAddCertificateContextToStore (
				ms_cert_store,
				ms_cert_ctx,
				CERT_STORE_ADD_ALWAYS,
				NULL)){

					DWORD const errcode = GetLastError();
					std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 
					STCRYPT_UNEXPECTED1("CertAddCertificateContextToStore have failed");

			}

		HANDLE hFile;
		if (hFile = CreateFile(
			L"c:\\temp\\test-cert.p7b", // The file name
			GENERIC_WRITE, // Access mode: write to this file
			0, // Share mode
			NULL, // Uses the DACL created previously
			CREATE_ALWAYS, // How to create
			FILE_ATTRIBUTE_NORMAL, // File attributes
			NULL)) // Template
		{
		}
		else
		{
			STCRYPT_UNEXPECTED();
		}
		BOOST_SCOPE_EXIT( (hFile) ) {
			BOOL const r = CloseHandle(hFile); assert(r);
		}  BOOST_SCOPE_EXIT_END

			if(CertSaveStore(
				ms_cert_store, // Store handle
				PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
				//CERT_STORE_SAVE_AS_STORE, 
				CERT_STORE_SAVE_AS_PKCS7,
				CERT_STORE_SAVE_TO_FILE,
				hFile, // The handle of an open disk file
				0)) // dwFlags: No flags are needed here.
			{
				printf("Saved the memory store to disk. \n");
			} else {
				DWORD const errcode = GetLastError();
				std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 
			}



	}


}

void dstu1_test(){
   NTSTATUS    Status  = STATUS_SUCCESS;
    NCRYPT_PROV_HANDLE      hProvider       = 0;
    NCRYPT_KEY_HANDLE       hKey            = 0;
    LPCWSTR                 pszKeyName      = L"MyKey";
    NCRYPT_UI_POLICY        UIPolicy        = {0};
    HWND                    hwndConsole     = NULL;

    BYTE                    rgbHash[20];
    PBYTE                   pbSignature     = NULL;
    DWORD                   cbSignature;
    DWORD                   i;
    BCRYPT_PKCS1_PADDING_INFO PKCS1PaddingInfo;
    VOID                    *pPaddingInfo;

    printf("Strong Key UX Sample\n");

    ZeroMemory(&UIPolicy, sizeof(UIPolicy));

	std::vector<BYTE> signature;

	// initialize hash
	for(i = 0; i < sizeof(rgbHash); i++)
	{
		rgbHash[i] = (BYTE)(i + 1);
	}

	{

	
	// Open Microsoft KSP (Key Storage Provider) to get a handle to it.
    Status = NCryptOpenStorageProvider(&hProvider,
                                       CNG_STCRYPT_KEYSTORAGE,
                                       0);
    if (FAILED(Status))
    {
        STCRYPT_UNEXPECTED1("ERROR: NCryptOpenStorageProvider");
    }


	BOOST_SCOPE_EXIT((hProvider)) {
		auto const status = NCryptFreeObject (hProvider); 
		assert( !FAILED(status) );
	} BOOST_SCOPE_EXIT_END


    // Create an RSA key exchange key-pair in the MS KSP
    // overwriting an existing key with the provided name.
    Status = NCryptCreatePersistedKey(hProvider,
                                      &hKey,
                                      /*NCRYPT_RSA_ALGORITHM,*/NCNG_DSTU4145,
                                      pszKeyName,
                                      AT_KEYEXCHANGE,
                                      NCRYPT_OVERWRITE_KEY_FLAG);
    if (FAILED(Status))
    {
        STCRYPT_UNEXPECTED1("ERROR: NCryptCreatePersistedKey");
    }
	else{
		printf("Create New RSA key\n");
	}

	BOOST_SCOPE_EXIT((hKey)) {
		auto const status = NCryptFreeObject (hKey); 
		assert( !FAILED(status) );
	} BOOST_SCOPE_EXIT_END


    // Set the policy on this key-pair, before finalizing the key-pair
    // generation. Once the key pair generation is finalized, these
    // properties can't be changed.
    UIPolicy.dwVersion = 1;
    UIPolicy.dwFlags = NCRYPT_UI_PROTECT_KEY_FLAG;
	
    UIPolicy.pszCreationTitle   = L"Strong Key UX Sample";
    UIPolicy.pszFriendlyName    = L"Test Friendly Name";
    UIPolicy.pszDescription = L"This is a Sample";

//     Status = NCryptSetProperty(hKey,
//                                NCRYPT_UI_POLICY_PROPERTY,
//                                (PBYTE)&UIPolicy,
//                                sizeof(UIPolicy),
//                                0);
//     if (FAILED(Status))
//     {
//         STCRYPT_UNEXPECTED1("ERROR: NCryptSetProperty(set UI params)");
//     }
// 
//     // Get a handle to the console window to use in key's property.
//     hwndConsole = GetConsoleWindow();
//     if (hwndConsole == NULL)
//     {
//         STCRYPT_UNEXPECTED1("ERROR: GetConsoleWindow");
//     }
// 
//     // OK, now attach that handle to the key
//     Status = NCryptSetProperty(hKey,
//                                NCRYPT_WINDOW_HANDLE_PROPERTY,
//                                (PBYTE)&hwndConsole,
//                                sizeof(hwndConsole),
//                                0);
//     if (FAILED(Status))
//     {
//         STCRYPT_UNEXPECTED1("ERROR: NCryptSetProperty(HWND) ");
//     }

    // Finalize the key-pair generation process.
    // From here on, the key handle is usable.
    Status = NCryptFinalizeKey(hKey, 0);
    if (FAILED(Status))
    {
        STCRYPT_UNEXPECTED1("ERROR: NCryptFinalizeKey : 0x%x\n");
    }

    //
    // Here we start using the key for some purpose.
    // The intent from here on is to show the strong key UX per its policy set above.
    //
    // Get a handle to the private key in the provider (KSP).
//     Status = NCryptOpenKey(
//                     hProvider,
//                     &hKey,
//                     pszKeyName,
//                     AT_KEYEXCHANGE,
//                     0);
// 
//     if(FAILED(Status))
//     {
//         STCRYPT_UNEXPECTED1("ERROR: NCryptOpenKey");
//     }
// 	else{
// 		printf("Open a RSA key to sign\n");
// 	}
// 
//     // Set the Window handle property on the key handle
//     Status = NCryptSetProperty(hKey,
//                                NCRYPT_WINDOW_HANDLE_PROPERTY,
//                                (PBYTE)&hwndConsole,
//                                sizeof(hwndConsole),
//                                0);
//     if (FAILED(Status))
//     {
//         STCRYPT_UNEXPECTED1("ERROR: NCryptSetProperty(HWND)");
//     }

    PKCS1PaddingInfo.pszAlgId = NCRYPT_SHA1_ALGORITHM;
    pPaddingInfo = &PKCS1PaddingInfo;

    // Call into signature function to determine the required output length
    Status = NCryptSignHash(hKey,
                            pPaddingInfo,
                            rgbHash,
                            sizeof(rgbHash),
                            NULL,
                            0,
                            &cbSignature,
                            NCRYPT_PAD_PKCS1_FLAG);
    if (FAILED(Status))
    {
        STCRYPT_UNEXPECTED1("ERROR: NCryptSignHash(size)");
    }

	signature.resize( cbSignature );

    // And call the signature function again to sign the data
    // and to get the signature blob
    Status = NCryptSignHash(hKey,
                            pPaddingInfo,
                            rgbHash,
                            sizeof(rgbHash),
                            signature.data(),
                            signature.size(),
                            &cbSignature,
                            NCRYPT_PAD_PKCS1_FLAG);
    if (FAILED(Status))
    {
        STCRYPT_UNEXPECTED1("ERROR: NCryptSignHash() : 0x%x\n");
    }
	else{
		printf("SUCCESS: Sign the Hash \n");
	}


	Status =NCryptVerifySignature(hKey, pPaddingInfo, rgbHash, sizeof(rgbHash), signature.data(), signature.size(), NCRYPT_PAD_PKCS1_FLAG);
	if (FAILED(Status))
	{
		STCRYPT_UNEXPECTED1("ERROR: NCryptVerifySignature() : 0x%x\n");
	}

	}



    // All done.

	{

		// Open Microsoft KSP (Key Storage Provider) to get a handle to it.
		Status = NCryptOpenStorageProvider(&hProvider,
			CNG_STCRYPT_KEYSTORAGE,
			0);
		if (FAILED(Status))
		{
			STCRYPT_UNEXPECTED1("ERROR: NCryptOpenStorageProvider");
		}


		BOOST_SCOPE_EXIT((hProvider)) {
			auto const status = NCryptFreeObject (hProvider); 
			assert( !FAILED(status) );
		} BOOST_SCOPE_EXIT_END

		Status = NCryptOpenKey(hProvider, &hKey, pszKeyName, 0, NCRYPT_SILENT_FLAG);
		if (FAILED(Status)) STCRYPT_UNEXPECTED1("ERROR: NCryptOpenKey");

		BOOST_SCOPE_EXIT((hKey)) {
			auto const status = NCryptFreeObject (hKey); 
			assert( !FAILED(status) );
		} BOOST_SCOPE_EXIT_END

		Status =NCryptVerifySignature(hKey, pPaddingInfo, rgbHash, sizeof(rgbHash), signature.data(), signature.size(), NCRYPT_PAD_PKCS1_FLAG);
		if (FAILED(Status))
		{
			STCRYPT_UNEXPECTED1("ERROR: NCryptVerifySignature() : 0x%x\n");
		}


		std::vector<BYTE> n_key_blob;
		DWORD key_blob_size;
		Status =NCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, 0, 0, 0, &key_blob_size, 0);
		if (FAILED(Status))
		{
			STCRYPT_UNEXPECTED1("ERROR: NCryptExportKey");
		}
		n_key_blob.resize( key_blob_size );

		Status =NCryptExportKey(hKey, 0, BCRYPT_PRIVATE_KEY_BLOB, 0, n_key_blob.data(), n_key_blob.size(), &key_blob_size, 0);
		if (FAILED(Status))
		{
			STCRYPT_UNEXPECTED1("ERROR: NCryptExportKey");
		}

		NCRYPT_KEY_HANDLE imported_key=0;
		Status =NCryptImportKey(hProvider, 0, BCRYPT_PRIVATE_KEY_BLOB, 0, &imported_key, n_key_blob.data(), n_key_blob.size(), 0);
		if (FAILED(Status))
		{
			STCRYPT_UNEXPECTED1("ERROR: NCryptImportKey");
		}

		BOOST_SCOPE_EXIT((imported_key)) {
			auto const status = NCryptFreeObject (imported_key); 
			assert( !FAILED(status) );
		} BOOST_SCOPE_EXIT_END


		Status =NCryptVerifySignature(imported_key, pPaddingInfo, rgbHash, sizeof(rgbHash), signature.data(), signature.size(), NCRYPT_PAD_PKCS1_FLAG);
		if (FAILED(Status))
		{
			STCRYPT_UNEXPECTED1("ERROR: NCryptVerifySignature() : 0x%x\n");
		}

		rgbHash[0]=-1;
		Status =NCryptVerifySignature(imported_key, pPaddingInfo, rgbHash, sizeof(rgbHash), signature.data(), signature.size(), NCRYPT_PAD_PKCS1_FLAG);
		if (Status!=NTE_BAD_SIGNATURE)
		{
			STCRYPT_UNEXPECTED1("ERROR: NCryptVerifySignature() : 0x%x\n");
		}


	}	
}

void hash_test(){
	NTSTATUS                status          = STATUS_UNSUCCESSFUL;

	BCRYPT_ALG_HANDLE       hAlg;
	//open an algorithm handle
	if(!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, CNG_G34311_ALGORITHM/*BCRYPT_SHA256_ALGORITHM*/, NULL, 0))) {
		STCRYPT_UNEXPECTED1("BCryptOpenAlgorithmProvider() have failed");
	}

	BOOST_SCOPE_EXIT((hAlg)) {
		auto const status = BCryptCloseAlgorithmProvider(hAlg, 0); 
		if(!NT_SUCCESS(status) ) {assert(false);}
	} BOOST_SCOPE_EXIT_END

		DWORD cbData;

	DWORD hash_length;
	//calculate the length of the hash
	if(!NT_SUCCESS(status = BCryptGetProperty(
		hAlg, 
		BCRYPT_HASH_LENGTH, 
		(PBYTE)&hash_length, 
		sizeof(hash_length), 
		&cbData, 
		0))){
			STCRYPT_UNEXPECTED();

	}

	DWORD cbHashObject;
	//calculate the size of the buffer to hold the hash object
	if(!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD),&cbData, 0))){
		STCRYPT_UNEXPECTED();
	}



	BCRYPT_HASH_HANDLE hash_handle;
	std::vector<BYTE> hash_object;
	hash_object.resize(cbHashObject);

	//create a hash
	if(!NT_SUCCESS(status = BCryptCreateHash(
		hAlg, 
		&hash_handle, 
		hash_object.data(), 
		hash_object.size(), 
		NULL, 
		0, 
		0))){
			STCRYPT_UNEXPECTED();

	}

	BOOST_SCOPE_EXIT((hash_handle)) {
		auto const status = BCryptDestroyHash(hash_handle); 
		if(!NT_SUCCESS(status) ) {assert(false);}
	} BOOST_SCOPE_EXIT_END

		char msg[]="Hello World!!";


	//hash some data
	if(!NT_SUCCESS(status = BCryptHashData(
		hash_handle,
		reinterpret_cast<BYTE*>(&msg[0]),
		sizeof(msg),
		0))){
			STCRYPT_UNEXPECTED();
	}

	std::vector<BYTE> hash_value( hash_length );
	//close the hash
	if(!NT_SUCCESS(status = BCryptFinishHash(
		hash_handle, 
		hash_value.data(), 
		hash_value.size(), 
		0))){
			STCRYPT_UNEXPECTED();
	}

}

void rsa_test(){

	NTSTATUS ntStatus = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE key = 0;

	ntStatus = BCryptOpenAlgorithmProvider(
		&hAlg,      // Algorithm handle
		//NCNG_DSTU4145, 
		BCRYPT_RSA_ALGORITHM,   // Algorithm name
		NULL,       // Provider name
		0           // Flags
		);

	if (!NT_SUCCESS(ntStatus)){STCRYPT_UNEXPECTED();}
	
	BOOST_SCOPE_EXIT((hAlg)) {
		auto const status = BCryptCloseAlgorithmProvider(hAlg, 0); 
		if(!NT_SUCCESS(status) ) {assert(false);}
	} BOOST_SCOPE_EXIT_END


	ntStatus = BCryptGenerateKeyPair(hAlg, &key, 2*1024, 0);
	if (!NT_SUCCESS(ntStatus)){STCRYPT_UNEXPECTED();}

	BOOST_SCOPE_EXIT((key)) {
		auto const status = BCryptDestroyKey (key); 
		if(!NT_SUCCESS(status) ) {assert(false);}
	} BOOST_SCOPE_EXIT_END

	ntStatus = BCryptFinalizeKeyPair(key, 0);
	if (!NT_SUCCESS(ntStatus)){STCRYPT_UNEXPECTED();}

	DWORD result;
	DWORD block_length=0;
	DWORD key_strength = 0;


	ntStatus = BCryptGetProperty(key, BCRYPT_BLOCK_LENGTH, (UCHAR*)&block_length, sizeof(block_length), &result, 0);
	if (!NT_SUCCESS(ntStatus)){STCRYPT_UNEXPECTED();}

	ntStatus = BCryptGetProperty(key, BCRYPT_KEY_STRENGTH, (UCHAR*)&key_strength, sizeof(key_strength), &result, 0);
	if (!NT_SUCCESS(ntStatus)){STCRYPT_UNEXPECTED();}


	std::vector<unsigned char> data; data.resize(125);
	std::vector<unsigned char> data_out; data_out.resize( (key_strength/8)*2);

	ntStatus = BCryptEncrypt(key, data.data(), data.size(), 0, 0, 0, data_out.data(), data_out.size(), &result, BCRYPT_PAD_PKCS1);
	if (!NT_SUCCESS(ntStatus)){STCRYPT_UNEXPECTED();}


}


void dstu_test(){
	auto const prov_and_key = open_or_create_dstu_key(L"lalala", 0, NCRYPT_MACHINE_KEY_FLAG | NCRYPT_OVERWRITE_KEY_FLAG);

	BOOST_SCOPE_EXIT((&prov_and_key)) {
		{auto const status = NCryptFreeObject( boost::get<1>(prov_and_key) ); if(!NT_SUCCESS(status) ) {assert(false);}}
		{auto const status = NCryptFreeObject( boost::get<0>(prov_and_key) ); if(!NT_SUCCESS(status) ) {assert(false);}}
	} BOOST_SCOPE_EXIT_END

	STCRYPT_CHECK(  NCryptFinalizeKey( boost::get<1>(prov_and_key), 0 )==ERROR_SUCCESS );;
	

}

void symmetric_test_std_aes(){
	

	NTSTATUS ntStatus = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_KEY_HANDLE key=0, key2 = 0;

	ntStatus = BCryptOpenAlgorithmProvider(
		&hAlg,      // Algorithm handle
		CNG_G28147_89, 
		 //BCRYPT_AES_ALGORITHM,   // Algorithm name
		NULL,       // Provider name
		0           // Flags
		);

	if (!NT_SUCCESS(ntStatus))
	{
		STCRYPT_UNEXPECTED();
	}

	BOOST_SCOPE_EXIT((hAlg)) {
		auto const status = BCryptCloseAlgorithmProvider(hAlg, 0); 
		if(!NT_SUCCESS(status) ) {assert(false);}
	} BOOST_SCOPE_EXIT_END

	DWORD cbData=0;
	DWORD cbObject=0;
	DWORD block_len=0;

	if(!NT_SUCCESS( BCryptGetProperty(hAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&block_len, sizeof(DWORD), &cbData, 0)))STCRYPT_UNEXPECTED();

	if(!NT_SUCCESS(BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbObject, sizeof(DWORD),&cbData, 0))) STCRYPT_UNEXPECTED();


	std::vector<BYTE>  object(cbObject);
	std::vector<BYTE>  object2(cbObject);
	std::vector<BYTE>  secret(32);// secret.push_back(1);

	boost::for_each(secret, [](BYTE& val){
		val = rand();
	});


	if(!NT_SUCCESS( BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0))) STCRYPT_UNEXPECTED();

	ntStatus= BCryptGenerateSymmetricKey(hAlg, &key, object.data(), object.size() , secret.data(), secret.size(), 0 );
	if(!NT_SUCCESS( ntStatus) ) STCRYPT_UNEXPECTED();

	BOOST_SCOPE_EXIT((key)) {
		auto const status = BCryptDestroyKey(key); 
		if(!NT_SUCCESS(status) ) {assert(false);}
	} BOOST_SCOPE_EXIT_END


	ntStatus= BCryptGenerateSymmetricKey(hAlg, &key2, object2.data(), object2.size() , secret.data(), secret.size(), 0 );
	if(!NT_SUCCESS( ntStatus) ) STCRYPT_UNEXPECTED();

	BOOST_SCOPE_EXIT((key2)) {
		auto const status = BCryptDestroyKey(key2); 
		if(!NT_SUCCESS(status) ) {assert(false);}
	} BOOST_SCOPE_EXIT_END


// 	std::vector<BYTE> in_place_plaintext; in_place_plaintext+= 1,2,3,4,5,6,7;
// 	std::vector<BYTE> in_place_plaintext2(in_place_plaintext);
// 	ULONG in_place_plaintext_size = in_place_plaintext.size();
// 	if(!NT_SUCCESS(BCryptEncrypt(key, in_place_plaintext.data(), in_place_plaintext.size(), NULL, 0/*pbIV*/, 0/*cbBlockLen*/, 0,0,&cbData,BCRYPT_BLOCK_PADDING))) STCRYPT_UNEXPECTED();
// 	in_place_plaintext.resize(cbData+1, -1);
// 	ntStatus = BCryptEncrypt(key, in_place_plaintext.data(), in_place_plaintext_size, NULL, 0/*pbIV*/, 0/*cbBlockLen*/, in_place_plaintext.data(),in_place_plaintext.size()-1,&cbData,BCRYPT_BLOCK_PADDING);
// 	if(!NT_SUCCESS(ntStatus )) STCRYPT_UNEXPECTED();
// 
// 	in_place_plaintext_size = in_place_plaintext2.size();
// 	if(!NT_SUCCESS(BCryptEncrypt(key, in_place_plaintext2.data(), in_place_plaintext2.size(), NULL, 0/*pbIV*/, 0/*cbBlockLen*/, 0,0,&cbData,BCRYPT_BLOCK_PADDING))) STCRYPT_UNEXPECTED();
// 	in_place_plaintext2.resize(cbData+1, -1);
// 	ntStatus = BCryptEncrypt(key, in_place_plaintext2.data(), in_place_plaintext_size, NULL, 0/*pbIV*/, 0/*cbBlockLen*/, in_place_plaintext2.data(),in_place_plaintext2.size()-1,&cbData,BCRYPT_BLOCK_PADDING);
// 	if(!NT_SUCCESS(ntStatus )) STCRYPT_UNEXPECTED();
// 
// 
 	std::vector<BYTE> plaintext; plaintext+= 1,2,3,4,5,6,7,8,9,10,11,12,13,14;//,15;
 	std::vector<BYTE> ciphertext;
 
//  	std::vector<BYTE> plaintext2; plaintext2+= 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16;
//  	std::vector<BYTE> ciphertext2;


	if(!NT_SUCCESS(BCryptEncrypt(key, plaintext.data(), plaintext.size(), NULL, 0/*pbIV*/, 0/*cbBlockLen*/, 0,0,&cbData,BCRYPT_BLOCK_PADDING))) STCRYPT_UNEXPECTED();
	plaintext.resize(cbData);
	ntStatus = BCryptEncrypt(key, plaintext.data(), plaintext.size(), NULL, 0/*pbIV*/, 0/*cbBlockLen*/, plaintext.data(), plaintext.size(),&cbData,BCRYPT_BLOCK_PADDING);
	if(!NT_SUCCESS(ntStatus )) STCRYPT_UNEXPECTED();

// 	if(!NT_SUCCESS(BCryptEncrypt(key, plaintext2.data(), plaintext2.size(), NULL, 0/*pbIV*/, 0/*cbBlockLen*/, 0,0,&cbData,BCRYPT_BLOCK_PADDING))) STCRYPT_UNEXPECTED();
// 	ciphertext2.resize(cbData);
// 	if(!NT_SUCCESS(BCryptEncrypt(key, plaintext2.data(), plaintext2.size(), NULL, 0/*pbIV*/, 0/*cbBlockLen*/, ciphertext2.data(),ciphertext2.size(),&cbData,BCRYPT_BLOCK_PADDING))) STCRYPT_UNEXPECTED();


	if(!NT_SUCCESS(BCryptDecrypt(key2, plaintext.data(), plaintext.size(), NULL, 0/*pbIV*/, 0/*cbBlockLen*/, 0, 0,&cbData,BCRYPT_BLOCK_PADDING))) STCRYPT_UNEXPECTED();
	plaintext.resize(16); //ciphertext.resize(plaintext.size());
	ntStatus = BCryptDecrypt(key2, plaintext.data(), plaintext.size(), NULL, 0/*pbIV*/, 0/*cbBlockLen*/, plaintext.data(),plaintext.size(),&cbData,BCRYPT_BLOCK_PADDING);
	if(!NT_SUCCESS(ntStatus)) STCRYPT_UNEXPECTED();

}

void symmetric_test(){

	NTSTATUS ntStatus = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE hAlg = NULL;

	ntStatus = BCryptOpenAlgorithmProvider(
		&hAlg,      // Algorithm handle
		CNG_G28147_89,   // Algorithm name
		NULL,       // Provider name
		0           // Flags
		);

	if (!NT_SUCCESS(ntStatus))
	{
		STCRYPT_UNEXPECTED();
	}

	BOOST_SCOPE_EXIT((hAlg)) {
		auto const status = BCryptCloseAlgorithmProvider(hAlg, 0); 
		if(!NT_SUCCESS(status) ) {assert(false);}
	} BOOST_SCOPE_EXIT_END


	DWORD count;
	DWORD key_object_size;

 	ntStatus = BCryptGetProperty( hAlg,BCRYPT_OBJECT_LENGTH,(PBYTE) &key_object_size,sizeof(key_object_size),&count,0);
 	if (!NT_SUCCESS(ntStatus))
 	{
 		STCRYPT_UNEXPECTED();
 	}


}


void test_enum_keys(){
	
	NCRYPT_PROV_HANDLE prov = 0;

	auto Status = NCryptOpenStorageProvider(&prov, CNG_STCRYPT_KEYSTORAGE, 0);
	STCRYPT_CHECK( !FAILED(Status) );
	BOOST_SCOPE_EXIT((prov)) {	auto const status = NCryptFreeObject (prov);assert( !FAILED(status) );	}  BOOST_SCOPE_EXIT_END

	NCryptKeyName * key_name = 0;
	BOOST_SCOPE_EXIT((&key_name)) {	auto const status = NCryptFreeBuffer(key_name); assert( !FAILED(status) );	}  BOOST_SCOPE_EXIT_END

	void * state = 0;
	BOOST_SCOPE_EXIT((&state)) {	auto const status = NCryptFreeBuffer(state); assert( !FAILED(status) );	}  BOOST_SCOPE_EXIT_END

	while( !FAILED(Status) ){
		Status = NCryptEnumKeys(prov, 0, &key_name, &state, 0);
		STCRYPT_CHECK( !FAILED(Status) || Status==NTE_NO_MORE_ITEMS );

	}

}


void msg_test2(wchar_t const*const subject_str);

// typedef struct _UNICODE_STRING {
// 	USHORT Length;
// 	USHORT MaximumLength;
// 	PWSTR  Buffer;
// } UNICODE_STRING, *PUNICODE_STRING;
// 
typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


typedef NTSTATUS (NTAPI*ZwCreateToken_t)(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN TOKEN_TYPE Type,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl,
	IN PTOKEN_SOURCE Source
	);


namespace {

	std::vector<DWORD> get_all_pids(){

		std::vector<DWORD> all_pids;
		all_pids.reserve( 1024 );

		unsigned int pids_to_query = all_pids.capacity() / 2;

		unsigned int pids_current_returned;
		unsigned int pids_returned=0;

		for(;;){

			DWORD bytes_returned;
			all_pids.resize( pids_to_query );

			STCRYPT_CHECK_WIN( EnumProcesses(all_pids.data(), all_pids.size() * sizeof(DWORD), &bytes_returned) );
			STCRYPT_CHECK( bytes_returned%sizeof(DWORD)==0 );
			pids_current_returned=bytes_returned/sizeof(DWORD);

			if(pids_current_returned==pids_to_query ){
				pids_to_query*=2;
				continue;
			}

			if(pids_current_returned<=pids_returned){
				break;
			}

			pids_returned = pids_current_returned;

		}

		all_pids.resize( pids_current_returned );

		return all_pids;
	}


	std::vector<HMODULE> get_all_modules(HANDLE const ph){

		std::vector<HMODULE > all_mods;
		all_mods.reserve( 1024 );

		unsigned int mods_to_query = all_mods.capacity() / 2;

		unsigned int mods_current_returned;
		unsigned int mods_returned=0;

		for(;;){

			DWORD bytes_returned;
			all_mods.resize( mods_to_query );

			STCRYPT_CHECK_WIN( EnumProcessModules(ph, all_mods.data(), all_mods.size() * sizeof(HMODULE), &bytes_returned) );
			STCRYPT_CHECK( bytes_returned%sizeof(HMODULE)==0 );
			mods_current_returned=bytes_returned/sizeof(HMODULE);

			if(mods_current_returned==mods_to_query ){
				mods_to_query*=2;
				continue;
			}

			if(mods_current_returned<=mods_returned){
				break;
			}

			mods_returned = mods_current_returned;

		}

		all_mods.resize( mods_current_returned );

		return all_mods;
	}

} //end anon ns

void t_sid(){

	
	auto const find_lsass_pid = []()->DWORD {

		auto const& all_pids = get_all_pids();

		auto const pid_iter = 
		boost::find_if( all_pids, [](DWORD const pid)->bool{

			auto const process_handle = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid );
			if (!process_handle){
				STCRYPT_LOG_PRINT_W_EX(L"OpenProcess() have failed", pid);
			} else  {
				wchar_t tmp_buffer[2*1024];
				auto const str_len=GetProcessImageFileName(process_handle, &tmp_buffer[0], sizeof(tmp_buffer)-1 );
				tmp_buffer[str_len]=0;
				if(!str_len){
					STCRYPT_LOG_PRINT_W_EX(L"GetProcessImageFileName() have failed", pid);
				} else {
					if( boost::filesystem::wpath( tmp_buffer ).leaf()==L"lsass.exe" ){//TODO:: case sensetive?
						return true;
					}
				}
			}


			return false;
		});

		STCRYPT_CHECK( pid_iter!=all_pids.end() );

		return *pid_iter;
	};

	auto const ntdll_module = LoadLibraryW(L"ntdll.dll");
	STCRYPT_CHECK_WIN( ntdll_module );
	BOOST_SCOPE_EXIT((ntdll_module)) { auto const status = FreeLibrary(ntdll_module); assert(status); }  BOOST_SCOPE_EXIT_END

	ZwCreateToken_t stcrypt_ZwCreateToken = reinterpret_cast<ZwCreateToken_t>( GetProcAddress( ntdll_module, "ZwCreateToken" ) );
	STCRYPT_CHECK_WIN(stcrypt_ZwCreateToken);

	PSID ti_sid = 0;
	STCRYPT_CHECK_WIN( ConvertStringSidToSid(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &ti_sid) );
	BOOST_SCOPE_EXIT((ti_sid)) { auto const status = LocalFree(ti_sid); assert(!status); }  BOOST_SCOPE_EXIT_END

	HANDLE this_proc_token = 0;
	STCRYPT_CHECK_WIN( OpenProcessToken( GetCurrentProcess(), TOKEN_ALL_ACCESS_P, &this_proc_token ) );
	BOOST_SCOPE_EXIT((this_proc_token)) {auto const status = CloseHandle(this_proc_token); assert(status); }  BOOST_SCOPE_EXIT_END



auto const GetFromToken = [](HANDLE hToken, TOKEN_INFORMATION_CLASS tic)->std::unique_ptr<BYTE, std::default_delete<BYTE[]> > 
	{
		DWORD n;
		BOOL const rv = GetTokenInformation(hToken, tic, 0, 0, &n);
		if(!rv){
			auto const last_error = GetLastError();
			STCRYPT_CHECK( last_error == ERROR_INSUFFICIENT_BUFFER );
		}
		std::unique_ptr<BYTE, std::default_delete<BYTE[]> > tmp( new BYTE[n] );
		STCRYPT_CHECK ( GetTokenInformation(hToken, tic, tmp.get(), n, &n) );

		return tmp;
	};

HANDLE hToken;

	auto lsass_process_handle = OpenProcess(PROCESS_ALL_ACCESS , false, find_lsass_pid() );
	STCRYPT_CHECK_WIN( lsass_process_handle );
	BOOST_SCOPE_EXIT((lsass_process_handle)) {auto const status = CloseHandle(lsass_process_handle); assert(status); }  BOOST_SCOPE_EXIT_END


	STCRYPT_CHECK_WIN( OpenProcessToken(lsass_process_handle,	TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_DUPLICATE,	&hToken) );
	BOOST_SCOPE_EXIT((hToken)) {auto const status = CloseHandle(hToken); assert(status); }  BOOST_SCOPE_EXIT_END

	STCRYPT_CHECK_WIN( ImpersonateLoggedOnUser( hToken ) );
	BOOST_SCOPE_EXIT((hToken)) { auto const status = RevertToSelf(); assert(status); }  BOOST_SCOPE_EXIT_END

// 	SID_IDENTIFIER_AUTHORITY nt = SECURITY_NT_AUTHORITY;
// 
// 	PSID system;
// 	STCRYPT_CHECK_WIN( AllocateAndInitializeSid(&nt,
// 		1,
// 		SECURITY_LOCAL_SYSTEM_RID,
// 		0, 0, 0, 0, 0, 0, 0,
// 		&system)) ;
// 	BOOST_SCOPE_EXIT((system)) {auto const status = FreeSid(system); assert(!status); }  BOOST_SCOPE_EXIT_END
	

	TOKEN_USER user = {{ti_sid, 0}};
	LUID luid;
	STCRYPT_CHECK_WIN( AllocateLocallyUniqueId(&luid) );

	TOKEN_SOURCE source = {{'*', '*', '*', '*', '*', '*', '*', '*'}, {luid.LowPart, luid.HighPart}};


	LUID authid = SYSTEM_LUID;
	auto token_statistics_data = GetFromToken(hToken, TokenStatistics);
	PTOKEN_STATISTICS stats = PTOKEN_STATISTICS( token_statistics_data.get() );

	SECURITY_QUALITY_OF_SERVICE sqos = {sizeof sqos, SecurityAnonymous,		SECURITY_STATIC_TRACKING, FALSE};

	OBJECT_ATTRIBUTES oa = {sizeof oa, 0, 0, 0, 0, &sqos};
	HANDLE hToken2 = 0;

	auto token_groups_data = GetFromToken(hToken, TokenGroups);
	PTOKEN_GROUPS token_group_caller = reinterpret_cast<PTOKEN_GROUPS>( token_groups_data.get() );
	auto const token_group_count = token_group_caller->GroupCount+1;
	std::vector<BYTE> token_group_data( sizeof(TOKEN_GROUPS)+sizeof(SID_AND_ATTRIBUTES)*(token_group_count-1) );
	auto token_group = reinterpret_cast<PTOKEN_GROUPS>( token_group_data.data() );
	token_group->GroupCount = token_group_count;
	std::copy(&token_group_caller->Groups[0], &token_group_caller->Groups[0] + token_group_caller->GroupCount, &token_group->Groups[0]);

	auto & ti_grp = token_group->Groups[token_group->GroupCount-1];
	ti_grp.Sid = ti_sid;
	ti_grp.Attributes = SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_OWNER;

	TOKEN_PRIMARY_GROUP token_pimary_group = {0};
	token_pimary_group.PrimaryGroup = ti_sid;

	TOKEN_OWNER token_owner = {0};
	token_owner.Owner = ti_sid;

	auto const nt_status = stcrypt_ZwCreateToken(&hToken2, TOKEN_ALL_ACCESS, &oa, TokenPrimary,
		PLUID(&authid),
		PLARGE_INTEGER(&stats->ExpirationTime),
		&user,
		token_group,//PTOKEN_GROUPS(GetFromToken(hToken, TokenGroups).get() ),
		PTOKEN_PRIVILEGES(GetFromToken(hToken, TokenPrivileges).get() ),
		&token_owner,//PTOKEN_OWNER(GetFromToken(hToken, TokenOwner).get() ),
		&token_pimary_group, //PTOKEN_PRIMARY_GROUP(GetFromToken(hToken, TokenPrimaryGroup).get() ),
		PTOKEN_DEFAULT_DACL(GetFromToken(hToken, TokenDefaultDacl).get() ),
		&source);
	
	switch(nt_status){
	case 0xC0000061 /*STATUS_PRIVILEGE_NOT_HELD*/: STCRYPT_UNEXPECTED1("STATUS_PRIVILEGE_NOT_HELD");
	default: STCRYPT_CHECK(nt_status==STATUS_SUCCESS);
	}

	//boost::thread worker([&](){

		STCRYPT_CHECK_WIN( ImpersonateLoggedOnUser( hToken2 ) );
		BOOST_SCOPE_EXIT((hToken)) { auto const status = RevertToSelf(); assert(status); }  BOOST_SCOPE_EXIT_END

		HKEY key = 0;
		auto const r = RegCreateKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\CLSID\\{0002000F-0000-0000-C000-000000000046}\\test2", &key);
		STCRYPT_CHECK( r==ERROR_SUCCESS );

	//});

//	worker.join();


}

void load_unload_test(){

	NCRYPT_PROV_HANDLE prov = 0;

	auto Status = NCryptOpenStorageProvider(&prov, CNG_STCRYPT_KEYSTORAGE, 0);
	STCRYPT_CHECK( !FAILED(Status) );
	BOOST_SCOPE_EXIT((prov)) {	auto const status = NCryptFreeObject (prov);assert( !FAILED(status) );	}  BOOST_SCOPE_EXIT_END

}


int _tmain(int argc, _TCHAR* argv[])
{

	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | /*_CRTDBG_CHECK_ALWAYS_DF |*/ _CRTDBG_DELAY_FREE_MEM_DF);
	//_CrtSetBreakAlloc(228);

	try{

		load_unload_test();
		//Sleep(100000);
		load_unload_test();

		//t_sid();

		//dstu_test();
		//test_enum_keys();

		//symmetric_test_std_aes();
		//rsa_test();

		//msg_test2(L"J.Smith");
		//msg_test(L"J.Smith");

		return 0;

		cert_create_test();

		return 0;

		cert_test();
		
		dstu1_test();

		symmetric_test_std_aes();

		symmetric_test();

		hash_test();


	} catch (boost::exception const& e) {
		std::cerr << boost::diagnostic_information(e) << std::endl;
		return (EXIT_FAILURE);

	} catch (std::exception const& e) {
		std::cerr << e.what() << std::endl;
		return (EXIT_FAILURE);

	}

	return 0;
}

