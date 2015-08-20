//================================================================================================================================================
// FILE: stcrypt-toycert-signature-verifier.cpp
// (c) GIE 2010-04-02  17:46
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-toycert-signature-verifier.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-crypto-alg-ids.h"

#include "boost/scope_exit.hpp"
//================================================================================================================================================
namespace stcrypt { namespace ca {

	bool verify_signature_via_csp( char const * const blob, size_t const size, toycert_t::signature_blob_t const& signature, toycert_t& pub_key_from_cert )
	{

		toycert_t::pub_key_blob_t public_key_blob;
		oid::oid_type oid;
		pub_key_from_cert.get_public_key_blob(public_key_blob, oid);
		if(public_key_blob.size()==0) STCRYPT_UNEXPECTED();

		stcrypt::cryptprov_ptr_t cprov = create_cryptprov_ptr(0, STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, CRYPT_VERIFYCONTEXT);

		stcrypt::crypthash_ptr_t hash = create_crypthash_ptr(*cprov, CALG_ID_HASH_G34311, 0, 0);
		STCRYPT_CHECK_MSCRYPTO( CryptHashData(*hash, reinterpret_cast<BYTE const*>(blob), size, 0) );

		HCRYPTPROV hkey= 0;
		STCRYPT_CHECK_MSCRYPTO( CryptImportKey(*cprov, reinterpret_cast<BYTE const*>(&public_key_blob[0]), public_key_blob.size(), 0, 0, &hkey) );

		BOOST_SCOPE_EXIT( (hkey) ){
			BOOL const r = CryptDestroyKey(hkey);
			assert(r!=0);
		} BOOST_SCOPE_EXIT_END

		try {
			STCRYPT_CHECK_MSCRYPTO( CryptVerifySignature(*hash, reinterpret_cast<BYTE const*>( &signature[0] ), signature.size(), hkey, 0,0 ) );
		} catch ( stcrypt::exception::cryptoapi_error const&e ) {
			return false;
		}

		return true;
	}


	void export_key(HCRYPTPROV const csp, HCRYPTKEY const key, toycert_t& cert, std::vector<char>& exported_and_encrypted_session_key){

		toycert_t::pub_key_blob_t public_key_blob;
		oid::oid_type oid;
		cert.get_public_key_blob(public_key_blob, oid);

		if(public_key_blob.size()==0)STCRYPT_UNEXPECTED();

		HCRYPTPROV public_key = 0;
		STCRYPT_CHECK_MSCRYPTO( CryptImportKey(csp, reinterpret_cast<BYTE const*>(&public_key_blob[0]), public_key_blob.size(), 0, 0, &public_key) );

		BOOST_SCOPE_EXIT( (public_key) ){
			BOOL const r = CryptDestroyKey(public_key);
			assert(r!=0);
		} BOOST_SCOPE_EXIT_END

		DWORD session_key_blob_size=0;
		STCRYPT_CHECK_MSCRYPTO( CryptExportKey(key, public_key, SIMPLEBLOB, 0, 0, &session_key_blob_size) );
		exported_and_encrypted_session_key.resize(session_key_blob_size);
		STCRYPT_CHECK_MSCRYPTO( CryptExportKey(key, public_key, SIMPLEBLOB, 0, reinterpret_cast<BYTE*>(&exported_and_encrypted_session_key[0]), &session_key_blob_size) );
	}


	HCRYPTKEY import_key( HCRYPTPROV const csp, std::vector<char> const& enc_key_blob )
	{
		HCRYPTPROV private_key = 0;
		STCRYPT_CHECK_MSCRYPTO( CryptGetUserKey(csp, AT_SIGNATURE, &private_key) );

		BOOST_SCOPE_EXIT( (private_key) ){
			BOOL const r = CryptDestroyKey(private_key);
			assert(r!=0);
		} BOOST_SCOPE_EXIT_END

		HCRYPTKEY session_key = 0;
		STCRYPT_CHECK_MSCRYPTO( CryptImportKey(csp, reinterpret_cast<BYTE const*>( &enc_key_blob[0] ), enc_key_blob.size(), private_key, 0, &session_key) );

		return session_key;

	}

} }
//================================================================================================================================================
