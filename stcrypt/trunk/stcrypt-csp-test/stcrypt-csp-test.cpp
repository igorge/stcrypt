// use_test_csp.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include <windows.h>
#include <vector>
#include <iostream>
#include "csp-test-common.hpp"
#include "../stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../stcrypt-csp/stcrypt-crypto-alg-ids.h"

//================================================================================================================================================
void cert_test();
//================================================================================================================================================

#define CHECKCRYPTO(x)	\
{	\
	if( !(x) ) {\
	DWORD const errc=GetLastError();\
	BOOST_THROW_EXCEPTION(stcrypt::exception::cryptoapi_error() << stcrypt::exception::cryptoapi_einfo(errc));\
	}\
}\
	/**/

//================================================================================================================================================
void test_gen_random(stcrypt::cryptprov_ptr_t& prov)
{
	std::vector<BYTE> rnd;
	rnd.resize(4*1024);

	CHECKCRYPTO( CryptGenRandom(*prov,rnd.size(), &rnd[0]));
}
//================================================================================================================================================
void test_hash_key(stcrypt::cryptprov_ptr_t& prov){
    //derive key
    std::string password="Secret Key";
    stcrypt::crypthash_ptr_t hHash = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;
    CHECKCRYPTO(CryptHashData(*hHash, reinterpret_cast<BYTE const*>( password.data() ), static_cast<DWORD>(password.size()),0));
    stcrypt::cryptkey_ptr_t hKey = stcrypt::derive_cryptkey_ptr(
        *prov/*hProv*/,               // Handle to CSP obtained earlier.
        CALG_ID_G28147_89_GAMMA_CBC,
        *hHash,               // Handle to hashed password.
        CRYPT_EXPORTABLE    // Make key exportable.
        );


    stcrypt::crypthash_ptr_t hashedmsg = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;

    CHECKCRYPTO(CryptHashSessionKey(*hashedmsg, *hKey, 0));


}
//================================================================================================================================================
void test_clone_hash(stcrypt::cryptprov_ptr_t& prov){

	std::vector<BYTE> hash0_v(32);
	std::vector<BYTE> hash1_v(32);
	std::vector<BYTE> hash2_v(32);

	DWORD hash_data_len=0;

	try{

		std::string data_to_hash1="Hello World";
		std::string data_to_hash2="qwertyui!";

		std::string data_to_hash0="Hello Worldqwertyui!";

	stcrypt::crypthash_ptr_t hash0 = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0, 0);
	CHECKCRYPTO( CryptHashData(*hash0, reinterpret_cast<BYTE const*>(data_to_hash0.data()), data_to_hash0.size(), 0));
	hash_data_len = hash0_v.size();
	CHECKCRYPTO( CryptGetHashParam(*hash0, HP_HASHVAL, &hash0_v[0], &hash_data_len, 0) );


	stcrypt::crypthash_ptr_t hash1 = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0, 0);
	CHECKCRYPTO( CryptHashData(*hash1, reinterpret_cast<BYTE const*>(data_to_hash1.data()), data_to_hash1.size(), 0));
	HCRYPTHASH hash2=0;
	CHECKCRYPTO(CryptDuplicateHash(*hash1, 0, 0, &hash2));

	CHECKCRYPTO( CryptHashData(*hash1, reinterpret_cast<BYTE const*>(data_to_hash2.data()), data_to_hash2.size(), 0));
	hash_data_len = hash1_v.size();
	CHECKCRYPTO( CryptGetHashParam(*hash1, HP_HASHVAL, &hash1_v[0], &hash_data_len, 0) );


	CHECKCRYPTO( CryptHashData(hash2, reinterpret_cast<BYTE const*>(data_to_hash2.data()), data_to_hash2.size(), 0));
	hash_data_len = hash2_v.size();
	CHECKCRYPTO( CryptGetHashParam(hash2, HP_HASHVAL, &hash2_v[0], &hash_data_len, 0) );

	assert(hash0_v == hash2_v);
	assert(hash1_v == hash2_v);

	try{

	}catch(...){
		CHECKCRYPTO(CryptDestroyHash(hash2));
	}
	CHECKCRYPTO(CryptDestroyHash(hash2));

	}catch(...){
		throw;
	}
}


void test_dstu_export_key_public(stcrypt::cryptprov_ptr_t& prov){
	stcrypt::cryptkey_ptr_t hKey1 = stcrypt::generate_cryptkey_ptr(*prov, AT_SIGNATURE, 0);

	std::vector<BYTE> key_blob;
	DWORD key_blob_size=0;

	{
		CHECKCRYPTO(CryptExportKey(*hKey1, 0, PUBLICKEYBLOB, 0, 0, &key_blob_size));
		key_blob.resize(key_blob_size);
		CHECKCRYPTO(CryptExportKey(*hKey1, 0, PUBLICKEYBLOB, 0, &key_blob[0], &key_blob_size));
	}

	HCRYPTKEY imported_key;
	CHECKCRYPTO(CryptImportKey(*prov, & key_blob[0], key_blob.size(), 0, 0, &imported_key));
	try{

	}catch(...){
		CHECKCRYPTO(CryptDestroyKey(imported_key));
		throw;
	}
	CHECKCRYPTO(CryptDestroyKey(imported_key));


}

void test_dstu_export_key_private(stcrypt::cryptprov_ptr_t& prov){
	test_dstu_export_key_public(prov);

	stcrypt::cryptkey_ptr_t hKey1 = stcrypt::generate_cryptkey_ptr(*prov, AT_SIGNATURE, 0);

	std::vector<BYTE> key_blob;
	DWORD key_blob_size=0;

	{
		CHECKCRYPTO(CryptExportKey(*hKey1, 0, PRIVATEKEYBLOB, 0, 0, &key_blob_size));
		key_blob.resize(key_blob_size);
		CHECKCRYPTO(CryptExportKey(*hKey1, 0, PRIVATEKEYBLOB, 0, &key_blob[0], &key_blob_size));

	}

}


void test_dstu_export_key(stcrypt::cryptprov_ptr_t& prov){
	test_dstu_export_key_private(prov);

	stcrypt::cryptkey_ptr_t session_key = stcrypt::generate_cryptkey_ptr(*prov, CALG_ID_G28147_89_GAMMA_CBC, 0);
	stcrypt::cryptkey_ptr_t hKey1 = stcrypt::generate_cryptkey_ptr(*prov, AT_SIGNATURE, 0);

	char data_crypt[]="123456788765432";
	DWORD data_crypt_size=sizeof(data_crypt);

	CHECKCRYPTO(CryptEncrypt(*session_key, 0, true, 0, reinterpret_cast<BYTE*>(&data_crypt[0]), &data_crypt_size, sizeof(data_crypt)));

	std::vector<BYTE> key_blob;
	DWORD key_blob_size=0;

	{
		CHECKCRYPTO(CryptExportKey(*session_key, *hKey1, SIMPLEBLOB, 0, 0, &key_blob_size));
		key_blob.resize(key_blob_size);
		CHECKCRYPTO(CryptExportKey(*session_key, *hKey1, SIMPLEBLOB, 0, &key_blob[0], &key_blob_size));

	}

	HCRYPTKEY imported_key;
	try{
		CHECKCRYPTO(CryptImportKey(*prov, & key_blob[0], key_blob.size(), *hKey1, 0, &imported_key));
		CHECKCRYPTO(CryptDecrypt(imported_key, 0,true, 0, reinterpret_cast<BYTE*>(&data_crypt[0]), &data_crypt_size));

		std::cout << data_crypt << std::endl;
	}catch(...){
		CHECKCRYPTO(CryptDestroyKey(imported_key));
		throw;
	}
	CHECKCRYPTO(CryptDestroyKey(imported_key));


}
void test_dstu(stcrypt::cryptprov_ptr_t& prov)
{
	std::vector<BYTE> signature;
	stcrypt::cryptkey_ptr_t hKey1;
	{
		hKey1 = stcrypt::generate_cryptkey_ptr(*prov, AT_SIGNATURE, 0);

		std::string password="Secret Key";
		stcrypt::crypthash_ptr_t hHash = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;
		CHECKCRYPTO(CryptHashData(*hHash, reinterpret_cast<BYTE const*>( password.data() ), static_cast<DWORD>(password.size()),0));

		DWORD sign_size=0;
		CHECKCRYPTO(CryptSignHash(*hHash, AT_SIGNATURE, 0, 0, 0, &sign_size));

		signature.resize(sign_size);
		CHECKCRYPTO(CryptSignHash(*hHash, AT_SIGNATURE, 0, 0, &signature[0], &sign_size));

		CHECKCRYPTO( CryptVerifySignature(*hHash, &signature[0], signature.size(), *hKey1, 0, 0) );


	}

	{

		std::string password="Secret Key2";
		stcrypt::crypthash_ptr_t hHash = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;
		CHECKCRYPTO(CryptHashData(*hHash, reinterpret_cast<BYTE const*>( password.data() ), static_cast<DWORD>(password.size()),0));

		try{
			CHECKCRYPTO( CryptVerifySignature(*hHash, &signature[0], signature.size(), *hKey1, 0, 0) );
			}catch(stcrypt::exception::cryptoapi_error const& e) {
				DWORD const * const errcode = boost::get_error_info<stcrypt::exception::cryptoapi_einfo>(e);
				assert(errcode);
				if(errcode && *errcode!=NTE_BAD_SIGNATURE) {
					std::wcout<<TEXT("Invalid error code returned\n");
				}

			}


	}

	stcrypt::cryptkey_ptr_t hKey2 = stcrypt::generate_cryptkey_ptr(*prov, CALG_DSTU4145_SIGN, 0);
}

void test_open_keys(stcrypt::cryptprov_ptr_t& prov){
	HCRYPTKEY key1=0;
	HCRYPTKEY key2=0;
	CryptGetUserKey(*prov, AT_SIGNATURE, &key1);
	CryptGetUserKey(*prov, AT_KEYEXCHANGE, &key2);

	if(key1)
		CryptDestroyKey(key1);
	if(key2)
		CryptDestroyKey(key2);
}

void test_gen_keys(stcrypt::cryptprov_ptr_t& prov)
{
	stcrypt::cryptkey_ptr_t hKey1 = stcrypt::generate_cryptkey_ptr(*prov, CALG_ID_G28147_89_SIMPLE, 0);
	stcrypt::cryptkey_ptr_t hKey2 = stcrypt::generate_cryptkey_ptr(*prov, CALG_ID_G28147_89_GAMMA, 0);
	stcrypt::cryptkey_ptr_t hKey3 = stcrypt::generate_cryptkey_ptr(*prov, CALG_ID_G28147_89_GAMMA_CBC, 0);
}
//================================================================================================================================================
void test_28147_gamma_cbc_w_hash_w_mac(stcrypt::cryptprov_ptr_t& prov)
{


	//derive key
	std::string password="Secret Key";
	stcrypt::crypthash_ptr_t hHash = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;
	CHECKCRYPTO(CryptHashData(*hHash, reinterpret_cast<BYTE const*>( password.data() ), static_cast<DWORD>(password.size()),0));
	stcrypt::cryptkey_ptr_t hKey = stcrypt::derive_cryptkey_ptr(
		*prov/*hProv*/,               // Handle to CSP obtained earlier.
		CALG_ID_G28147_89_GAMMA_CBC,
		*hHash,               // Handle to hashed password.
		CRYPT_EXPORTABLE    // Make key exportable.
		);


	stcrypt::crypthash_ptr_t hashedmsg = stcrypt::create_crypthash_ptr(*prov, CALG_ID_G28147_89_MAC, *hKey,0) ;
	stcrypt::crypthash_ptr_t hashedmsg2 = stcrypt::create_crypthash_ptr(*prov, CALG_ID_G28147_89_MAC, *hKey, 0) ;

	//get block length
	DWORD block_len;
	DWORD buffer_len=sizeof(block_len);
	CHECKCRYPTO(CryptGetKeyParam(*hKey,KP_BLOCKLEN, reinterpret_cast<BYTE*>(&block_len), &buffer_len, 0));
	assert(!(block_len%8));
	block_len/=8;


	//encrypt
	std::string secret_data="Very secret string 222333!";
	std::vector<BYTE> buffer;
	buffer.assign( secret_data.begin(), secret_data.end() );
	buffer_len=static_cast<DWORD>( buffer.size() );
	CHECKCRYPTO(CryptEncrypt(*hKey, 
		NULL, //hash
		TRUE, //final
		0, //flags
		0, //get buffer size
		&buffer_len, //data size
		buffer_len)); // buffer len

	assert(buffer_len>=buffer.size());
	buffer.resize(buffer_len);
	buffer.at(secret_data.size())=0xFF;
	buffer.at(buffer.size()-1)=0xFF;
	buffer_len=secret_data.size();
	buffer.resize( buffer.size()+1 );
	buffer.at(buffer.size()-1)=0xAA;
	CHECKCRYPTO(CryptEncrypt(*hKey, 
		*hashedmsg, //hash
		TRUE, //final
		0, //flags
		&buffer[0], //
		&buffer_len, 
		buffer.size()-1));

	assert(buffer.at(buffer.size()-1)==0xAA);
	buffer.resize(buffer.size()-1);

	DWORD hash_data_len;
	std::vector<BYTE> hash1;
	CHECKCRYPTO(CryptGetHashParam(*hashedmsg, HP_HASHVAL, 0, &hash_data_len, 0));
	hash1.resize(hash_data_len);
	CHECKCRYPTO(CryptGetHashParam(*hashedmsg, HP_HASHVAL, &hash1[0], &hash_data_len, 0));

	{
		buffer_len=buffer_len;
		CHECKCRYPTO(CryptDecrypt(*hKey, 
			*hashedmsg2, //hash
			TRUE, //final
			0, //flags
			&buffer[0], //
			&buffer_len
			));

		DWORD hash_data_len;
		std::vector<BYTE> hash2;
		CHECKCRYPTO(CryptGetHashParam(*hashedmsg2, HP_HASHVAL, 0, &hash_data_len, 0));
		hash2.resize(hash_data_len);
		CHECKCRYPTO(CryptGetHashParam(*hashedmsg2, HP_HASHVAL, &hash2[0], &hash_data_len, 0));

		assert(hash1==hash2);
		//+		hash2	[8](45 '-',53 '5',29 '?',1 '?',238 'î',26 '?',54 '6',194 'Â')	std::vector<unsigned char,std::allocator<unsigned char> >


	}

}
//================================================================================================================================================
//================================================================================================================================================
void test_28147_gamma_cbc_w_hash(stcrypt::cryptprov_ptr_t& prov)
{

	stcrypt::crypthash_ptr_t hashedmsg = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;
	stcrypt::crypthash_ptr_t hashedmsg2 = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;


	//derive key
	std::string password="Secret Key";
	stcrypt::crypthash_ptr_t hHash = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;
	CHECKCRYPTO(CryptHashData(*hHash, reinterpret_cast<BYTE const*>( password.data() ), static_cast<DWORD>(password.size()),0));
	stcrypt::cryptkey_ptr_t hKey = stcrypt::derive_cryptkey_ptr(
		*prov/*hProv*/,               // Handle to CSP obtained earlier.
		CALG_ID_G28147_89_GAMMA_CBC,
		*hHash,               // Handle to hashed password.
		CRYPT_EXPORTABLE    // Make key exportable.
		);


	//get block length
	DWORD block_len;
	DWORD buffer_len=sizeof(block_len);
	CHECKCRYPTO(CryptGetKeyParam(*hKey,KP_BLOCKLEN, reinterpret_cast<BYTE*>(&block_len), &buffer_len, 0));
	assert(!(block_len%8));
	block_len/=8;


	//encrypt
	std::string secret_data="Very secret string 222333!";
	std::vector<BYTE> buffer;
	buffer.assign( secret_data.begin(), secret_data.end() );
	buffer_len=static_cast<DWORD>( buffer.size() );
	CHECKCRYPTO(CryptEncrypt(*hKey, 
		NULL, //hash
		TRUE, //final
		0, //flags
		0, //get buffer size
		&buffer_len, //data size
		buffer_len)); // buffer len

	assert(buffer_len>=buffer.size());
	buffer.resize(buffer_len);
	buffer.at(secret_data.size())=0xFF;
	buffer.at(buffer.size()-1)=0xFF;
	buffer_len=secret_data.size();
	buffer.resize( buffer.size()+1 );
	buffer.at(buffer.size()-1)=0xAA;
	CHECKCRYPTO(CryptEncrypt(*hKey, 
		*hashedmsg, //hash
		TRUE, //final
		0, //flags
		&buffer[0], //
		&buffer_len, 
		buffer.size()-1));

	assert(buffer.at(buffer.size()-1)==0xAA);
	buffer.resize(buffer.size()-1);

	DWORD hash_data_len;
	std::vector<BYTE> hash1;
	CHECKCRYPTO(CryptGetHashParam(*hashedmsg, HP_HASHVAL, 0, &hash_data_len, 0));
	hash1.resize(hash_data_len);
	CHECKCRYPTO(CryptGetHashParam(*hashedmsg, HP_HASHVAL, &hash1[0], &hash_data_len, 0));

	{
		buffer_len=buffer_len;
		CHECKCRYPTO(CryptDecrypt(*hKey, 
			*hashedmsg2, //hash
			TRUE, //final
			0, //flags
			&buffer[0], //
			&buffer_len
			));

		DWORD hash_data_len;
		std::vector<BYTE> hash2;
		CHECKCRYPTO(CryptGetHashParam(*hashedmsg2, HP_HASHVAL, 0, &hash_data_len, 0));
		hash2.resize(hash_data_len);
		CHECKCRYPTO(CryptGetHashParam(*hashedmsg2, HP_HASHVAL, &hash2[0], &hash_data_len, 0));


	}

}
//================================================================================================================================================
void test_28147_gamma_cbc(stcrypt::cryptprov_ptr_t& prov)
{
	//derive key
	std::string password="Secret Key";
	stcrypt::crypthash_ptr_t hHash = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;
	CHECKCRYPTO(CryptHashData(*hHash, reinterpret_cast<BYTE const*>( password.data() ), static_cast<DWORD>(password.size()),0));
	stcrypt::cryptkey_ptr_t hKey = stcrypt::derive_cryptkey_ptr(
		*prov/*hProv*/,               // Handle to CSP obtained earlier.
		CALG_ID_G28147_89_GAMMA_CBC,
		*hHash,               // Handle to hashed password.
		CRYPT_EXPORTABLE    // Make key exportable.
		);


	//get block length
	DWORD block_len;
	DWORD buffer_len=sizeof(block_len);
	CHECKCRYPTO(CryptGetKeyParam(*hKey,KP_BLOCKLEN, reinterpret_cast<BYTE*>(&block_len), &buffer_len, 0));
	assert(!(block_len%8));
	block_len/=8;


	//encrypt
	std::string secret_data="Very secret string 222333!";
	std::vector<BYTE> buffer;
	buffer.assign( secret_data.begin(), secret_data.end() );
	buffer_len=static_cast<DWORD>( buffer.size() );
	CHECKCRYPTO(CryptEncrypt(*hKey, 
		NULL, //hash
		TRUE, //final
		0, //flags
		0, //get buffer size
		&buffer_len, //data size
		buffer_len)); // buffer len

	assert(buffer_len>=buffer.size());
	buffer.resize(buffer_len);
	buffer.at(secret_data.size())=0xFF;
	buffer.at(buffer.size()-1)=0xFF;
	buffer_len=secret_data.size();
	buffer.resize( buffer.size()+1 );
	buffer.at(buffer.size()-1)=0xAA;
	CHECKCRYPTO(CryptEncrypt(*hKey, 
		NULL, //hash
		TRUE, //final
		0, //flags
		&buffer[0], //
		&buffer_len, 
		buffer.size()-1));

	assert(buffer.at(buffer.size()-1)==0xAA);
	buffer.resize(buffer.size()-1);

	{
		buffer_len=buffer_len;
		CHECKCRYPTO(CryptDecrypt(*hKey, 
			NULL, //hash
			TRUE, //final
			0, //flags
			&buffer[0], //
			&buffer_len
			));

	}


}


void test_28147_gamma(stcrypt::cryptprov_ptr_t& prov)
{
	//derive key
	std::string password="Secret Key";
	stcrypt::crypthash_ptr_t hHash = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;
	CHECKCRYPTO(CryptHashData(*hHash, reinterpret_cast<BYTE const*>( password.data() ), static_cast<DWORD>(password.size()),0));
	stcrypt::cryptkey_ptr_t hKey = stcrypt::derive_cryptkey_ptr(
		*prov/*hProv*/,               // Handle to CSP obtained earlier.
		CALG_ID_G28147_89_GAMMA,
		*hHash,               // Handle to hashed password.
		CRYPT_EXPORTABLE    // Make key exportable.
		);


	//get block length
	DWORD block_len;
	DWORD buffer_len=sizeof(block_len);
	CHECKCRYPTO(CryptGetKeyParam(*hKey,KP_BLOCKLEN, reinterpret_cast<BYTE*>(&block_len), &buffer_len, 0));
	assert(!(block_len%8));
	block_len/=8;


	//encrypt
	std::string secret_data="Very secret string 222333!";
	std::vector<BYTE> buffer;
	buffer.assign( secret_data.begin(), secret_data.end() );
	buffer_len=static_cast<DWORD>( buffer.size() );
	CHECKCRYPTO(CryptEncrypt(*hKey, 
		NULL, //hash
		TRUE, //final
		0, //flags
		0, //get buffer size
		&buffer_len, //data size
		buffer_len)); // buffer len

	assert(buffer_len>=buffer.size());
	buffer.resize(buffer_len);
	buffer.at(secret_data.size())=0xFF;
	buffer.at(buffer.size()-1)=0xFF;
	buffer_len=secret_data.size();
	buffer.resize( buffer.size()+1 );
	buffer.at(buffer.size()-1)=0xAA;
	CHECKCRYPTO(CryptEncrypt(*hKey, 
		NULL, //hash
		TRUE, //final
		0, //flags
		&buffer[0], //
		&buffer_len, 
		buffer.size()-1));

	assert(buffer.at(buffer.size()-1)==0xAA);
	buffer.resize(buffer.size()-1);

	{
		buffer_len=buffer_len;
		CHECKCRYPTO(CryptDecrypt(*hKey, 
			NULL, //hash
			TRUE, //final
			0, //flags
			&buffer[0], //
			&buffer_len
			));

	}


}

void test_28147(stcrypt::cryptprov_ptr_t& prov)
{
	//derive key
	std::string password="Secret Key";
	stcrypt::crypthash_ptr_t hHash = stcrypt::create_crypthash_ptr(*prov, CALG_ID_HASH_G34311, 0,0) ;
	CHECKCRYPTO(CryptHashData(*hHash, reinterpret_cast<BYTE const*>( password.data() ), static_cast<DWORD>(password.size()),0));
	stcrypt::cryptkey_ptr_t hKey = stcrypt::derive_cryptkey_ptr(
		*prov/*hProv*/,               // Handle to CSP obtained earlier.
		CALG_ID_G28147_89_SIMPLE,
		*hHash,               // Handle to hashed password.
		CRYPT_EXPORTABLE    // Make key exportable.
		);


	//get block length
	DWORD block_len;
	DWORD buffer_len=sizeof(block_len);
	CHECKCRYPTO(CryptGetKeyParam(*hKey,KP_BLOCKLEN, reinterpret_cast<BYTE*>(&block_len), &buffer_len, 0));
	assert(!(block_len%8));
	block_len/=8;


	//encrypt
	std::string secret_data="Very secret string 222333!";
	std::vector<BYTE> buffer;
	buffer.assign( secret_data.begin(), secret_data.end() );
	buffer_len=static_cast<DWORD>( buffer.size() );
	CHECKCRYPTO(CryptEncrypt(*hKey, 
				 NULL, //hash
				 TRUE, //final
				 0, //flags
				 0, //get buffer size
				 &buffer_len, //data size
				 buffer_len)); // buffer len

	assert(buffer_len>=buffer.size());
	buffer.resize(buffer_len);
	buffer.at(secret_data.size())=0xFF;
	buffer.at(buffer.size()-1)=0xFF;
	buffer_len=secret_data.size();
	buffer.resize( buffer.size()+1 );
	buffer.at(buffer.size()-1)=0xAA;
	CHECKCRYPTO(CryptEncrypt(*hKey, 
		NULL, //hash
		TRUE, //final
		0, //flags
		&buffer[0], //
		&buffer_len, 
		buffer.size()-1));
	
	assert(buffer.at(buffer.size()-1)==0xAA);
	buffer.resize(buffer.size()-1);

	{
		buffer_len=buffer.size();
		CHECKCRYPTO(CryptDecrypt(*hKey, 
			NULL, //hash
			TRUE, //final
			0, //flags
			&buffer[0], //
			&buffer_len
			));

	}


}
//================================================================================================================================================
int _tmain(int argc, _TCHAR* argv[])
{
    _CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_DELAY_FREE_MEM_DF);

	try {

        cert_test();

		{
			stcrypt::cryptprov_ptr_t hProv = stcrypt::create_cryptprov_ptr(TEXT("Test KEY Container"), 		TEXT("STCRYPT"),STCRYPT_PROVIDER_TYPE, 0 /*CRYPT_NEWKEYSET */);

			std::vector<BYTE> container_name;
			DWORD dataLen;
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, 0, &dataLen, CRYPT_FIRST));
			container_name.resize(dataLen);
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_FIRST));
			container_name.resize(dataLen-1);

			try{
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_NEXT));
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_NEXT));
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_NEXT));

			}catch(stcrypt::exception::cryptoapi_error const& e) {
				DWORD const * const errcode = boost::get_error_info<stcrypt::exception::cryptoapi_einfo>(e);
				assert(errcode);
				if(errcode && *errcode!=ERROR_NO_MORE_ITEMS) {
					std::wcout<<TEXT("Invalid error code returned\n");
				}

			}
		}




		{
			stcrypt::cryptprov_ptr_t hProv = stcrypt::create_cryptprov_ptr(TEXT("Test KEY Container"), 		TEXT("STCRYPT"), STCRYPT_PROVIDER_TYPE, 0 /*CRYPT_NEWKEYSET */);

			PROV_ENUMALGS_EX enum_algs;
			DWORD len =  sizeof(enum_algs);
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMALGS_EX, reinterpret_cast<BYTE*>(&enum_algs), &len, CRYPT_FIRST));

			try{
				while(true){CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMALGS_EX, reinterpret_cast<BYTE*>(&enum_algs), &len, CRYPT_NEXT));}
			}catch(stcrypt::exception::cryptoapi_error const& e) {
				DWORD const * const errcode = boost::get_error_info<stcrypt::exception::cryptoapi_einfo>(e);
				assert(errcode);
				if(errcode && *errcode!=ERROR_NO_MORE_ITEMS) {
					std::wcout<<TEXT("Invalid error code returned\n");
				}

			}



		}

		{
			stcrypt::cryptprov_ptr_t hProv = stcrypt::create_cryptprov_ptr(TEXT("Test KEY Container"), 		TEXT("STCRYPT"), STCRYPT_PROVIDER_TYPE, 0 /*CRYPT_NEWKEYSET */);

			PROV_ENUMALGS enum_algs;
			DWORD len =  sizeof(enum_algs);
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMALGS, reinterpret_cast<BYTE*>(&enum_algs), &len, CRYPT_FIRST));

			try{
				while(true){CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMALGS, reinterpret_cast<BYTE*>(&enum_algs), &len, CRYPT_NEXT));}
			}catch(stcrypt::exception::cryptoapi_error const& e) {
				DWORD const * const errcode = boost::get_error_info<stcrypt::exception::cryptoapi_einfo>(e);
				assert(errcode);
				if(errcode && *errcode!=ERROR_NO_MORE_ITEMS) {
					std::wcout<<TEXT("Invalid error code returned\n");
				}

			}

			

		}

		{ // orig MS RSA query
			stcrypt::cryptprov_ptr_t hProv = stcrypt::create_cryptprov_ptr(0, 		0, PROV_RSA_FULL, 0 );

			std::vector<BYTE> container_name;
			DWORD dataLen=1024;
			container_name.resize(dataLen);
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_FIRST));
			container_name.resize(dataLen-1); //do not need 0

			try{
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_NEXT));
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_NEXT));
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_NEXT));

			}catch(stcrypt::exception::cryptoapi_error const& e) {
				DWORD const * const errcode = boost::get_error_info<stcrypt::exception::cryptoapi_einfo>(e);
				assert(errcode);
				if(errcode && *errcode!=ERROR_NO_MORE_ITEMS) {
					std::wcout<<TEXT("Invalid error code returned\n");
				}

			}



		}

		stcrypt::cryptprov_ptr_t hProv = stcrypt::create_cryptprov_ptr(TEXT("Test KEY Container"), 		TEXT("STCRYPT"), STCRYPT_PROVIDER_TYPE, 0 /*CRYPT_NEWKEYSET */);

		{
			std::vector<BYTE> name;
			DWORD dataLen;
			name.resize(1024);
			dataLen=static_cast<DWORD>( name.size() );
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_NAME, &name[0], &dataLen, 0));
		}
		
		{
			std::vector<BYTE> container_name;
			DWORD dataLen;
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_CONTAINER, 0, &dataLen, 0));
			container_name.resize(dataLen);
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_CONTAINER, &container_name[0], &dataLen, 0));
		}

		{
			std::vector<BYTE> container_name;
			DWORD dataLen=1024;
			container_name.resize(dataLen);
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_FIRST));
			container_name.resize(dataLen-1); //do not need 0

			try{
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_NEXT));
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_NEXT));
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, &container_name[0], &dataLen, CRYPT_NEXT));

			}catch(stcrypt::exception::cryptoapi_error const& e) {
				DWORD const * const errcode = boost::get_error_info<stcrypt::exception::cryptoapi_einfo>(e);
				assert(errcode);
				if(errcode && *errcode!=ERROR_NO_MORE_ITEMS) {
					std::wcout<<TEXT("Invalid error code returned\n");
				}

			}

		}


		{
			DWORD dataLen;
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, 0, &dataLen, CRYPT_FIRST));
			CHECKCRYPTO(CryptGetProvParam(*hProv,PP_ENUMCONTAINERS, 0, &dataLen, CRYPT_NEXT));
		}

		{
			try {
				std::vector<BYTE> container_name;
				DWORD dataLen;
				container_name.resize(5);
				dataLen=static_cast<DWORD>( container_name.size() );
				CHECKCRYPTO(CryptGetProvParam(*hProv,PP_CONTAINER, &container_name[0], &dataLen, 0));
			} catch(stcrypt::exception::cryptoapi_error const& e) {
				DWORD const * const errcode = boost::get_error_info<stcrypt::exception::cryptoapi_einfo>(e);
				assert(errcode);
				if(errcode && *errcode!=ERROR_MORE_DATA) {
					std::wcout<<TEXT("Invalid error code returned\n");
				}
			}
		}


		std::string data="Test  data to hash";

		stcrypt::crypthash_ptr_t hHash = stcrypt::create_crypthash_ptr(*hProv, CALG_ID_HASH_G34311, 0,0) ;
			
		if(!CryptHashData(*hHash, reinterpret_cast<BYTE const*>( data.data() ), static_cast<DWORD>(data.size()),0)){
				printf("Failed to hash data");}
			else {
				typedef std::vector<BYTE> hash_type;
				hash_type hashed_data;

				DWORD hash_data_len;
				if(!CryptGetHashParam(*hHash, HP_HASHVAL, 0, &hash_data_len, 0)){
					printf("Failed to get hashed data size");	
				} else {
					hashed_data.resize(hash_data_len);
					if(!CryptGetHashParam(*hHash, HP_HASHVAL, &hashed_data[0], &hash_data_len, 0)){
						printf("Failed to get hash") ;
					} else {
						for(hash_type::const_iterator end=hashed_data.end(), i=hashed_data.begin(); i<end;++i)
						{
							std::cout << std::hex << static_cast<unsigned int>(*i);
						}
						std::cout<<std::endl;
					}
				}

			}

    test_hash_key(hProv);
	test_clone_hash(hProv);
	test_open_keys(hProv);
	test_dstu_export_key(hProv);
	test_dstu(hProv);
	test_gen_keys(hProv);
	test_gen_random(hProv);
	test_28147_gamma_cbc_w_hash_w_mac(hProv);
	test_28147_gamma_cbc_w_hash(hProv);
	test_28147_gamma_cbc(hProv);
	test_28147(hProv);
	test_28147_gamma(hProv);

	std::cerr << "OK\n";
	} catch(stcrypt::exception::cryptoapi_error const& e) {
		std::cerr << boost::diagnostic_information(e) << '\n';
		DWORD const * const errc = boost::get_error_info<stcrypt::exception::cryptoapi_einfo>(e);
		if(errc){ std::wcerr << format_sys_message<TCHAR>(*errc) << TEXT("\n"); }
	} catch(boost::exception const& e) {
		std::cerr << boost::diagnostic_information(e) << TEXT("\n");
    } catch(std::exception const& e) {
        std::cerr << e.what()<< std::endl;
    }

	getchar();

	return 0;
}

