//================================================================================================================================================
// FILE: util-raii-helpers-crypt.h
// (c) GIE 2009-11-03  12:27
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_RAII_HELPERS_CRYPT_2009_11_03_12_27
#define H_GUARD_UTIL_RAII_HELPERS_CRYPT_2009_11_03_12_27
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"
#include "boost/shared_ptr.hpp"
#include <WinCrypt.h>

#include <vector>
//================================================================================================================================================
#define STCRYPT_CHECK_MSCRYPTO(x)	\
{	\
	if( !(x) ) {\
	DWORD const errc=GetLastError();\
	STCRYPT_THROW_EXCEPTION(stcrypt::exception::cryptoapi_error() << stcrypt::exception::cryptoapi_einfo(errc));\
	}\
}\
	/**/
//================================================================================================================================================

namespace stcrypt {
//================================================================================================================================================
	inline
	void export_key_as_simple_blob(HCRYPTKEY const key, HCRYPTKEY encrypt_with_key, std::vector<char>& exported_blob){
		DWORD blob_size = 0;
		STCRYPT_CHECK_MSCRYPTO( CryptExportKey(key, encrypt_with_key,  SIMPLEBLOB, 0,0, &blob_size) );
		exported_blob.resize(blob_size);
		STCRYPT_CHECK_MSCRYPTO( CryptExportKey(key, encrypt_with_key, SIMPLEBLOB, 0,reinterpret_cast<BYTE*>( &exported_blob[0] ), &blob_size) );
	}

	inline
	void export_key_as_public_blob(HCRYPTKEY const key, std::vector<char>& exported_blob){
		DWORD blob_size = 0;
		STCRYPT_CHECK_MSCRYPTO( CryptExportKey(key, 0, PUBLICKEYBLOB, 0,0, &blob_size) );
		exported_blob.resize(blob_size);
		STCRYPT_CHECK_MSCRYPTO( CryptExportKey(key, 0, PUBLICKEYBLOB, 0,reinterpret_cast<BYTE*>( &exported_blob[0] ), &blob_size) );
	}

//================================================================================================================================================
	inline void delete_HCRYPTPROV(HCRYPTPROV * const prov)
	{
		assert(prov);
		BOOL const r = CryptReleaseContext(*prov, 0);
		assert( r ); //TODO: can't throw from a destructor
		delete prov;
	}

	typedef boost::shared_ptr<HCRYPTPROV>	cryptprov_ptr_t;

	inline cryptprov_ptr_t create_cryptprov_ptr( LPCTSTR pszContainer, LPCTSTR pszProvider,	DWORD dwProvType, DWORD dwFlags )
	{
		HCRYPTPROV tmp;
		if( !CryptAcquireContext(&tmp, pszContainer, pszProvider, dwProvType, dwFlags ) )
		{
			DWORD const errc = GetLastError();
			STCRYPT_THROW_EXCEPTION( exception::cryptoapi_error( ) << exception::cryptoapi_einfo(errc) );
		}

		std::auto_ptr<HCRYPTHASH> hcryptprov_mem;
		try {
			hcryptprov_mem.reset(new HCRYPTPROV(tmp));
		}catch(...){
			BOOL const r = CryptReleaseContext(tmp,0); assert(r);
			throw;
		}

		return cryptprov_ptr_t ( hcryptprov_mem.release(), delete_HCRYPTPROV );
	}

//================================================================================================================================================
	inline void delete_HCRYPTHASH(HCRYPTHASH * const hash)
	{
		assert(hash);
		BOOL const r = CryptDestroyHash(*hash);
		assert( r ); //TODO: can't throw from a destructor
		delete hash;
	}

	typedef boost::shared_ptr<HCRYPTHASH>	crypthash_ptr_t;

	inline crypthash_ptr_t create_crypthash_ptr(HCRYPTPROV hProv,	ALG_ID Algid,	HCRYPTKEY hKey,	DWORD dwFlags)
	{
		HCRYPTHASH tmp;
		
		if( !CryptCreateHash( hProv, Algid, hKey, dwFlags, &tmp ) )
		{
			DWORD const errc = GetLastError();
			STCRYPT_THROW_EXCEPTION( exception::cryptoapi_error() << exception::cryptoapi_einfo(errc) );
		}

		std::auto_ptr<HCRYPTHASH> hcrypthash_mem;
		try {
			hcrypthash_mem.reset(new HCRYPTHASH(tmp));
		}catch(...){
			BOOL const r = CryptDestroyHash(tmp); assert(r);
			throw;
		}

		return crypthash_ptr_t  ( hcrypthash_mem.release(), delete_HCRYPTHASH );
	}
//================================================================================================================================================
	inline void delete_HCRYPTKEY(HCRYPTKEY * const key)
	{
		assert(key);
		BOOL const r = CryptDestroyKey(*key);
		assert( r ); //TODO: can't throw from a destructor
		delete key;
	}

	typedef boost::shared_ptr<HCRYPTKEY>	cryptkey_ptr_t;


	inline cryptkey_ptr_t wrap_cryptkey_ptr(HCRYPTKEY const tmp)
	{
		std::auto_ptr<HCRYPTKEY> HCRYPTKEY_mem;
		try {
			HCRYPTKEY_mem.reset(new HCRYPTKEY(tmp));
		}catch(...){
			BOOL const r = CryptDestroyKey(tmp); assert(r);
			throw;
		}

		return cryptkey_ptr_t  ( HCRYPTKEY_mem.release(), delete_HCRYPTKEY );
	}

	inline cryptkey_ptr_t derive_cryptkey_ptr(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTHASH hBaseData, DWORD dwFlags)
	{
		HCRYPTKEY tmp;
		
		if( !CryptDeriveKey(hProv, Algid, hBaseData, dwFlags, &tmp ) )
		{
			DWORD const errc = GetLastError();
			STCRYPT_THROW_EXCEPTION( exception::cryptoapi_error() << exception::cryptoapi_einfo(errc) );
		}

		std::auto_ptr<HCRYPTKEY> HCRYPTKEY_mem;
		try {
			HCRYPTKEY_mem.reset(new HCRYPTKEY(tmp));
		}catch(...){
			BOOL const r = CryptDestroyKey(tmp); assert(r);
			throw;
		}

		return cryptkey_ptr_t  ( HCRYPTKEY_mem.release(), delete_HCRYPTKEY );
	}

	inline cryptkey_ptr_t get_user_cryptkey_ptr(HCRYPTPROV hProv, DWORD dwKeySpec)
	{
		HCRYPTKEY tmp;

		if( !CryptGetUserKey(hProv, dwKeySpec, &tmp ) )
		{
			DWORD const errc = GetLastError();
			STCRYPT_THROW_EXCEPTION( exception::cryptoapi_error() << exception::cryptoapi_einfo(errc) );
		}

		std::auto_ptr<HCRYPTKEY> HCRYPTKEY_mem;
		try {
			HCRYPTKEY_mem.reset(new HCRYPTKEY(tmp));
		}catch(...){
			BOOL const r = CryptDestroyKey(tmp); assert(r);
			throw;
		}

		return cryptkey_ptr_t  ( HCRYPTKEY_mem.release(), delete_HCRYPTKEY );
	}


	inline cryptkey_ptr_t generate_cryptkey_ptr(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags)
	{
		HCRYPTKEY tmp;

		if( !CryptGenKey(hProv, Algid, dwFlags, &tmp ) )
		{
			DWORD const errc = GetLastError();
			STCRYPT_THROW_EXCEPTION( exception::cryptoapi_error() << exception::cryptoapi_einfo(errc) );
		}

		std::auto_ptr<HCRYPTKEY> HCRYPTKEY_mem;
		try {
			HCRYPTKEY_mem.reset(new HCRYPTKEY(tmp));
		}catch(...){
			BOOL const r = CryptDestroyKey(tmp); assert(r);
			throw;
		}

		return cryptkey_ptr_t  ( HCRYPTKEY_mem.release(), delete_HCRYPTKEY );
	}


	inline cryptkey_ptr_t import_cryptkey_ptr(HCRYPTPROV hProv, char const * const data, DWORD const size, HCRYPTKEY const pub_key, DWORD const flags)
	{
		HCRYPTKEY tmp;

		if( !CryptImportKey(hProv, reinterpret_cast<BYTE const*>(data), size, pub_key, flags, &tmp ) )
		{
			DWORD const errc = GetLastError();
			STCRYPT_THROW_EXCEPTION( exception::cryptoapi_error() << exception::cryptoapi_einfo(errc) );
		}

		std::auto_ptr<HCRYPTKEY> HCRYPTKEY_mem;
		try {
			HCRYPTKEY_mem.reset(new HCRYPTKEY(tmp));
		}catch(...){
			BOOL const r = CryptDestroyKey(tmp); assert(r);
			throw;
		}

		return cryptkey_ptr_t  ( HCRYPTKEY_mem.release(), delete_HCRYPTKEY );
	}

//================================================================================================================================================

}
//================================================================================================================================================
#endif
//================================================================================================================================================
