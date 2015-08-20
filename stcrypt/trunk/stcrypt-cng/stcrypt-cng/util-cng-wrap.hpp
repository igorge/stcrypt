//================================================================================================================================================
// FILE: util-cng-wrap.h
// (c) GIE 2010-08-26  21:14
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_CNG_WRAP_2010_08_26_21_14
#define H_GUARD_UTIL_CNG_WRAP_2010_08_26_21_14
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"

#include <vector>
//================================================================================================================================================
namespace stcrypt {

	struct n_key_func_wrap_t {
		typedef NCRYPT_KEY_HANDLE	raw_handle_type;

		static size_t sign_hash(raw_handle_type const m_key, void * const padding_info, unsigned char const*const data_to_be_hashed, size_t const size_of_data_to_be_hashed,
								unsigned char *const signature, size_t const size_of_signature, DWORD const flags = 0){

			assert(m_key);
			assert(data_to_be_hashed);

			DWORD result_size = size_of_data_to_be_hashed;
			auto const status = NCryptSignHash(m_key,	padding_info, const_cast<unsigned char*>( data_to_be_hashed ), size_of_data_to_be_hashed,  signature, size_of_signature, &result_size, flags);
			if( FAILED(status) ) STCRYPT_THROW_EXCEPTION( exception::cng_n_call() << exception::security_status_einfo(status) );

			return result_size;
		}


		static size_t signature_size(raw_handle_type const m_key, void * const padding_info, unsigned char const*const data_to_be_hashed, size_t const size_of_data_to_be_hashed, DWORD const flags = 0){
			assert(m_key);
			assert(data_to_be_hashed);

			return sign_hash( m_key, padding_info, data_to_be_hashed, size_of_data_to_be_hashed, 0, 0, flags);
		}

		static size_t export_key_blob(raw_handle_type const m_key, LPCWSTR pszBlobType, unsigned char * const buffer, size_t const buffer_size){
			assert( m_key );
			assert( pszBlobType );

			ULONG result_size;

			auto const status = NCryptExportKey(m_key, 0, pszBlobType, 0, buffer, buffer_size, &result_size, 0);
			if( FAILED(status) ) STCRYPT_THROW_EXCEPTION( exception::cng_n_call() << exception::security_status_einfo(status) );

			return result_size;
		}

		static std::vector<BYTE> export_key_blob(raw_handle_type const m_key, LPCWSTR pszBlobType){
			std::vector<BYTE> tmp;

			auto const blob_size = export_key_blob( m_key, pszBlobType, 0, 0 );
			tmp.resize(blob_size);

			auto const actual_blob_size = export_key_blob( m_key, pszBlobType, tmp.data(), tmp.size() );
			if(actual_blob_size!=blob_size) tmp.resize( actual_blob_size );

			return std::move( tmp );
		}


		static size_t key_blob_size(raw_handle_type const m_key, LPCWSTR pszBlobType){
			return export_key_blob( m_key, pszBlobType, 0, 0 );
		}
	};

	struct cng_key_func_wrap_t {
		typedef BCRYPT_KEY_HANDLE	raw_handle_type;

		static void sign_hash(raw_handle_type const m_key, VOID * const pPaddingInfo,PBYTE const pbInput, DWORD const cbInput, PBYTE const pbOutput,DWORD const cbOutput, DWORD * const pcbResult, ULONG const dwFlags){
			assert( m_key );

			auto const status = BCryptSignHash(m_key, pPaddingInfo, pbInput, cbInput, pbOutput, cbOutput, pcbResult, dwFlags);
			if(! NT_SUCCESS(status) ) {
				STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(status) );
			}
		}

		static bool verify_signature(raw_handle_type const m_key, VOID *pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags){
			assert( m_key );

			auto const status = BCryptVerifySignature(m_key, pPaddingInfo, pbHash, cbHash, pbSignature, cbSignature, dwFlags);

			if( status == STATUS_INVALID_SIGNATURE ){
				return false;
			} else if(! NT_SUCCESS(status) ) {
				STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(status) );
			}

			return true;
		}

		static void finalize(raw_handle_type const m_key){
			assert( m_key );

			auto const status = BCryptFinalizeKeyPair(m_key, 0);
			if(! NT_SUCCESS(status) ) {
				STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(status) );
			}
		}


		static size_t key_blob_size(raw_handle_type const m_key, LPCWSTR pszBlobType){
			assert( m_key );
			assert( pszBlobType );

			ULONG result_size;

			auto const status = BCryptExportKey(m_key, 0, pszBlobType, 0, 0, &result_size, 0);
			if( !NT_SUCCESS(status) ) STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(status) );

			return result_size;

		}

		static size_t export_key_blob(raw_handle_type const m_key, LPCWSTR pszBlobType, unsigned char * const buffer, size_t const buffer_size){
			assert( m_key );
			assert( pszBlobType );
			assert( buffer );

			ULONG result_size;

			auto const status = BCryptExportKey(m_key, 0, pszBlobType, buffer, buffer_size, &result_size, 0);
			if( !NT_SUCCESS(status) ) STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(status) );

			return result_size;
		}

		static std::vector<UCHAR> export_key_blob(raw_handle_type const m_key, LPCWSTR pszBlobType){
			assert( m_key );
			assert( pszBlobType );

			auto const result_size = key_blob_size( m_key, pszBlobType );

			std::vector<UCHAR> tmp(result_size);

			if( export_key_blob(m_key, pszBlobType, tmp.data(), tmp.size() )!=result_size){
				tmp.resize( result_size );
			}

			return std::move( tmp );
		}

		static DWORD asym_decrypt(raw_handle_type const m_key, PBYTE const pbInput, DWORD const cbInput, VOID * const pPaddingInfo, PBYTE const pbOutput, DWORD const cbOutput, DWORD const dwFlags){
			assert( m_key );
			assert( pbInput );

			ULONG result = 0;
			auto const status =BCryptDecrypt(m_key, pbInput, cbInput, pPaddingInfo, 0, 0, pbOutput, cbOutput, &result, dwFlags);

			if( !NT_SUCCESS(status) ) STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(status) );

			return result;
		}


	};


	struct cng_key
		: private cng_key_func_wrap_t
	{
		typedef cng_key_func_wrap_t impl_t;
		typedef cng_key_func_wrap_t::raw_handle_type	raw_handle_type;

		explicit cng_key()
			: m_key(0)
		{}

		explicit cng_key (raw_handle_type  const alg)
			: m_key( alg )
		{}

		cng_key(cng_key&& other){
			m_key = other.m_key;
			other.m_key = 0;
		}

		cng_key& operator=(cng_key && other){
			assert(this!=&other);

			this->destroy_();
			m_key = other.m_key;

			return *this;
		}

		~cng_key(){
			destroy_();
		}

		raw_handle_type to_handle()const{
			return m_key;
		}

		raw_handle_type release(){
			auto const tmp = this->to_handle();
			m_key = 0;

			return std::move(tmp);
		}

		void sign_hash(VOID * const pPaddingInfo,PBYTE const pbInput, DWORD const cbInput, PBYTE const pbOutput,DWORD const cbOutput, DWORD * const pcbResult, ULONG const dwFlags){
			return impl_()->sign_hash(m_key, pPaddingInfo, pbInput, cbInput, pbOutput, cbOutput, pcbResult, dwFlags);
		}

		bool verify_signature(VOID *pPaddingInfo, PUCHAR pbHash, ULONG cbHash, PUCHAR pbSignature, ULONG cbSignature, ULONG dwFlags)const{
			return impl_()->verify_signature(m_key, pPaddingInfo, pbHash, cbHash, pbSignature, cbSignature, dwFlags);
		}

		void finalize(){
			return impl_()->finalize(m_key);
		}

		std::vector<UCHAR> export_key_blob(LPCWSTR pszBlobType){
			return impl_()->export_key_blob(m_key, pszBlobType);
		}

		DWORD asym_decrypt(PBYTE const pbInput, DWORD const cbInput, VOID * const pPaddingInfo, PBYTE const pbOutput, DWORD const cbOutput, DWORD const dwFlags){
			return impl_()->asym_decrypt(m_key, pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, dwFlags);
		}

	private:
		explicit cng_key(cng_key const& other);
		cng_key& operator=(cng_key const& other);

		void destroy_(){
			if( m_key ) {
				auto const status = BCryptDestroyKey(m_key); 
				if(!NT_SUCCESS(status) ) {assert(false);}
			}
		}


		impl_t* impl_(){ return static_cast<impl_t*>(this); }
		impl_t const * impl_()const{ return static_cast<impl_t const*>(this); }

	private:
		BCRYPT_KEY_HANDLE	m_key;
	};


	struct cng_alg {


		explicit cng_alg()
			: m_alg(0)
		{}

		explicit cng_alg (BCRYPT_ALG_HANDLE  const alg)
			: m_alg( alg )
		{}

		cng_alg(cng_alg&& other){
			m_alg = other.m_alg;
			other.m_alg = 0;
		}

		cng_alg& operator=(cng_alg && other){
			assert(this!=&other);

			this->release_();
			m_alg = other.m_alg;

			return *this;
		}

		~cng_alg(){
			release_();
		}

		BCRYPT_ALG_HANDLE to_handle()const{
			return m_alg;
		}

		static cng_alg create(LPCWSTR const alg_id, LPCWSTR const implementation = 0, DWORD const flags = 0){
			
			BCRYPT_ALG_HANDLE alg_handle;

			auto const status = BCryptOpenAlgorithmProvider(&alg_handle, alg_id, implementation, flags);
			if(! NT_SUCCESS(status) ){
				STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(status) );
			} else {
				return cng_alg(alg_handle);
			}
				
		}


		cng_key	generate_key_pair(ULONG const dwLength,  ULONG const dwFlags=0){
			assert(m_alg);
			BCRYPT_KEY_HANDLE key=0;

			auto const status = BCryptGenerateKeyPair(m_alg, &key, dwLength,dwFlags);

			if(! NT_SUCCESS(status) ){
				STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(status) );
			} else {
				return cng_key(key);
			}

		}


		cng_key import_key_pair(LPCWSTR  const blob_type, BYTE const*const blob, ULONG const blob_size, ULONG flags = 0)const{
			assert(m_alg);
			BCRYPT_KEY_HANDLE key=0;

			auto const status = BCryptImportKeyPair(m_alg, 0, blob_type, &key, const_cast<BYTE*>(blob), blob_size, flags);

			if(! NT_SUCCESS(status) ){
				STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(status) );
			} else {
				return cng_key(key);
			}
		}

	private:
		explicit cng_alg(cng_alg const& other);
		cng_alg& operator=(cng_alg const& other);

		void release_(){
			if( m_alg ) {
				auto const r = BCryptCloseAlgorithmProvider(m_alg,0);
				assert(NT_SUCCESS(r)); (void)r;
			}
		}

		BCRYPT_ALG_HANDLE m_alg;
	};
}
//================================================================================================================================================
#endif
//================================================================================================================================================
