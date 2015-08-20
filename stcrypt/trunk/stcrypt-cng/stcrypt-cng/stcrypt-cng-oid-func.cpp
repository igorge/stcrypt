//================================================================================================================================================
// FILE: stcrypt-cng-oid-func.cpp
// (c) GIE 2010-09-13  16:39
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-oid-func.hpp"
//================================================================================================================================================

#include "stcrypt-debug.hpp"
#include "stcrypt-exceptions.hpp"
#include "util-cng-wrap.hpp"
#include "stcrypt-crypto-alg-ids.h"
#include "stcrypt-cng-oid-exceptions.hpp"
#include "stcrypt-cng-oid-encdec.hpp"
#include "util-sio-cng.hpp"
#include "util-cng-wrap.hpp"

#include <boost/scope_exit.hpp>
#include <boost/range.hpp>
//================================================================================================================================================
namespace stcrypt{

	// CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC
	// PFN_CRYPT_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC
	void cng_export_public_key_info(
		NCRYPT_KEY_HANDLE hNCryptKey, 
		DWORD dwCertEncodingType, 
		LPSTR pszPublicKeyObjId, 
		DWORD dwFlags, 
		void *pvAuxInfo, 
		PCERT_PUBLIC_KEY_INFO pInfo, 
		DWORD *pcbInfo){
			assert(pcbInfo);

			typedef n_key_func_wrap_t cng_w;


			auto const& n_key_blob = cng_w::export_key_blob( hNCryptKey, BCRYPT_PUBLIC_KEY_BLOB);
			auto const n_key_blob_size = n_key_blob.size();

			cng_blob_info_t const obj_blob_header = {-1, n_key_blob.data(), n_key_blob.size() };
			DWORD ret_size=0;
			if( !CryptEncodeObjectEx(dwCertEncodingType, pszPublicKeyObjId, &obj_blob_header, 0, 0, 0, &ret_size) ){
				auto const err_code = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::encode_object() << exception::getlasterror_einfo(err_code) );
			}
			
			size_t const asn_encoded_size = ret_size;
			auto const cert_pub_key_info_size = sizeof(CERT_PUBLIC_KEY_INFO) + asn_encoded_size;// n_key_blob_size;

			if( pInfo ) {

				if( *pcbInfo < cert_pub_key_info_size ) STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair(*pcbInfo, cert_pub_key_info_size) ) );

				auto const pInfo_as_byte = reinterpret_cast<BYTE*>( pInfo );
				memset(pInfo_as_byte, 0, *pcbInfo);

				auto const key_blob_start = pInfo_as_byte+sizeof(CERT_PUBLIC_KEY_INFO);
				auto const key_blob_have_buffer_size = cert_pub_key_info_size - sizeof(CERT_PUBLIC_KEY_INFO);


				pInfo->Algorithm.pszObjId = OID_DSTU4145_PUBKEY;
				pInfo->Algorithm.Parameters.cbData = 0;
				pInfo->Algorithm.Parameters.pbData = 0;

				pInfo->PublicKey.cUnusedBits = 0;
				pInfo->PublicKey.cbData = asn_encoded_size;
				pInfo->PublicKey.pbData = key_blob_start;

				ret_size = pInfo->PublicKey.cbData;
				if( !CryptEncodeObjectEx(dwCertEncodingType, pszPublicKeyObjId, &obj_blob_header, 0, 0, key_blob_start, &ret_size) ){
					auto const err_code = GetLastError();
					STCRYPT_THROW_EXCEPTION( exception::encode_object() << exception::getlasterror_einfo(err_code) );
				}

			}

			*pcbInfo = cert_pub_key_info_size;
	}

	namespace {


		void * WINAPI encdec_self_crt_alloc_func(size_t size){
			return new (std::nothrow) unsigned char[size];
		}

		void WINAPI encdec_self_crt_free_func(void * m){
			delete[] static_cast<unsigned char*>(m);
		}

	} // end anon ns



	BCRYPT_KEY_HANDLE cng_import_public_key_info(
		DWORD const dwCertEncodingType,
		PCERT_PUBLIC_KEY_INFO const pInfo,
		DWORD const dwFlags)
	{
		assert(pInfo);
		assert(pInfo->Algorithm.pszObjId);
		assert(pInfo->PublicKey.pbData);

		if(pInfo->PublicKey.cUnusedBits!=0) STCRYPT_UNEXPECTED();



		DWORD size = 0;

		CRYPT_DECODE_PARA const alloc_free = {sizeof(alloc_free), encdec_self_crt_alloc_func, encdec_self_crt_free_func};
		cng_blob_info_t * blob_info = 0;
		BOOST_SCOPE_EXIT( (&blob_info) ) { encdec_self_crt_free_func( blob_info ); } BOOST_SCOPE_EXIT_END;
		
		if( !CryptDecodeObjectEx(dwCertEncodingType, pInfo->Algorithm.pszObjId, pInfo->PublicKey.pbData, pInfo->PublicKey.cbData, CRYPT_DECODE_ALLOC_FLAG, const_cast<PCRYPT_DECODE_PARA>( &alloc_free ), &blob_info, &size) ){
			auto const err_code = GetLastError();
			STCRYPT_THROW_EXCEPTION( exception::decode_object() << exception::getlasterror_einfo(err_code) );
		}

		if( blob_info->m_type!=-1 ) STCRYPT_UNEXPECTED();

		BCRYPT_KEY_BLOB blob_header;
		auto input_range = boost::make_iterator_range(blob_info->m_blob, blob_info->m_blob + blob_info->m_blob_size);


		sio::read<decltype(blob_header)>::apply(blob_header, input_range) ;

		if( blob_header.Magic == CNG_DSTU4145_BLOB_MAGIC_PUBLIC ){

			auto const alg_class = cng_alg::create(CNG_DSTU4145);

			return alg_class.import_key_pair( BCRYPT_PUBLIC_KEY_BLOB,  blob_info->m_blob, blob_info->m_blob_size).release();
		} else {
			STCRYPT_THROW_EXCEPTION( exception::invalid_blob_type() );
		}
	}





	void cng_sign_and_encode_hash(
		NCRYPT_KEY_HANDLE const hKey, 
		DWORD const dwCertEncodingType, 
		PCRYPT_ALGORITHM_IDENTIFIER const pSignatureAlgorithm,
		void *const pvDecodedSignPara,
		LPCWSTR const pwszCNGPubKeyAlgid,
		LPCWSTR const pwszCNGHashAlgid,
		BYTE *const pbComputedHash,
		DWORD const cbComputedHash,
		BYTE *const pbSignature,
		DWORD *const pcbSignature
		){
			typedef n_key_func_wrap_t cng_w;

			assert(hKey);
			assert(pSignatureAlgorithm);
			assert(pwszCNGHashAlgid);
			assert(pwszCNGPubKeyAlgid);
			assert(pcbSignature);

			auto const size_of_signature = cng_w::signature_size(hKey, 0, pbComputedHash, cbComputedHash );

			std::vector<unsigned char> signature_data( size_of_signature ); // TODO: replace with stack based optimized vector like class

			unsigned char * const sign  = signature_data.data();
			if( !sign ) STCRYPT_UNEXPECTED();

			cng_blob_info_t const obj_blob_header = {-1, sign, size_of_signature };
			DWORD ret_size=0;
			if( !CryptEncodeObjectEx(dwCertEncodingType, pSignatureAlgorithm->pszObjId, &obj_blob_header, 0, 0, 0, &ret_size) ){
				auto const err_code = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::encode_object() << exception::getlasterror_einfo(err_code) );
			}

			size_t const asn_encoded_size_of_signature = ret_size;

			if(!pbSignature) {

				*pcbSignature = asn_encoded_size_of_signature;

			} else {

				if( *pcbSignature < asn_encoded_size_of_signature ) STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair( *pcbSignature, asn_encoded_size_of_signature ) ) );
				auto const new_size_of_signature = cng_w::sign_hash(hKey, 0, pbComputedHash, cbComputedHash, sign, size_of_signature);
				if(size_of_signature!=new_size_of_signature) STCRYPT_UNEXPECTED();

				if( !CryptEncodeObjectEx(dwCertEncodingType, pSignatureAlgorithm->pszObjId, &obj_blob_header, 0, 0, pbSignature, pcbSignature) ){
					auto const err_code = GetLastError();
					STCRYPT_THROW_EXCEPTION( exception::encode_object() << exception::getlasterror_einfo(err_code) );
				}

				if(*pcbSignature!=asn_encoded_size_of_signature){ 
					*pcbSignature=asn_encoded_size_of_signature;
				}

			}
	}





	bool verify_encoded_signature(
		DWORD const dwCertEncodingType,
		PCERT_PUBLIC_KEY_INFO const pPubKeyInfo,
		PCRYPT_ALGORITHM_IDENTIFIER const pSignatureAlgorithm,
		void * const pvDecodedSignPara,
		LPCWSTR const pwszCNGPubKeyAlgid,
		LPCWSTR const pwszCNGHashAlgid,
		BYTE * const pbComputedHash,
		DWORD const cbComputedHash,
		BYTE * const pbSignature,
		DWORD const cbSignature
		)
	{
		assert(pPubKeyInfo);
		assert(pSignatureAlgorithm);
		assert(pSignatureAlgorithm->pszObjId);
		assert(pwszCNGPubKeyAlgid);
		assert(pwszCNGHashAlgid);
		assert(pbComputedHash);
		assert(pbSignature);


		DWORD size = 0;

		CRYPT_DECODE_PARA const alloc_free = {sizeof(alloc_free), encdec_self_crt_alloc_func, encdec_self_crt_free_func};
		cng_blob_info_t * blob_info = 0;
		BOOST_SCOPE_EXIT( (&blob_info) ) { encdec_self_crt_free_func( blob_info ); } BOOST_SCOPE_EXIT_END;

		if( !CryptDecodeObjectEx(dwCertEncodingType, pSignatureAlgorithm->pszObjId, pbSignature, cbSignature, CRYPT_DECODE_ALLOC_FLAG, const_cast<PCRYPT_DECODE_PARA>( &alloc_free ), &blob_info, &size) ){
			auto const err_code = GetLastError();
			STCRYPT_THROW_EXCEPTION( exception::decode_object() << exception::getlasterror_einfo(err_code) );
		}


		return cng_key ( cng_import_public_key_info(dwCertEncodingType, pPubKeyInfo, 0) ).verify_signature( 0, pbComputedHash, cbComputedHash, const_cast<PUCHAR>( blob_info->m_blob ), blob_info->m_blob_size, 0);
	}





} // end of stcrypt ns


BOOL WINAPI STCRYPT_ExportPublicKeyInfoEx2 (
	__in NCRYPT_KEY_HANDLE hNCryptKey,
	__in DWORD dwCertEncodingType,
	__in LPSTR pszPublicKeyObjId,
	__in DWORD dwFlags,
	__in_opt void *pvAuxInfo,
	__out_bcount_part_opt(*pcbInfo, *pcbInfo) PCERT_PUBLIC_KEY_INFO pInfo,
	__inout DWORD *pcbInfo
	)
{
		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		if( !hNCryptKey ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter_handle() );
		if( !pcbInfo ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );

		stcrypt::cng_export_public_key_info(hNCryptKey, dwCertEncodingType, pszPublicKeyObjId, dwFlags, pvAuxInfo, pInfo, pcbInfo);

		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_END

}


BOOL WINAPI STCRYPT_SignAndEncodeHash(
	__in     NCRYPT_KEY_HANDLE hKey,
	__in     DWORD dwCertEncodingType,
	__in     PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
	__in     void *pvDecodedSignPara,
	__in     LPCWSTR pwszCNGPubKeyAlgid,
	__in     LPCWSTR pwszCNGHashAlgid,
	__in     BYTE *pbComputedHash,
	__in     DWORD cbComputedHash,
	__out    BYTE *pbSignature,
	__inout  DWORD *pcbSignature
	)
{
		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		if( !hKey ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter_handle() );
		if( !pcbSignature ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pwszCNGPubKeyAlgid ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pwszCNGHashAlgid ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pcbSignature ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );

		stcrypt::cng_sign_and_encode_hash(hKey, dwCertEncodingType, pSignatureAlgorithm, pvDecodedSignPara, pwszCNGPubKeyAlgid, pwszCNGHashAlgid, pbComputedHash, cbComputedHash, pbSignature, pcbSignature);

		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_END

}


BOOL WINAPI STCRYPT_VerifyEncodedSignature(
	__in      DWORD dwCertEncodingType,
	__in      PCERT_PUBLIC_KEY_INFO pPubKeyInfo,
	__in      PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
	__in_opt  void *pvDecodedSignPara,
	__in      LPCWSTR pwszCNGPubKeyAlgid,
	__in      LPCWSTR pwszCNGHashAlgid,
	__in      BYTE *pbComputedHash,
	__in      DWORD cbComputedHash,
	__in      BYTE *pbSignature,
	__in      DWORD cbSignature
	)
{
		// If this callback function does not support the signature algorithm, it must return FALSE and call SetLastError with ERROR_NOT_SUPPORTED. 
		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		if( !pPubKeyInfo ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter_handle() );
		if( !pSignatureAlgorithm ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter_handle() );
		if( !pwszCNGPubKeyAlgid ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pwszCNGHashAlgid ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pbComputedHash ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pbSignature ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );

		if( !stcrypt::verify_encoded_signature( dwCertEncodingType, pPubKeyInfo, pSignatureAlgorithm, pvDecodedSignPara, pwszCNGPubKeyAlgid, pwszCNGHashAlgid, pbComputedHash, cbComputedHash, pbSignature, cbSignature) ){
			STCRYPT_THROW_EXCEPTION( stcrypt::exception::signature_verification_failed() );
		}

		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_END
}


//PFN_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC
BOOL WINAPI STCRYPT_ImportPublicKeyInfoEx2(
	__in   DWORD dwCertEncodingType,
	__in   PCERT_PUBLIC_KEY_INFO pInfo,
	__in   DWORD dwFlags,
	__in   void *pvAuxInfo,
	__out  BCRYPT_KEY_HANDLE *phKey
	)
{
		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		if( !phKey ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pInfo ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pInfo->PublicKey.pbData ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pInfo->Algorithm.pszObjId) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );

		*phKey = stcrypt::cng_import_public_key_info(dwCertEncodingType, pInfo, dwFlags);

		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_END
}

template <unsigned int id>
BOOL STCRYPT_CatchAllDummy(){
	try{
		CSP_LOG_TRACE

		STCRYPT_LOG_W_STRING(L":::::::::::::::::::::::::::::: CATCH ALL DUMMY ::::::::::::::::::::::::::::::::");

		
	}catch(...){

	}

	abort(); // stack is toasted anyway

	return FALSE;

}


BOOL WINAPI STCRYPT_CatchAllDummy(){
	return STCRYPT_CatchAllDummy<0>();
}

#include <boost/preprocessor/cat.hpp>

#define STCRYPT_DECLARE_DUMMY(id) BOOL WINAPI BOOST_PP_CAT(STCRYPT_CatchAllDummy,id)(){ return STCRYPT_CatchAllDummy<id>(); }

STCRYPT_DECLARE_DUMMY(1);
STCRYPT_DECLARE_DUMMY(2);
STCRYPT_DECLARE_DUMMY(3);
STCRYPT_DECLARE_DUMMY(4);
STCRYPT_DECLARE_DUMMY(5);
STCRYPT_DECLARE_DUMMY(6);
STCRYPT_DECLARE_DUMMY(7);

//================================================================================================================================================
