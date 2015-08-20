//================================================================================================================================================
// FILE: stcrypt-cryptoapi-csp-wrap.cpp
// (c) GIE 2010-04-29  15:25
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cryptoapi-csp-wrap.hpp"

#include "boost/scope_exit.hpp"
//================================================================================================================================================
namespace stcrypt {

	void capi_csp_hash_wrap_t::check_(){
		if(!m_prov || m_hash==0){
			STCRYPT_UNEXPECTED();
		}
	}


	capi_csp_hash_wrap_t::capi_csp_hash_wrap_t(cryptprov_ptr_t  const& prov,  HCRYPTHASH const hash)
		: m_prov(prov)
		, m_hash( hash )
	{

	}


	void capi_csp_hash_wrap_t::set_param(DWORD const param, BYTE const * const data){
		check_();

		STCRYPT_CHECK_MSCRYPTO( CryptSetHashParam(m_hash, param, data, 0) );
	}
	void capi_csp_hash_wrap_t::get_param(DWORD const param, BYTE* const data, DWORD * const datalen){
		check_();

		STCRYPT_CHECK_MSCRYPTO( CryptGetHashParam(m_hash, param, data, datalen, 0) );
	}


	capi_csp_hash_wrap_t::~capi_csp_hash_wrap_t(){
		if( m_hash ){
			BOOL const r = CryptDestroyHash(m_hash);
			assert(r);
		}
	}

	void capi_csp_hash_wrap_t::hash_data(BYTE const * const data, size_t const len){
		check_();

		STCRYPT_CHECK_MSCRYPTO( CryptHashData(m_hash,data,len,0) );
	}

	DWORD capi_csp_hash_wrap_t::get_alg_id(){
		ALG_ID data;
		DWORD data_len = sizeof(data);
		STCRYPT_CHECK_MSCRYPTO( CryptGetHashParam(m_hash,HP_ALGID, reinterpret_cast<BYTE*>( &data ), &data_len, 0) );

		return data;
	}

	DWORD capi_csp_hash_wrap_t::get_hash_size(){
		DWORD data;
		DWORD data_len = sizeof(data);
		STCRYPT_CHECK_MSCRYPTO( CryptGetHashParam(m_hash,HP_HASHSIZE, reinterpret_cast<BYTE*>( &data ), &data_len, 0) );

		return data;
	}


	void  capi_csp_hash_wrap_t::get_hash_value(BYTE* const data, DWORD const datalen){
		DWORD data_len = datalen;

		STCRYPT_CHECK_MSCRYPTO( CryptGetHashParam(m_hash,HP_HASHVAL, data, &data_len, 0) ) ;
	}
	void  capi_csp_hash_wrap_t::set_hash_value(BYTE const * const data){
		STCRYPT_UNEXPECTED();
	}
	boost::intrusive_ptr<hash_impl_base_t> capi_csp_hash_wrap_t::create_new(){
		STCRYPT_UNEXPECTED();
	}
	boost::intrusive_ptr<hash_impl_base_t> capi_csp_hash_wrap_t::clone(){
		STCRYPT_UNEXPECTED();
	}

	capi_csp_hash_wrap_ptr_t create_sha1_hash(cryptprov_ptr_t const& prov){
		HCRYPTHASH hash = 0;
		STCRYPT_CHECK_MSCRYPTO( CryptCreateHash(*prov, CALG_SHA1, 0, 0, &hash) );

		BOOST_SCOPE_EXIT( (&hash) ){
			if(hash) {
				BOOL const r = CryptDestroyHash(hash);
				assert(r);
			}
		}BOOST_SCOPE_EXIT_END;

		capi_csp_hash_wrap_ptr_t tmp ( new capi_csp_hash_wrap_t(prov, hash)  );
		hash = 0;

		return tmp;
	}


}
//================================================================================================================================================
