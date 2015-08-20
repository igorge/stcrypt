//================================================================================================================================================
// FILE: stcrypt-cryptoapi-csp-wrap.h
// (c) GIE 2010-04-29  15:25
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CRYPTOAPI_CSP_WRAP_2010_04_29_15_25
#define H_GUARD_STCRYPT_CRYPTOAPI_CSP_WRAP_2010_04_29_15_25
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-hash-base.hpp"
#include "stcrypt-exceptions.hpp"
#include "util-raii-helpers-crypt.hpp"

#include "boost/intrusive_ptr.hpp"
//================================================================================================================================================
namespace stcrypt {

	struct capi_csp_hash_wrap_t
		: stcrypt::hash_impl_base_t
	{
		capi_csp_hash_wrap_t(cryptprov_ptr_t const& prov, HCRYPTHASH const hash);
		~capi_csp_hash_wrap_t();

		virtual void set_param(DWORD const param, BYTE const * const data);
		virtual void get_param(DWORD const param, BYTE* const data, DWORD * const datalen);

		virtual void hash_data(BYTE const * const data, size_t const len);
		virtual DWORD get_alg_id();
		virtual DWORD get_hash_size();
		virtual void  get_hash_value(BYTE* const data, DWORD const datalen);
		virtual void  set_hash_value(BYTE const * const data);
		virtual boost::intrusive_ptr<hash_impl_base_t> create_new();
		virtual boost::intrusive_ptr<hash_impl_base_t> clone();

		private:
			void check_();

		private:
			cryptprov_ptr_t const m_prov;
			HCRYPTHASH			  m_hash;
	};

	typedef boost::intrusive_ptr<stcrypt::capi_csp_hash_wrap_t> capi_csp_hash_wrap_ptr_t;
	capi_csp_hash_wrap_ptr_t create_sha1_hash(cryptprov_ptr_t const& prov);

}
//================================================================================================================================================
#endif
//================================================================================================================================================
