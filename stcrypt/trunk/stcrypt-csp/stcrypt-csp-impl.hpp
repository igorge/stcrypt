//================================================================================================================================================
// FILE: stcrypt-csp-impl.h
// (c) GIE 2009-11-02  15:49
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CSP_IMPL_2009_11_02_15_49
#define H_GUARD_STCRYPT_CSP_IMPL_2009_11_02_15_49
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-dstu4145-random.hpp"
#include "stcrypt-key-factory.hpp"
#include "stcrypt-key-base.hpp"
#include "utll-capi-get-param-enums-impl.hpp"
#include "stcrypt-debug.hpp"
#include "stcrypt-crypto-alg-ids.h"
#include "stcrypt-key-storage.hpp"
#include "stcrypt-exceptions.hpp"
#include "util-raii-helpers.hpp"
#include "util-atomic-counter.hpp"
#include "stcrypt-cryptolib.hpp"

#include "boost/intrusive_ptr.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/noncopyable.hpp"
#include "boost/filesystem.hpp"
#include "boost/optional.hpp"

#include <WinCrypt.h>
//================================================================================================================================================
namespace stcrypt {

	struct hash_impl_base_t;

	//prototype for MAC creation function
	boost::intrusive_ptr<hash_impl_base_t> create_gost_28147_mac(key_base_ptr const& key);

	struct csp_t 
		: atomic_counter_impl_t
		, boost::noncopyable
		, get_param_enums_impl_t<csp_t, PROV_ENUMALGS const*, PROV_ENUMALGS const*>
		, get_param_enums_impl_t<csp_t, PROV_ENUMALGS_EX const*, PROV_ENUMALGS_EX const*>
	{
		refcnt add_ref() { return ccom_internal_inc_ref_(); }		
		refcnt dec_ref() { return ccom_internal_dec_ref_(); }

		typedef get_param_enums_impl_t<csp_t, PROV_ENUMALGS const*, PROV_ENUMALGS const*> enum_algs_impl_type;
		typedef get_param_enums_impl_t<csp_t, PROV_ENUMALGS_EX const*, PROV_ENUMALGS_EX const*> enum_algs_ex_impl_type;

		friend enum_algs_impl_type;
		friend enum_algs_ex_impl_type;

		static DWORD const provider_type = STCRYPT_PROVIDER_TYPE;

		boost::intrusive_ptr<hash_impl_base_t> create_hash(ALG_ID const alg_id, key_base_ptr const& key);
		key_base_ptr	gen_key(ALG_ID const alg_id, DWORD const flags){ STCRYPT_UNIMPLEMENTED(); }
		key_base_ptr	derive_key(ALG_ID const alg_id, DWORD const flags, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key);
		key_base_ptr	generate_key(ALG_ID const alg_id, DWORD const flags);
		key_base_ptr	get_key(DWORD const dwKeySpec);
		key_base_ptr	get_user_key(DWORD const dwKeySpec);

		void set_param(DWORD const params, BYTE const * const data, DWORD const flags);
		void get_param(DWORD const param, BYTE* const data, DWORD * const datalen, DWORD const flags);

		void sign_hash(boost::intrusive_ptr<hash_impl_base_t> const& hash, DWORD const dwKeySpec, LPBYTE const pbSignature, LPDWORD pcbSigLen);
		void verify_hash(boost::intrusive_ptr<hash_impl_base_t> const& hash, key_base_ptr const& key, BYTE const * const pbSignature, DWORD const cbSigLen);
		void hash_key(boost::intrusive_ptr<hash_impl_base_t> const& hash, key_base_ptr const& key);

		void export_key(key_base_ptr const& key,key_base_ptr const& pub_key,DWORD const dwBlobType,DWORD const dwFlags,LPBYTE const pbData,LPDWORD const pcbDataLen);
		key_base_ptr import_key(key_base_ptr const& pub_key,DWORD const dwFlags,BYTE const * const pbData,DWORD const DataLen);



		void gen_random(BYTE * buffer, size_t const buffer_size);

		bool is_verify_context()const throw() {
			return m_is_verifycontext;
		}

		csp_t(key_storage_base_ptr const& key_storage, bool const is_verifycontext);
		~csp_t()
		{
			STCRYPT_TRACE_CALL
		}

		boost::weak_ptr<csp_t> get_weak_ptr();

	private:

		//////////////////////////////////////////////////////////////////////////
		// enum_algs_impl_type
		std::pair<enum_algs_impl_type::iterator_type,enum_algs_impl_type::iterator_type> 
			init_iters_(enum_algs_impl_type::tag_type const);
		void from_iter_to_item_(enum_algs_impl_type::tag_type const, enum_algs_impl_type::iterator_type& iter, enum_algs_impl_type::item_type& item);
		void copy_func_(enum_algs_impl_type::tag_type const, enum_algs_impl_type::item_type const& item, BYTE* const data, DWORD const datalen);
		size_t item_size_(enum_algs_impl_type::tag_type const, enum_algs_impl_type::item_type const& item)const;

		//////////////////////////////////////////////////////////////////////////
		// enum_algs_ex_impl_type
		std::pair<enum_algs_ex_impl_type::iterator_type,enum_algs_ex_impl_type::iterator_type> 
			init_iters_(enum_algs_ex_impl_type::tag_type const);
		void from_iter_to_item_(enum_algs_ex_impl_type::tag_type const, enum_algs_ex_impl_type::iterator_type& iter, enum_algs_ex_impl_type::item_type& item);
		void copy_func_(enum_algs_ex_impl_type::tag_type const, enum_algs_ex_impl_type::item_type const& item, BYTE* const data, DWORD const datalen);
		size_t item_size_(enum_algs_ex_impl_type::tag_type const, enum_algs_ex_impl_type::item_type const& item)const;
	private:

		enum_algs_impl_type* get_algs_enum() {
			return static_cast<enum_algs_impl_type*>( this );
		}
		
		enum_algs_ex_impl_type* get_algs_ex_enum() {
			return static_cast<enum_algs_ex_impl_type*>( this );
		}

		void check_null_flags_(DWORD const flags){
			if( flags!=0 ) {STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() << exception::flags_einfo(flags) );}
		}

		key_base_ptr generate_AT_KEYEXCHANGE_();
		key_base_ptr generate_AT_SIGNATURE_();

		void get_param__container_name_(BYTE* const data, DWORD * const datalen);
		void get_param__name_(BYTE* const data, DWORD * const datalen);
		void get_param__imp_type_(BYTE* const data, DWORD * const datalen);
		void get_param__prov_type_(BYTE* const data, DWORD * const datalen);
		void get_param__version_(BYTE* const data, DWORD * const datalen);
		void get_param__enum_containers_(BYTE* const data, DWORD * const datalen, DWORD const flags);
		void get_param__enum_algs_(BYTE* const data, DWORD * const datalen, DWORD const flags);
		void get_param__enum_algs_ex_(BYTE* const data, DWORD * const datalen, DWORD const flags);
	STCRYPT_PRIVATE:
		boost::intrusive_ptr<hash_impl_base_t> create_hash_gost_34311();
	private:
		boost::optional<dstu4145_random_t> m_generator;
		boost::shared_ptr<csp_t> m_this_for_weak_ptr;

		key_base_ptr m_key_keyx;
		key_base_ptr m_key_sign;
	private:
		bool m_is_verifycontext;
		key_storage_base_ptr	m_keystorage;
		key_storage_manager_base_ptr key_storage_manager_(){
			return m_keystorage->get_manager();
		}
	};
//================================================================================================================================================
	inline void intrusive_ptr_add_ref(csp_t * const p)
	{
		p->add_ref();
	}
	inline void intrusive_ptr_release(csp_t * const p)throw()
	{
		if( p->dec_ref() ==0 ) delete p;
	}
//================================================================================================================================================
}
//================================================================================================================================================
#endif
//================================================================================================================================================
