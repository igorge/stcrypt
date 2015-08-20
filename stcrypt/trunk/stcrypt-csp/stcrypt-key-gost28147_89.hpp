//================================================================================================================================================
// FILE: stcrypt-key.h
// (c) GIE 2009-11-06  13:59
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_KEY_2009_11_06_13_59
#define H_GUARD_STCRYPT_KEY_2009_11_06_13_59
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-hash-base.hpp"
#include "stcrypt-key-blob.hpp"
#include "stcrypt-key-base.hpp"
#include "stcrypt-crypto-alg-ids.h"
#include "stcrypt-debug.hpp"
#include "CryptoLibTypes.h"

#include "boost/optional.hpp"
#include <wincrypt.h>

#include <vector>
//================================================================================================================================================
namespace stcrypt {

	struct csp_t;
	struct gost28147_89_simple_cipher_t;
	struct gost28147_89_gamma_cipher_t;
	struct gost28147_89_cipher_base_t;

	struct gost28147_89_simple_cipher_info_block_t;
	struct gost28147_89_gamma_cipher_info_block_t;
	struct gost28147_89_gamma_cbc_cipher_info_block_t;


	/*
	 *
	 *  
	 */
	struct gost28147_89_family_key_t 
		: cryptoapi_key_base_t
	{

		typedef cryptoapi_key_blob_t key_blob_type;

		gost28147_89_family_key_t(csp_t * const csp, ALG_ID const alg_id)
			: cryptoapi_key_base_t(csp)
			, m_alg_id(alg_id)
			, m_op_mode(op_none)
		{
			assert(m_alg_id==CALG_ID_G28147_89_SIMPLE || m_alg_id==CALG_ID_G28147_89_GAMMA || m_alg_id==CALG_ID_G28147_89_GAMMA_CBC);
		}
		gost28147_89_family_key_t(csp_t * const csp,  ALG_ID const alg_id,  BYTE const * const blob_data, size_t const blob_size, key_op::load_from_blob const&);
		explicit gost28147_89_family_key_t(gost28147_89_family_key_t const& other);

		virtual void set_iv(BYTE const*const iv);

		virtual DWORD get_blocklen();
		virtual ALG_ID get_alg_id()const{ return m_alg_id; }

		virtual void export_key_blob(std::vector<BYTE>& key_blob);

		virtual size_t key_blob_size();

		key_blob_type const& get_key_data()const{ return m_key; }

	protected:
		template <class ThisType>
		static
			boost::intrusive_ptr<ThisType> do_clone_(ThisType * const orig){
				assert(orig);
				boost::intrusive_ptr<ThisType> clone (new ThisType(*orig, key_op::init_from_other()) );
				assert( typeid(*orig)==typeid(*clone.get()) );
				return clone;
		}


	STCRYPT_PROTECTED:
		virtual symmetric_block_cipher_info_block_i* get_cipher_info_block_()=0;
		virtual size_t invoke_cipher_encrypt(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);
		virtual size_t invoke_cipher_decrypt(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);

	STCRYPT_PROTECTED:
		virtual size_t invoke_cipher_encrypt_(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);
		virtual size_t invoke_cipher_decrypt_(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);

		//! \note Returned generated key material may be larger than requested.
		static void derive_key_material_from_hash_(size_t const required_key_material_size, std::vector<BYTE> & key_material, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key);
		static size_t copy_data_from_hash_to_key_material_(std::vector<BYTE>& hash_data, boost::intrusive_ptr<hash_impl_base_t> const& hash, std::vector<BYTE>& key_material);
	STCRYPT_PROTECTED:
		key_blob_type	m_key;
		symmetric_block_cipher_base_ptr m_cipher;
	private:
		ALG_ID const m_alg_id;
		op_mode_type m_op_mode;
	};



	/*
	 *
	 *
	 */
	template <
		class base_tt, 
		class info_block_tt> 
	struct gost28147_89_family_key_mixin {
	protected:
		symmetric_block_cipher_info_block_i* get_cipher_info_block__() {
			if( !m_cipher_info_block ) {
				m_cipher_info_block.reset( new info_block_tt( this->get_self_() ) );
			}

			return m_cipher_info_block.get();
		}
		~gost28147_89_family_key_mixin(){
			if(m_cipher_info_block)
				m_cipher_info_block->reset_parent();
		}
	protected:
		boost::intrusive_ptr<info_block_tt>		   m_cipher_info_block;
	private:
		base_tt * get_self_()throw(){ return static_cast<base_tt*>(this); }
	};


	/*
	 *
	 *
	 */
	struct gost28147_89_simple_key_t 
		: boost::noncopyable
		, gost28147_89_family_key_t
		, protected  gost28147_89_family_key_mixin<gost28147_89_simple_key_t, gost28147_89_simple_cipher_info_block_t>
	{

		explicit gost28147_89_simple_key_t(csp_t * const csp, key_op::generate const&);
		explicit gost28147_89_simple_key_t(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size, key_op::load_from_blob const&);
		explicit gost28147_89_simple_key_t(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key, key_op::derive const&);
		~gost28147_89_simple_key_t();

		gost28147_89_simple_key_t(gost28147_89_simple_key_t const& other, key_op::init_from_other const&);


		virtual boost::intrusive_ptr<cryptoapi_key_base_t> clone();


 	protected:
		virtual symmetric_block_cipher_info_block_i* get_cipher_info_block_();
	//private:
	//	boost::intrusive_ptr<gost28147_89_simple_cipher_t> m_cipher;
	};

	/*
	 *
	 *
	 */
	struct gost28147_89_gamma_key_t 
		: boost::noncopyable
		, gost28147_89_family_key_t 
		, protected gost28147_89_family_key_mixin<gost28147_89_gamma_key_t, gost28147_89_gamma_cipher_info_block_t>
	{

		explicit gost28147_89_gamma_key_t(csp_t * const csp, key_op::generate const&);
		explicit gost28147_89_gamma_key_t(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size, key_op::load_from_blob const&);
		explicit gost28147_89_gamma_key_t(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key, key_op::derive const&);
		~gost28147_89_gamma_key_t();
		gost28147_89_gamma_key_t(gost28147_89_gamma_key_t const& other, key_op::init_from_other const&);

		virtual boost::intrusive_ptr<cryptoapi_key_base_t> clone();


 	protected:
 		virtual symmetric_block_cipher_info_block_i* get_cipher_info_block_();
	//private:
	//	boost::intrusive_ptr<gost28147_89_gamma_cipher_t> m_cipher;
	};


	/*
	 *
	 *
	 */
	struct gost28147_89_gamma_cbc_key_t 
		: boost::noncopyable
		, gost28147_89_family_key_t 
		, protected gost28147_89_family_key_mixin<gost28147_89_gamma_cbc_key_t, gost28147_89_gamma_cbc_cipher_info_block_t>
	{

		explicit gost28147_89_gamma_cbc_key_t(csp_t * const csp, key_op::generate const&);
		explicit gost28147_89_gamma_cbc_key_t(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size, key_op::load_from_blob const&);
		explicit gost28147_89_gamma_cbc_key_t(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key, key_op::derive const&);
		~gost28147_89_gamma_cbc_key_t();
		explicit gost28147_89_gamma_cbc_key_t(gost28147_89_gamma_cbc_key_t const& other, key_op::init_from_other const&);

		virtual boost::intrusive_ptr<cryptoapi_key_base_t> clone();

	protected:
		virtual symmetric_block_cipher_info_block_i* get_cipher_info_block_();
	//private:
	//	boost::intrusive_ptr<gost28147_89_gamma_cipher_t> m_cipher;
	};



}
//================================================================================================================================================
#endif
//================================================================================================================================================
