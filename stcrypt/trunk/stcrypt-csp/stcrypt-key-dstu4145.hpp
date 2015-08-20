//================================================================================================================================================
// FILE: stcrypt-key-dstu4145.h
// (c) GIE 2010-01-05  18:01
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_KEY_DSTU4145_2010_01_05_18_01
#define H_GUARD_STCRYPT_KEY_DSTU4145_2010_01_05_18_01
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-asymmetric-base.hpp"
#include "stcrypt-key-base.hpp"
#include "stcrypt-cryptolib.hpp"
#include "stcrypt-debug.hpp"

#include "boost/optional.hpp"
#include "boost/utility/in_place_factory.hpp"
//================================================================================================================================================
namespace stcrypt {

	struct csp_t;

	struct dstu_4145_key_t {

		typedef TGFELEMENT private_part_type;
		typedef TECPOINT public_part_type;

		unsigned int	m_std_mode;
		boost::optional<private_part_type>  m_private_part; //d
		public_part_type					m_public_part; //Q

		dstu_4145_key_t(){}

		dstu_4145_key_t(dstu_4145_key_t const& other)
			: m_std_mode (other.m_std_mode)
		{
			if(other.m_private_part){
				m_private_part = boost::in_place();				
				#ifdef STCRYPT_DEBUG
					private_part_type const * const other_priv_key = &(*other.m_private_part);
					private_part_type const * const this_priv_key = &(*m_private_part);
				#endif
				memcpy_s(&(*m_private_part), sizeof(private_part_type), &(*other.m_private_part), sizeof(private_part_type));
				#ifdef STCRYPT_DEBUG
					int dummy00=0;
				#endif
			} else {
				m_private_part.reset();
			}

			#ifdef STCRYPT_DEBUG
				public_part_type const * const other_pub_key = &other.m_public_part;
				public_part_type const * const this_pub_key = &m_public_part;
			#endif
			memcpy_s(&m_public_part, sizeof(public_part_type), &other.m_public_part, sizeof(public_part_type));

		}

		void to_blob(std::vector<BYTE>& out_cont);
		void public_part_to_blob(std::vector<BYTE>& out_cont);
		size_t public_part_blob_size();
		void from_blob(BYTE const* const key_blob, size_t const key_blob_size);
		size_t blob_size();

	};


	struct dstu_4145_cryptoapi_key_t
		: boost::noncopyable
		, cryptoapi_key_base_t
	{
		typedef  dstu_4145_key_t key_type;

		enum role_type {role_undef=0, role_keyx, role_sign};

		virtual boost::intrusive_ptr<cryptoapi_key_base_t> clone(){
			boost::intrusive_ptr<cryptoapi_key_base_t> cloned( new dstu_4145_cryptoapi_key_t(*this, key_op::init_from_other()) ) ;
			return cloned;
		}

		dstu_4145_cryptoapi_key_t(csp_t * const csp, role_type const role,  BYTE const* const key_blob, size_t const key_blob_size, key_op::load_from_blob const&);
		dstu_4145_cryptoapi_key_t(csp_t * const csp, role_type const role,  key_op::generate const&);
		dstu_4145_cryptoapi_key_t(dstu_4145_cryptoapi_key_t const& other, key_op::init_from_other const&);
		~dstu_4145_cryptoapi_key_t();

		virtual void sign(BYTE const* const data, size_t const data_size, BYTE * const sign_buffer, size_t const sign_buffer_sisze);
		virtual bool verify(BYTE const* const data, size_t const data_size, BYTE const * const sign_buffer, size_t const sign_buffer_sisze);
		virtual size_t get_signature_size();
		virtual std::pair<size_t,size_t> buffers_sizes();

		virtual size_t invoke_cipher_encrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len, hash_impl_base_t * const hasher, bool const final);
		virtual size_t invoke_cipher_decrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len, hash_impl_base_t * const hasher, bool const final);


		virtual void export_key_blob(std::vector<BYTE>& key_blob);
		virtual size_t key_blob_size();

		virtual void export_public_key_blob(std::vector<BYTE>& key_blob);
		virtual size_t public_key_blob_size();

		virtual DWORD get_blocklen();
		virtual ALG_ID get_alg_id()const;


		dstu_4145_key_t& get_key(){ return m_key; }
		dstu_4145_key_t const& get_key()const{ return m_key; }
	
	private:
		asymmetric_cipher_base_t* get_cipher_();

	private:
		dstu_4145_key_t m_key;
		asymmetric_cipher_base_ptr	m_cipher;
		role_type					m_role;
	};

	asymmetric_cipher_base_ptr create_dstu4145_cipher(dstu_4145_cryptoapi_key_t * const key);

}
//================================================================================================================================================
#endif
//================================================================================================================================================
