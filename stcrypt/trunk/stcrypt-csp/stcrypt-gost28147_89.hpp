//================================================================================================================================================
// FILE: stcrypt-gost28147_89.h
// (c) GIE 2009-11-06  14:15
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_GOST28147_89_2009_11_06_14_15
#define H_GUARD_STCRYPT_GOST28147_89_2009_11_06_14_15
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-crypto-alg-ids.h"
#include "stcrypt-symmetric-base.hpp"
#include "stcrypt-exceptions.hpp"
#include "stcrypt-debug.hpp"
#include "stcrypt-cryptolib.hpp"

#include "GOST_28147_89.h"

#include "boost/weak_ptr.hpp"
//================================================================================================================================================
namespace stcrypt {

	struct gost28147_89_family_key_t;
	struct gost28147_89_simple_cipher_info_block_t;
	struct gost28147_89_gamma_cipher_info_block_t;
	struct gost28147_89_gamma_cbc_cipher_info_block_t;
	struct csp_t;

	struct gost28147_89_cipher_base_t 
		: symmetric_block_cipher_base_t
		//, protected symmetric_api_t
	{
		explicit gost28147_89_cipher_base_t(boost::weak_ptr<csp_t> const& csp);
		virtual ~gost28147_89_cipher_base_t();
	protected:
		void copy_state_from_(gost28147_89_cipher_base_t const& other);
		static size_t suggest_buffer_size_(size_t const block_size, size_t const data_size);
	protected:
		//cryptolib_context_t m_ctx;
		Gost28147 m_alg;
	};

	/*
	 *
	 *
	 */
	template <class parent_tt, class info_block_tt>
	struct gost28147_89_cipher_mixin_t {

	protected:
		explicit gost28147_89_cipher_mixin_t(info_block_tt* const parent) : m_parent( parent ) {}
		boost::intrusive_ptr<info_block_tt> m_parent;
	};



	//! \brief Common for encrypt/decrypt simple cipher parts
	struct gost28147_89_simple_cipher_t 
		: gost28147_89_cipher_base_t
		, gost28147_89_cipher_mixin_t<gost28147_89_simple_cipher_t, gost28147_89_simple_cipher_info_block_t>
	{
		typedef gost28147_89_cipher_mixin_t<gost28147_89_simple_cipher_t, gost28147_89_simple_cipher_info_block_t> cipher_mixin_type;

		explicit gost28147_89_simple_cipher_t(gost28147_89_simple_cipher_info_block_t * const parent);
		~gost28147_89_simple_cipher_t();
	};

	/*! \brief Encrypt simple cipher part
	 *
	 *  \note Allow final block not to be multiply of cipher block size, padding with zeros (potential security problem?)
	 */
	struct gost28147_89_simple_encrypt_cipher_t
		: gost28147_89_simple_cipher_t
	{
		explicit gost28147_89_simple_encrypt_cipher_t(gost28147_89_simple_cipher_info_block_t * const parent);
		virtual size_t process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);
		virtual void validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final);
		virtual size_t suggest_buffer_size(size_t const data_size);

		typedef gost28147_89_simple_encrypt_cipher_t this_type;

		virtual boost::intrusive_ptr<symmetric_block_cipher_base_t> clone(){
			boost::intrusive_ptr<this_type> cloned( new this_type(m_parent.get()) );
			cloned->copy_state_from_(*this); assert( typeid(*this)==typeid(*cloned.get()) );  return cloned;
		}

	};

	//! \brief Decrypt simple cipher part
	struct gost28147_89_simple_decrypt_cipher_t
		: gost28147_89_simple_cipher_t
	{
		explicit gost28147_89_simple_decrypt_cipher_t(gost28147_89_simple_cipher_info_block_t * const parent);
		virtual size_t process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);
		virtual void validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final);
		virtual size_t suggest_buffer_size(size_t const data_size);

		typedef gost28147_89_simple_decrypt_cipher_t this_type;

		virtual boost::intrusive_ptr<symmetric_block_cipher_base_t> clone(){
			boost::intrusive_ptr<this_type> cloned( new this_type(m_parent.get()) );
			cloned->copy_state_from_(*this); assert( typeid(*this)==typeid(*cloned.get()) );  return cloned;
		}



	};

//================================================================================================================================================

 	/*
	 *
	 *
 	 */
	template <class parent_tt, class info_block_tt>
 	struct gost28147_89_gamma_cipher_mixin_t 
		: gost28147_89_cipher_mixin_t<parent_tt, info_block_tt>
	{
	protected:
		explicit gost28147_89_gamma_cipher_mixin_t(info_block_tt* const parent) : gost28147_89_cipher_mixin_t<parent_tt, info_block_tt>( parent ) {}

		size_t process_data_(BYTE * const data, size_t const data_len, size_t const buffer_len, bool const final){
			assert(data);
			assert(data_len);
			assert(data_len<=buffer_len);

			DWORD const data_size_to_process = static_cast<DWORD>( data_len );

			if(data_size_to_process>buffer_len){ STCRYPT_UNEXPECTED(); }

			this->self_()->m_alg.ProcessBuffer( reinterpret_cast<void*>( const_cast<BYTE*>(data) ), data_size_to_process);
			/*DWORD const errc = GOST28147ProcessBuffer(this->self_()->m_ctx, reinterpret_cast<void*>( const_cast<BYTE*>(data) ), data_size_to_process);
			if(errc!=0) {
				STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
			}*/
			return data_size_to_process;
		}


		void validate_buffer_(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final){
			if(!data) {STCRYPT_UNEXPECTED();}
			if( data_len==0 ) { STCRYPT_THROW_EXCEPTION(exception::bad_data() << exception::bad_data_einfo(data_len) ); }

			size_t const block_len = m_parent->block_size();

			if(!final) {
				if( data_len % block_len !=0 ) { //if not final the we have to process with block granularity
					STCRYPT_THROW_EXCEPTION(exception::bad_data() << exception::bad_data_einfo(data_len) );
				}

			} // else we process final block, so it can be of any length

			if( buffer_len < data_len ){ // just to be sure
				STCRYPT_THROW_EXCEPTION(exception::bad_len() << exception::bad_data_einfo(buffer_len) );
			}

		}

	private:
		parent_tt * self_(){
			return static_cast<parent_tt*>(this);
		}

 	};


//================================================================================================================================================


	//! \brief Common for encrypt/decrypt gamma cipher parts
	struct gost28147_89_gamma_cipher_t 
		: gost28147_89_cipher_base_t
		, gost28147_89_gamma_cipher_mixin_t<gost28147_89_gamma_cipher_t, gost28147_89_gamma_cipher_info_block_t>

	{
		typedef gost28147_89_gamma_cipher_mixin_t<gost28147_89_gamma_cipher_t, gost28147_89_gamma_cipher_info_block_t> cipher_mixin_typel;
		friend cipher_mixin_typel;

		explicit gost28147_89_gamma_cipher_t(gost28147_89_gamma_cipher_info_block_t * const parent);
		~gost28147_89_gamma_cipher_t();
	};

	/*! \brief Encrypt simple cipher part
	 *
	 *  \note Allow final block not to be multiply of cipher block size, padding with zeros (potential security problem?)
	 */
	struct gost28147_89_gamma_encrypt_cipher_t
		: gost28147_89_gamma_cipher_t
	{
		explicit gost28147_89_gamma_encrypt_cipher_t(gost28147_89_gamma_cipher_info_block_t * const parent);
		virtual size_t process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);
		virtual void validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final);
		virtual size_t suggest_buffer_size(size_t const data_size);

		typedef gost28147_89_gamma_encrypt_cipher_t this_type;

		virtual boost::intrusive_ptr<symmetric_block_cipher_base_t> clone(){
			boost::intrusive_ptr<this_type> cloned( new this_type(m_parent.get()) );
			cloned->copy_state_from_(*this); assert( typeid(*this)==typeid(*cloned.get()) );  return cloned;
		}

	};

	/*! \brief Decrypt simple cipher part
	 *
	 * 
	 */
	struct gost28147_89_gamma_decrypt_cipher_t
		: gost28147_89_gamma_encrypt_cipher_t 
	{
		explicit gost28147_89_gamma_decrypt_cipher_t(gost28147_89_gamma_cipher_info_block_t * const parent)
			: gost28147_89_gamma_encrypt_cipher_t(parent)
		{}
		virtual size_t process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);

		typedef gost28147_89_gamma_decrypt_cipher_t this_type;

		virtual boost::intrusive_ptr<symmetric_block_cipher_base_t> clone(){
			boost::intrusive_ptr<this_type> cloned( new this_type(m_parent.get()) );
			cloned->copy_state_from_(*this); assert( typeid(*this)==typeid(*cloned.get()) );  return cloned;
		}

	};

//================================================================================================================================================

	//! \brief Common for encrypt/decrypt gamma cbc cipher parts
	struct gost28147_89_gamma_cbc_cipher_t 
		: gost28147_89_cipher_base_t
		, gost28147_89_gamma_cipher_mixin_t<gost28147_89_gamma_cbc_cipher_t, gost28147_89_gamma_cbc_cipher_info_block_t>

	{
		typedef gost28147_89_gamma_cipher_mixin_t<gost28147_89_gamma_cbc_cipher_t, gost28147_89_gamma_cbc_cipher_info_block_t> cipher_mixint_type;
		friend cipher_mixint_type;

		explicit gost28147_89_gamma_cbc_cipher_t(gost28147_89_gamma_cbc_cipher_info_block_t * const parent);
		~gost28147_89_gamma_cbc_cipher_t();
	};

	/*! \brief Encrypt simple cipher part
	 *
	 *  \note Allow final block not to be multiply of cipher block size, padding with zeros (potential security problem?)
	 */
	struct gost28147_89_gamma_cbc_encrypt_cipher_t
		: gost28147_89_gamma_cbc_cipher_t
	{

		explicit gost28147_89_gamma_cbc_encrypt_cipher_t(gost28147_89_gamma_cbc_cipher_info_block_t * const parent);
		virtual size_t process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);
		virtual void validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final);
		virtual size_t suggest_buffer_size(size_t const data_size);

		typedef gost28147_89_gamma_cbc_encrypt_cipher_t this_type;

		virtual boost::intrusive_ptr<symmetric_block_cipher_base_t> clone(){
			boost::intrusive_ptr<this_type> cloned( new this_type(m_parent.get()) );
			cloned->copy_state_from_(*this); assert( typeid(*this)==typeid(*cloned.get()) );  return cloned;
		}

	};

	//! \brief Decrypt gamma cbc cipher part
	struct gost28147_89_gamma_cbc_decrypt_cipher_t
		: gost28147_89_gamma_cbc_cipher_t
	{
		explicit gost28147_89_gamma_cbc_decrypt_cipher_t(gost28147_89_gamma_cbc_cipher_info_block_t * const parent);
		virtual size_t process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final);
		virtual void validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final);
		virtual size_t suggest_buffer_size(size_t const data_size);

		typedef gost28147_89_gamma_cbc_decrypt_cipher_t this_type;

		virtual boost::intrusive_ptr<symmetric_block_cipher_base_t> clone(){
			boost::intrusive_ptr<this_type> cloned( new this_type(m_parent.get()) );
			cloned->copy_state_from_(*this); assert( typeid(*this)==typeid(*cloned.get()) );  return cloned;
		}

	};

//================================================================================================================================================

	/*
	 *
	 *
	 */
	struct gost28147_89_info_block_base_t
		: symmetric_block_cipher_info_block_i
	{
		explicit gost28147_89_info_block_base_t(gost28147_89_family_key_t * const parent)
			: m_parent( parent )
		{}
		virtual size_t  block_size()const {
			return CALG_ID_G28147_89_BLOCKSIZE;
		}
		gost28147_89_family_key_t * get_parent()const{return m_parent;}
		void reset_parent(){
			m_parent = 0;
		}
	private:
		gost28147_89_family_key_t * m_parent; //TODO: generalize with weakptr ?
	};

	/*
	 *
	 *
	 */
	struct gost28147_89_simple_cipher_info_block_t
		: gost28147_89_info_block_base_t
	{
		virtual symmetric_block_cipher_base_ptr create_encrypt();
		virtual symmetric_block_cipher_base_ptr create_decrypt();
		explicit gost28147_89_simple_cipher_info_block_t(gost28147_89_family_key_t * const parent) 
			: gost28147_89_info_block_base_t( parent )	{}
	};
	typedef boost::intrusive_ptr<gost28147_89_simple_cipher_info_block_t> gost28147_89_simple_cipher_info_block_ptr;


	/*
	 *
	 *
	 */
	struct gost28147_89_gamma_cipher_info_block_t
		: gost28147_89_info_block_base_t
	{
		virtual symmetric_block_cipher_base_ptr create_encrypt();
		virtual symmetric_block_cipher_base_ptr create_decrypt();
		explicit gost28147_89_gamma_cipher_info_block_t(gost28147_89_family_key_t * const parent) 
			: gost28147_89_info_block_base_t( parent )	{}
	};
	typedef boost::intrusive_ptr<gost28147_89_gamma_cipher_info_block_t> gost28147_89_gamma_cipher_info_block_ptr;


	/*
	 *
	 *
	 */
	struct gost28147_89_gamma_cbc_cipher_info_block_t
		: gost28147_89_info_block_base_t
	{
		virtual symmetric_block_cipher_base_ptr create_encrypt();
		virtual symmetric_block_cipher_base_ptr create_decrypt();
		explicit gost28147_89_gamma_cbc_cipher_info_block_t(gost28147_89_family_key_t * const parent) 
			: gost28147_89_info_block_base_t( parent )	{}
	};
	typedef boost::intrusive_ptr<gost28147_89_gamma_cbc_cipher_info_block_t> gost28147_89_gamma_cbc_cipher_info_block_ptr;


}
//================================================================================================================================================
#endif
//================================================================================================================================================
