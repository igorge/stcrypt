//================================================================================================================================================
// FILE: stcrypt-gost28147_89.cpp
// (c) GIE 2009-11-06  14:15
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-key-gost28147_89.hpp"
#include "stcrypt-gost28147_89.hpp"
#include "stcrypt-crypto-alg-ids.h"

#include "CryptoLib.h"
//================================================================================================================================================
namespace stcrypt {


	gost28147_89_cipher_base_t::gost28147_89_cipher_base_t(boost::weak_ptr<csp_t> const& csp) 
		//: symmetric_api_t( csp )
		//: m_ctx(0)
	{
// 		DWORD const errc = GOST28147AcquireContext(&m_ctx);
// 		if(errc!=0) {
// 			STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
// 		}
	}

	gost28147_89_cipher_base_t::~gost28147_89_cipher_base_t(){
// 		DWORD const errc = GOST28147DestroyContext(m_ctx);
// 		if(errc!=0) {
// 			assert(!"GOST28147DestroyContext() have failed");
// 		}
	}

	size_t gost28147_89_cipher_base_t::suggest_buffer_size_(size_t const block_size, size_t const data_size){
		assert(block_size);
		assert(data_size);

		if(!data_size){STCRYPT_UNEXPECTED();}

		size_t const buffer_len = (data_size/block_size + ((data_size%block_size)==0?0:1) )*block_size;
		return buffer_len;

	}

	void gost28147_89_cipher_base_t::copy_state_from_(gost28147_89_cipher_base_t const& other){
		m_alg.copy_state_from(other.m_alg);
	}


	//================================================================================================================================================
	gost28147_89_simple_decrypt_cipher_t::gost28147_89_simple_decrypt_cipher_t(gost28147_89_simple_cipher_info_block_t * const parent)
		: gost28147_89_simple_cipher_t(parent)
	{
		gost28147_89_family_key_t * const key = m_parent->get_parent();
		gost28147_89_family_key_t::key_blob_type const& key_data = key->get_key_data();
		assert(key);

		if(!key_data.m_key){STCRYPT_UNEXPECTED();}

		TBLOCK256* const key256 = const_cast<TBLOCK256*>( &key_data.m_key->data );
		TGOSTDKE* const dke = key_data.m_dke ? const_cast<TGOSTDKE*>( &key_data.m_dke->data ) : 0;

		m_alg.Init(GOST28147_MODE_SIMPLE_REPLACE, key256, dke, false);
// 		DWORD const errc = GOST28147InitSR(m_ctx, dke , key256, false);
// 		if(errc!=0) {
// 			STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
// 		}

	}



	size_t gost28147_89_simple_decrypt_cipher_t::suggest_buffer_size(size_t const data_size)
	{
		STCRYPT_UNEXPECTED();
	}



	void gost28147_89_simple_decrypt_cipher_t::validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final){
		if(!data) {STCRYPT_UNEXPECTED();}
		if( data_len==0 ) { STCRYPT_THROW_EXCEPTION(exception::bad_data() << exception::bad_data_einfo(data_len) ); }
		size_t const block_len = m_parent->block_size();


		if( data_len % block_len !=0 ) {
			STCRYPT_THROW_EXCEPTION(exception::bad_data() << exception::bad_data_einfo(data_len) );
		}
	}



	size_t gost28147_89_simple_decrypt_cipher_t::process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
	
		size_t const block_size = m_parent->block_size();

		DWORD const data_size_to_process = static_cast<DWORD>( data_len );
		if( data_size_to_process%block_size!=0 ){ STCRYPT_UNEXPECTED(); }
		if(data_size_to_process<buffer_len){ STCRYPT_UNEXPECTED(); }

		m_alg.ProcessBuffer(reinterpret_cast<void*>( data ), data_size_to_process);
//		DWORD const errc = GOST28147ProcessBuffer(m_ctx, reinterpret_cast<void*>( data ), data_size_to_process);
//		if(errc!=0) {
//			STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
//		}

		if(hasher) hasher->hash_data(data,data_size_to_process);

		return data_size_to_process;
	}


	//================================================================================================================================================
	gost28147_89_simple_encrypt_cipher_t::gost28147_89_simple_encrypt_cipher_t(gost28147_89_simple_cipher_info_block_t * const parent)
		: gost28147_89_simple_cipher_t(parent)
	{
		gost28147_89_family_key_t * const key = m_parent->get_parent();
		gost28147_89_family_key_t::key_blob_type const& key_data = key->get_key_data();
		assert(key);

		if(!key_data.m_key){STCRYPT_UNEXPECTED();}
		
		TBLOCK256* const key256 = const_cast<TBLOCK256*>( &key_data.m_key->data );
		TGOSTDKE* const dke = key_data.m_dke ? const_cast<TGOSTDKE*>( &key_data.m_dke->data ) : 0;

		m_alg.Init(GOST28147_MODE_SIMPLE_REPLACE, key256, dke, true);
		//DWORD const errc = GOST28147InitSR(m_ctx, dke , key256, true);
		//if(errc!=0) {
	//		STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
//		}

	}



	size_t gost28147_89_simple_encrypt_cipher_t::suggest_buffer_size(size_t const data_size)
	{
		return suggest_buffer_size_(m_parent->block_size(), data_size);
	}



	void gost28147_89_simple_encrypt_cipher_t::validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final){
		if(!data) {STCRYPT_UNEXPECTED();}
		if( data_len==0 ) { STCRYPT_THROW_EXCEPTION(exception::bad_data() << exception::bad_data_einfo(data_len) ); }
		size_t const block_len = m_parent->block_size();

		if( buffer_len < this->suggest_buffer_size(data_len) ){
			STCRYPT_THROW_EXCEPTION(exception::bad_len() << exception::bad_data_einfo(buffer_len) );
		}
		
		if(final) {

		} else {
			if( data_len % block_len !=0 ) {
				STCRYPT_THROW_EXCEPTION(exception::bad_data() << exception::bad_data_einfo(data_len) );
			}
		}
	}



	size_t gost28147_89_simple_encrypt_cipher_t::process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
		size_t const block_size = m_parent->block_size();

		if(final){
			#pragma warning(disable:4996)

			DWORD const data_size_to_process = static_cast<DWORD>( data_len%block_size==0?data_len:this->suggest_buffer_size(data_len) );
			if(data_size_to_process>buffer_len){ STCRYPT_UNEXPECTED(); }
			std::fill_n(data+data_len, data_size_to_process-data_len,0);

			if(hasher) hasher->hash_data(data,data_size_to_process);

			m_alg.ProcessBuffer(reinterpret_cast<void*>( data ), data_size_to_process);
			/*DWORD const errc = GOST28147ProcessBuffer(m_ctx, reinterpret_cast<void*>( data ), data_size_to_process);
			if(errc!=0) {
				STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
			}*/
			return data_size_to_process;

			#pragma warning(default:4996)
		} else {
			DWORD const data_size_to_process = static_cast<DWORD>( data_len );
			if( data_size_to_process%block_size!=0 ){ STCRYPT_UNEXPECTED(); }
			if(data_size_to_process>buffer_len){ STCRYPT_UNEXPECTED(); }

			m_alg.ProcessBuffer(reinterpret_cast<void*>( data ), data_size_to_process);
			/*DWORD const errc = GOST28147ProcessBuffer(m_ctx, reinterpret_cast<void*>( const_cast<BYTE*>(data) ), data_size_to_process);
			if(errc!=0) {
				STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
			}*/
			return data_size_to_process;
		}
	}



	//================================================================================================================================================
	gost28147_89_simple_cipher_t::gost28147_89_simple_cipher_t(gost28147_89_simple_cipher_info_block_t * const parent)
		: gost28147_89_cipher_base_t( parent->get_parent()->get_csp() )
		, cipher_mixin_type( parent )
	{
	}



	gost28147_89_simple_cipher_t::~gost28147_89_simple_cipher_t(){
	}

	//================================================================================================================================================
	gost28147_89_gamma_cipher_t::gost28147_89_gamma_cipher_t(gost28147_89_gamma_cipher_info_block_t * const parent)
		: gost28147_89_cipher_base_t( parent->get_parent()->get_csp() )
		, cipher_mixin_typel( parent )
	{
	}



	gost28147_89_gamma_cipher_t::~gost28147_89_gamma_cipher_t(){
	}
	//================================================================================================================================================
	gost28147_89_gamma_encrypt_cipher_t::gost28147_89_gamma_encrypt_cipher_t(gost28147_89_gamma_cipher_info_block_t * const parent) 
		: gost28147_89_gamma_cipher_t(parent)
	{
		typedef gost28147_89_family_key_t::key_blob_type key_blob_type;

		gost28147_89_family_key_t * const key = m_parent->get_parent();
		assert(key);
		key_blob_type const& key_data = key->get_key_data();

		if(!key_data.m_key){STCRYPT_UNEXPECTED();}
		if(!key_data.m_iv){STCRYPT_UNEXPECTED();}

		key_blob_type::key_type* const key256 = const_cast<key_blob_type::key_type*>( &key_data.m_key->data );
		key_blob_type::iv_type* const iv = const_cast<key_blob_type::iv_type*>( &key_data.m_iv->data );
		key_blob_type::dke_type* const dke = key_data.m_dke ? const_cast<TGOSTDKE*>( &key_data.m_dke->data ) : 0;

		m_alg.Init(GOST28147_MODE_GAMMING, key256, dke, true, iv);
		/*DWORD const errc = GOST28147InitG(m_ctx, dke , key256, iv);
		if(errc!=0) {
			STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
		}*/

	}



	size_t gost28147_89_gamma_encrypt_cipher_t::process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
		if(hasher) hasher->hash_data(data,data_len);
		return this->process_data_(data, data_len, buffer_len, final);
	}

	size_t gost28147_89_gamma_decrypt_cipher_t::process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
		size_t const data_size = this->process_data_(data, data_len, buffer_len, final);
		if(hasher) hasher->hash_data(data,data_len);
		return data_size;
	}
	



	void gost28147_89_gamma_encrypt_cipher_t::validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final){
		return this->validate_buffer_(data, data_len, buffer_len, final);
 	}

	size_t gost28147_89_gamma_encrypt_cipher_t::suggest_buffer_size(size_t const data_size){
		return suggest_buffer_size_(m_parent->block_size(), data_size);
	}


	//================================================================================================================================================





	gost28147_89_gamma_cbc_cipher_t::gost28147_89_gamma_cbc_cipher_t(gost28147_89_gamma_cbc_cipher_info_block_t * const parent)
		: gost28147_89_cipher_base_t( parent->get_parent()->get_csp() )
		, cipher_mixint_type( parent )
	{
	}



	gost28147_89_gamma_cbc_cipher_t::~gost28147_89_gamma_cbc_cipher_t(){
	}
	//================================================================================================================================================
	gost28147_89_gamma_cbc_encrypt_cipher_t::gost28147_89_gamma_cbc_encrypt_cipher_t(gost28147_89_gamma_cbc_cipher_info_block_t * const parent) 
		: gost28147_89_gamma_cbc_cipher_t(parent)
	{
		typedef gost28147_89_family_key_t::key_blob_type key_blob_type;

		gost28147_89_family_key_t * const key = m_parent->get_parent();
		assert(key);
		key_blob_type const& key_data = key->get_key_data();

		if(!key_data.m_key){STCRYPT_UNEXPECTED();}
		if(!key_data.m_iv){STCRYPT_UNEXPECTED();}

		key_blob_type::key_type* const key256 = const_cast<key_blob_type::key_type*>( &key_data.m_key->data );
		key_blob_type::iv_type* const iv = const_cast<key_blob_type::iv_type*>( &key_data.m_iv->data );
		key_blob_type::dke_type* const dke = key_data.m_dke ? const_cast<TGOSTDKE*>( &key_data.m_dke->data ) : 0;

		m_alg.Init(GOST28147_MODE_FEEDBACK_GAMMING, key256, dke, true, iv);
		/*DWORD const errc = GOST28147InitFBG(m_ctx, dke , key256, iv, true);
		if(errc!=0) {
			STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
		}*/

	}



	size_t gost28147_89_gamma_cbc_encrypt_cipher_t::process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
		if(hasher) hasher->hash_data(data,data_len);
		return this->process_data_(data, data_len, buffer_len, final);
	}



	void gost28147_89_gamma_cbc_encrypt_cipher_t::validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final){
		return this->validate_buffer_(data, data_len, buffer_len, final);
	}
	size_t gost28147_89_gamma_cbc_encrypt_cipher_t::suggest_buffer_size(size_t const data_size){
		return suggest_buffer_size_(m_parent->block_size(), data_size);
	}


	//================================================================================================================================================
	gost28147_89_gamma_cbc_decrypt_cipher_t::gost28147_89_gamma_cbc_decrypt_cipher_t(gost28147_89_gamma_cbc_cipher_info_block_t * const parent) 
		: gost28147_89_gamma_cbc_cipher_t(parent)
	{
		typedef gost28147_89_family_key_t::key_blob_type key_blob_type;

		gost28147_89_family_key_t * const key = m_parent->get_parent();
		assert(key);
		key_blob_type const& key_data = key->get_key_data();

		if(!key_data.m_key){STCRYPT_UNEXPECTED();}
		if(!key_data.m_iv){STCRYPT_UNEXPECTED();}

		key_blob_type::key_type* const key256 = const_cast<key_blob_type::key_type*>( &key_data.m_key->data );
		key_blob_type::iv_type* const iv = const_cast<key_blob_type::iv_type*>( &key_data.m_iv->data );
		key_blob_type::dke_type* const dke = key_data.m_dke ? const_cast<TGOSTDKE*>( &key_data.m_dke->data ) : 0;

		m_alg.Init(GOST28147_MODE_FEEDBACK_GAMMING, key256, dke, false , iv);
		/*DWORD const errc = GOST28147InitFBG(m_ctx, dke , key256, iv, false);
		if(errc!=0) {
			STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(errc));
		}*/

	}



	size_t gost28147_89_gamma_cbc_decrypt_cipher_t::process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
		size_t const data_size =  this->process_data_(data, data_len, buffer_len, final);
		if(hasher) hasher->hash_data(data,data_size);
		return data_size;
	}



	void gost28147_89_gamma_cbc_decrypt_cipher_t::validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final){
		return this->validate_buffer_(data, data_len, buffer_len, final);
	}
	size_t gost28147_89_gamma_cbc_decrypt_cipher_t::suggest_buffer_size(size_t const data_size){
		return suggest_buffer_size_(m_parent->block_size(), data_size);
	}


	//================================================================================================================================================

	symmetric_block_cipher_base_ptr gost28147_89_simple_cipher_info_block_t::create_encrypt(){
		return symmetric_block_cipher_base_ptr( new gost28147_89_simple_encrypt_cipher_t(this) );
	}


	
	symmetric_block_cipher_base_ptr gost28147_89_simple_cipher_info_block_t::create_decrypt(){
		return symmetric_block_cipher_base_ptr( new gost28147_89_simple_decrypt_cipher_t(this) );
	}
	//================================================================================================================================================
	symmetric_block_cipher_base_ptr gost28147_89_gamma_cipher_info_block_t::create_encrypt(){
		return symmetric_block_cipher_base_ptr( new gost28147_89_gamma_encrypt_cipher_t(this) );
	}



	symmetric_block_cipher_base_ptr gost28147_89_gamma_cipher_info_block_t::create_decrypt(){
		return symmetric_block_cipher_base_ptr( new gost28147_89_gamma_decrypt_cipher_t(this) );
	}

	//================================================================================================================================================
	symmetric_block_cipher_base_ptr gost28147_89_gamma_cbc_cipher_info_block_t::create_encrypt(){
		return symmetric_block_cipher_base_ptr( new gost28147_89_gamma_cbc_encrypt_cipher_t(this) );
	}



	symmetric_block_cipher_base_ptr gost28147_89_gamma_cbc_cipher_info_block_t::create_decrypt(){
		return symmetric_block_cipher_base_ptr( new gost28147_89_gamma_cbc_decrypt_cipher_t(this) );
	}

}
//================================================================================================================================================
