//================================================================================================================================================
// FILE: stcrypt-dstu4145-cipher.cpp
// (c) GIE 2010-01-05  18:01
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-dstu4145-cipher.hpp"

#include "stcrypt-key-dstu4145.hpp"
//================================================================================================================================================
namespace stcrypt {

	dstu4145_cipher_t::dstu4145_cipher_t(dstu_4145_cryptoapi_key_t * const key)
		: m_key(key)
		, m_ctx(0)
	{
		assert(m_key);
		typedef dstu_4145_cryptoapi_key_t::key_type key_type;

		key_type const& key_data = m_key->get_key();
		STCRYPT_CHECK_CRYPTO(DSTU4145AcquireContext(&m_ctx));
		try{
			STCRYPT_CHECK_CRYPTO(DSTU4145InitStd(m_ctx,key_data.m_std_mode));
		}catch(...){
			STCRYPT_DEBUG_CHECK_CRYPTO(DSTU4145DestroyContext(m_ctx));
			throw;
		}

	}
	dstu4145_cipher_t::~dstu4145_cipher_t(){
		STCRYPT_DEBUG_CHECK_CRYPTO(DSTU4145DestroyContext(m_ctx));
	}

	void dstu4145_cipher_t::reset_key_(){
		m_key = 0;
	}

	void dstu4145_cipher_t::notify(){
		reset_key_();
	}


	size_t dstu4145_cipher_t::encrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len){
		typedef TBLOCK256 data_block_type;
		
		if(data_len!=sizeof(data_block_type))
			STCRYPT_UNIMPLEMENTED();

		if(!out_buffer)
			STCRYPT_UNEXPECTED();

		if(out_buffer_len!=this->buffers_sizes().second)
			STCRYPT_UNEXPECTED();

		assert(m_key);
		typedef dstu_4145_cryptoapi_key_t::key_type key_type;

		key_type const& key_data = m_key->get_key();

		DWORD buffer_size = static_cast<DWORD>(out_buffer_len);
		STCRYPT_CHECK_CRYPTO( AsymmetricEncryption(m_ctx, 
												   reinterpret_cast<data_block_type*>( const_cast<BYTE*>(data) ), 
												   const_cast<key_type::public_part_type*>(&key_data.m_public_part), 
												   out_buffer, 
												   &buffer_size) );

		assert(buffer_size==out_buffer_len);


		return out_buffer_len;
	}



	size_t dstu4145_cipher_t::decrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len){
		typedef TBLOCK256 data_block_type;

		if(out_buffer_len!=sizeof(data_block_type))
			STCRYPT_UNIMPLEMENTED();

		if(!out_buffer)
			STCRYPT_UNEXPECTED();

		if(data_len!=this->buffers_sizes().second)
			STCRYPT_UNEXPECTED();

		assert(m_key);
		typedef dstu_4145_cryptoapi_key_t::key_type key_type;

		key_type const& key_data = m_key->get_key();
		if( !key_data.m_private_part )
			STCRYPT_THROW_EXCEPTION(exception::bad_key());

		DWORD buffer_size = static_cast<DWORD>(out_buffer_len);
		STCRYPT_CHECK_CRYPTO( AsymmetricDecryption(
			m_ctx, 
			const_cast<key_type::private_part_type*>(&(*key_data.m_private_part)), 
			const_cast<BYTE*>( data ),
			data_len,
			reinterpret_cast<data_block_type*>( const_cast<BYTE*>(out_buffer) ) ) );

		return sizeof(data_block_type);
	}



	std::pair<size_t,size_t> dstu4145_cipher_t::buffers_sizes(){

		TBLOCK256 data_block;
		DWORD	  encrypted_data_block_size;

		assert(m_key);
		typedef dstu_4145_cryptoapi_key_t::key_type key_type;

		key_type const& key_data = m_key->get_key();

		STCRYPT_CHECK_CRYPTO(AsymmetricEncryption(m_ctx, &data_block, const_cast<key_type::public_part_type*>(&key_data.m_public_part), 0, &encrypted_data_block_size));
		return std::make_pair(sizeof(data_block), encrypted_data_block_size);

	}
	size_t dstu4145_cipher_t::sign_size(){
		DWORD sign_size=0;
		STCRYPT_CHECK_CRYPTO( DSTU4145GetSignSize(m_ctx,&sign_size) );
		return sign_size;
	}



	void dstu4145_cipher_t::sign(BYTE const* const data, size_t const data_size, BYTE * const sign_buffer, size_t const sign_buffer_size){

		TBLOCK256 tmp_buffer;
		BYTE const* data_to_be_signed;
		
		if(sizeof(TBLOCK256)==data_size){
			data_to_be_signed = data;
		} else if(sizeof(TBLOCK256)<data_size) {
			STCRYPT_THROW_EXCEPTION(exception::bad_data());
		} else { //data_size<TBLOCK256
			memset(tmp_buffer,0,sizeof(tmp_buffer) );
			memcpy(&tmp_buffer,data,data_size);
			data_to_be_signed = reinterpret_cast<BYTE const*>(tmp_buffer);
		}
		
		assert(m_key);
		typedef dstu_4145_cryptoapi_key_t::key_type key_type;

		key_type const& key_data = m_key->get_key();

		if(!key_data.m_private_part)
			STCRYPT_THROW_EXCEPTION(exception::bad_key());

		DWORD dw_sign_buffer_size = static_cast<DWORD>( sign_buffer_size );

		STCRYPT_CHECK_CRYPTO( DSTU4145CalcSign(m_ctx, 
					reinterpret_cast<TBLOCK256*>( const_cast<BYTE*>(data_to_be_signed)), 
					const_cast<key_type::private_part_type*>(&(*key_data.m_private_part)), 
					sign_buffer, 
					&dw_sign_buffer_size ) );

		if(dw_sign_buffer_size!=sign_buffer_size){
			assert(!"Should never get here");
			STCRYPT_UNEXPECTED();
		}
	}

	bool dstu4145_cipher_t::verify(BYTE const* const data, size_t const data_size, BYTE const * const sign_buffer, size_t const sign_buffer_sisze){
		
		TBLOCK256 tmp_buffer;
		BYTE const* data_to_be_verified;

		if(sizeof(TBLOCK256)==data_size){
			data_to_be_verified = data;
		} else if(sizeof(TBLOCK256)<data_size) {
			STCRYPT_THROW_EXCEPTION(exception::bad_data());
		} else { //data_size<TBLOCK256
			memset(tmp_buffer,0,sizeof(tmp_buffer) );
			memcpy(&tmp_buffer,data,data_size);
			data_to_be_verified = reinterpret_cast<BYTE const*>(tmp_buffer);
		}
		
		assert(m_key);
		typedef dstu_4145_cryptoapi_key_t::key_type key_type;

		key_type const& key_data = m_key->get_key();

		DWORD const res = DSTU4145CheckSign(m_ctx, 
					reinterpret_cast<TBLOCK256*>( const_cast<BYTE*>(data_to_be_verified)), 
					const_cast<key_type::public_part_type*>(&key_data.m_public_part), 
					const_cast<BYTE*>(sign_buffer), 
					static_cast<DWORD>(sign_buffer_sisze) );

		if(res==CL_RES_SUCCESS){
			return true;
		} else if(res==CL_RES_ERROR_SIGN) {
			return false;
		} else {
			STCRYPT_CRYPTO_THROW_FROM_CODE(res);
		}


	}




	asymmetric_cipher_base_ptr create_dstu4145_cipher(dstu_4145_cryptoapi_key_t * const key){
		return asymmetric_cipher_base_ptr( new dstu4145_cipher_t(key) );
	}


}
//================================================================================================================================================
