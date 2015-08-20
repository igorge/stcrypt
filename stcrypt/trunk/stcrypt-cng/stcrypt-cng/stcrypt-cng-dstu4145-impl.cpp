//================================================================================================================================================
// FILE: stcrypt-cng-dstu4145-impl.cpp
// (c) GIE 2010-09-02  12:47
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-dstu4145-impl.hpp"

#include "gie/gie_auto_vector.hpp"

#include <boost/utility/in_place_factory.hpp>
#include <boost/numeric/conversion/cast.hpp>
//================================================================================================================================================
namespace stcrypt {


	void dstu4145_t::sign(BYTE const* const data, size_t const data_size, BYTE * const sign_buffer, size_t const sign_buffer_size){

		assert( this->signature_size() <= sign_buffer_size );

		sign_block_type tmp_buffer;
		BYTE const* data_to_be_signed;

		auto const max_sign_block_size = this->signature_block_size();

		if(max_sign_block_size==data_size){
			data_to_be_signed = data;
		} else if(max_sign_block_size<data_size) {
			STCRYPT_THROW_EXCEPTION(exception::bad_data());
		} else { //data_size<max_sign_block_size
			memset(tmp_buffer+data_size,0,sizeof(tmp_buffer)-data_size );
			memcpy(&tmp_buffer,data,data_size);
			data_to_be_signed = &tmp_buffer[0];
		}


		if(!m_private_part)
			STCRYPT_THROW_EXCEPTION(exception::bad_key());

		auto dw_sign_buffer_size = static_cast<DWORD>( sign_buffer_size );

		STCRYPT_CHECK_CRYPTO( DSTU4145CalcSign(m_ctx, 
			reinterpret_cast<sign_block_type*>( const_cast<BYTE*>(data_to_be_signed)), 
			const_cast<private_part_type*>(&(*m_private_part)), 
			sign_buffer, 
			&dw_sign_buffer_size ) );

		if(dw_sign_buffer_size!=sign_buffer_size){
			assert(!"Should never get here");
			STCRYPT_UNEXPECTED();
		}

	}


	
	bool dstu4145_t::verify(BYTE const* const data, size_t const data_size, BYTE const * const signature, size_t const signature_size){

		assert( this->signature_size() <= signature_size );

		sign_block_type tmp_buffer;
		BYTE const* data_to_be_verified;

		auto const max_sign_block_size = this->signature_block_size();

		if(max_sign_block_size==data_size){
			data_to_be_verified = data;
		} else if(max_sign_block_size<data_size) {
			STCRYPT_THROW_EXCEPTION(exception::bad_data());
		} else { //data_size<max_sign_block_size
			memset(tmp_buffer+data_size,0,sizeof(tmp_buffer)-data_size );
			memcpy(&tmp_buffer,data,data_size);
			data_to_be_verified = &tmp_buffer[0];
		}

		
		DWORD const res = DSTU4145CheckSign(m_ctx, 
			reinterpret_cast<TBLOCK256*>( const_cast<BYTE*>(data_to_be_verified)), 
			const_cast<public_part_type*>(&m_public_part), 
			const_cast<BYTE*>(signature), 
			static_cast<DWORD>(signature_size) );

		if(res==CL_RES_SUCCESS){
			return true;
		} else if(res==CL_RES_ERROR_SIGN) {
			return false;
		} else {
			STCRYPT_CRYPTO_THROW_FROM_CODE(res);
		}

	}



	size_t dstu4145_t::signature_size()const{
		DWORD sign_size=0;
		STCRYPT_CHECK_CRYPTO( DSTU4145GetSignSize(m_ctx,&sign_size) );
		return sign_size;
	}


	
	boost::tuple<size_t,size_t> dstu4145_t::buffers_sizes()const{
		plaintext_block_type data_block;
		DWORD				 encrypted_data_block_size;

		STCRYPT_CHECK_CRYPTO(AsymmetricEncryption(m_ctx, &data_block, const_cast<public_part_type*>( &m_public_part ), 0, &encrypted_data_block_size));
		return boost::make_tuple( sizeof(data_block), encrypted_data_block_size );
	}

	size_t dstu4145_t::encrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len){
		auto const& buffers_sizes = this->buffers_sizes();

		auto const complete_input_blocks = data_len/boost::get<0>( buffers_sizes );
		bool const partial_input_blocks =  (data_len%boost::get<0>( buffers_sizes ))!=0;
		auto const total_input_blocks = complete_input_blocks+(partial_input_blocks?1:0);
		auto const required_output_buffer_size = total_input_blocks*boost::get<1>( buffers_sizes );

		if( out_buffer_len<required_output_buffer_size  ) STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair(out_buffer_len, required_output_buffer_size) ) );
		
		auto in_bytes_left = data_len;
		auto out_bytes_left = out_buffer_len;

		BYTE const* curr_in = data;
		BYTE * curr_out = out_buffer;

		if(complete_input_blocks) {
			auto const in_to_consume = complete_input_blocks*boost::get<0>( buffers_sizes );
			auto const out_to_consume = complete_input_blocks*boost::get<1>( buffers_sizes );

			assert(curr_in+in_to_consume<=data+data_len);
			assert(curr_out+out_to_consume<=out_buffer+out_buffer_len);

			auto const out_buffer_consumed = this->encrypt_blocks(curr_in, in_to_consume, curr_out, out_to_consume);
			assert(out_buffer_consumed==out_to_consume); (void)out_buffer_consumed;

			curr_in+=in_to_consume;
			curr_out+=out_to_consume;

			in_bytes_left-=in_to_consume;
			out_bytes_left-=out_to_consume;
		}

		if(partial_input_blocks){
			assert(in_bytes_left<boost::get<0>( buffers_sizes ));
			assert(out_bytes_left>=boost::get<1>( buffers_sizes ));
			assert(curr_out+boost::get<1>( buffers_sizes )<=out_buffer+out_buffer_len);

			gie::monotonic::vector<BYTE, 4*1024> tmp_block;

			std::copy(curr_in, curr_in+in_bytes_left, std::back_inserter(tmp_block) );
			tmp_block.resize( boost::get<0>( buffers_sizes ) );

			this->encrypt_block( tmp_block.data(), tmp_block.size(), curr_out, boost::get<1>( buffers_sizes ) );

		}

		return total_input_blocks*boost::get<1>( buffers_sizes );
	}

	size_t dstu4145_t::encrypt_blocks(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len){
		auto const& buffers_sizes = this->buffers_sizes();

		if( data_len%boost::get<0>( buffers_sizes )!=0 ) STCRYPT_UNEXPECTED();
		if( out_buffer_len%boost::get<1>( buffers_sizes )!=0 ) STCRYPT_UNEXPECTED();
		
		if( data_len%boost::get<0>( buffers_sizes ) != out_buffer_len%boost::get<1>( buffers_sizes ) ) STCRYPT_UNEXPECTED();

		BYTE const* curr_in = data;
		BYTE * curr_out = out_buffer;

		while( curr_in != data+data_len ){
			assert( curr_in+boost::get<0>( buffers_sizes )<=data+data_len );
			assert( curr_out+boost::get<1>( buffers_sizes )<=out_buffer+out_buffer_len );

			auto data_written = encrypt_block(curr_in, boost::get<0>( buffers_sizes ), curr_out, boost::get<1>( buffers_sizes ) );
			assert( data_written==boost::get<1>( buffers_sizes ) );
			(void)data_written;

			curr_in+= boost::get<0>( buffers_sizes );
			curr_out+= boost::get<1>( buffers_sizes );
		}

		assert(curr_out==out_buffer+out_buffer_len);

		return out_buffer_len;
	}



	size_t dstu4145_t::encrypt_block( BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len ){

		STCRYPT_CHECK(data);
		STCRYPT_CHECK(out_buffer);

		auto const& buffers_sizes = this->buffers_sizes();
		assert( boost::get<0>( buffers_sizes )==sizeof(plaintext_block_type) );

		if( data_len!=boost::get<0>( buffers_sizes ) )
			STCRYPT_UNIMPLEMENTED();

		if( out_buffer_len!=boost::get<1>( buffers_sizes ) )
			STCRYPT_UNEXPECTED();

		DWORD buffer_size = boost::numeric_cast<DWORD>(out_buffer_len);
		STCRYPT_CHECK_CRYPTO( AsymmetricEncryption(m_ctx, 
			reinterpret_cast<plaintext_block_type*>( const_cast<BYTE*>(data) ), 
			const_cast<public_part_type*>(&m_public_part), 
			out_buffer, 
			&buffer_size) );

		assert(buffer_size==out_buffer_len);


		return out_buffer_len;
	}

	size_t dstu4145_t::decrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len){
		return this->decrypt_blocks(data, data_len, out_buffer, out_buffer_len);
	}


	size_t dstu4145_t::decrypt_blocks(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len){
		auto const& buffers_sizes = this->buffers_sizes();

		if( data_len%boost::get<1>( buffers_sizes )!=0 ) STCRYPT_UNEXPECTED();
		if( out_buffer_len%boost::get<0>( buffers_sizes )!=0 ) STCRYPT_UNEXPECTED();

		if( data_len%boost::get<1>( buffers_sizes ) != out_buffer_len%boost::get<0>( buffers_sizes ) ) STCRYPT_UNEXPECTED();

		BYTE const* curr_in = data;
		BYTE * curr_out = out_buffer;

		while( curr_in != data+data_len ){
			assert( curr_in+boost::get<1>( buffers_sizes )<=data+data_len );
			assert( curr_out+boost::get<0>( buffers_sizes )<=out_buffer+out_buffer_len );

			auto data_written = decrypt_block(curr_in, boost::get<1>( buffers_sizes ), curr_out, boost::get<0>( buffers_sizes ) );
			assert( data_written==boost::get<0>( buffers_sizes ) );
			(void)data_written;

			curr_in+= boost::get<1>( buffers_sizes );
			curr_out+= boost::get<0>( buffers_sizes );
		}

		assert(curr_out==out_buffer+out_buffer_len);

		return out_buffer_len;
	}




	size_t dstu4145_t::decrypt_block(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len){

		STCRYPT_CHECK(data);
		STCRYPT_CHECK(out_buffer);

		auto const& buffers_sizes = this->buffers_sizes();
		assert( boost::get<0>( buffers_sizes )==sizeof(plaintext_block_type) );

		if(out_buffer_len!=boost::get<0>( buffers_sizes )) STCRYPT_UNIMPLEMENTED();

		if(data_len!=boost::get<1>( this->buffers_sizes() ) ) STCRYPT_UNEXPECTED();

		if( !m_private_part )
			STCRYPT_THROW_EXCEPTION(exception::bad_key());

		DWORD buffer_size = boost::numeric_cast<DWORD>(out_buffer_len);
		STCRYPT_CHECK_CRYPTO( AsymmetricDecryption(
			m_ctx, 
			const_cast<private_part_type*>(&(*m_private_part)), 
			const_cast<BYTE*>( data ),
			data_len,
			reinterpret_cast<plaintext_block_type*>( const_cast<BYTE*>(out_buffer) ) ) );

		return sizeof(plaintext_block_type);
	}

	dstu4145_t::dstu4145_t(tag_import const&, boost::optional<private_part_type const &> const& private_part, boost::optional<public_part_type const&> const& public_part){
		assert(public_part);
		if( !public_part ) STCRYPT_UNEXPECTED();

		if( private_part ){
			m_private_part = boost::in_place();
			std::copy( boost::begin(*private_part), boost::end(*private_part), boost::begin(*m_private_part) );
		}

		m_public_part = *public_part ;

		STCRYPT_CHECK_CRYPTO(DSTU4145AcquireContext(&m_ctx));
		try{
			m_std_mode = 9; //TODO: rationale?
			STCRYPT_CHECK_CRYPTO(DSTU4145InitStd(m_ctx,m_std_mode));
		}catch(...){
			STCRYPT_DEBUG_CHECK_CRYPTO(DSTU4145DestroyContext(m_ctx));
			throw;			
		}
	}

	dstu4145_t::dstu4145_t(tag_generate const&)
		: m_ctx( 0 )
	{
		STCRYPT_CHECK_CRYPTO(DSTU4145AcquireContext(&m_ctx));
		try{
			m_private_part = boost::in_place();
			m_std_mode = 9; //TODO: rationale?

			STCRYPT_CHECK_CRYPTO(DSTU4145InitStd(m_ctx,m_std_mode));
			STCRYPT_CHECK_CRYPTO(DSTU4145GenKeys(m_ctx,&(*m_private_part), &m_public_part)); 

		}catch(...){
			STCRYPT_DEBUG_CHECK_CRYPTO(DSTU4145DestroyContext(m_ctx));
			throw;			
		}

	}


	dstu4145_t::~dstu4145_t(){
		STCRYPT_DEBUG_CHECK_CRYPTO(DSTU4145DestroyContext(m_ctx));
	}

}
//================================================================================================================================================
