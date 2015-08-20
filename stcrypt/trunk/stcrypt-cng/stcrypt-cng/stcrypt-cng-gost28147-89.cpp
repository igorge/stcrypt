//================================================================================================================================================
// FILE: stcrypt-cng-gost28147-89.cpp
// (c) GIE 2010-08-16  19:33
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "../../stcrypt-csp/stcrypt-key-blob.hpp"
#include "stcrypt-exceptions.hpp"
#include "stcrypt-crypto-alg-ids.h"
#include "stcrypt-cng-gost28147-89.hpp"
#include "util-cng-get-prop.hpp"
#include "util-bittest.hpp"

#include "GOST_28147_89.h"

#include <boost/array.hpp>
#include <boost/utility/in_place_factory.hpp>
#include <boost/optional.hpp>
//================================================================================================================================================
namespace stcrypt {

	template <class SelfT>
	struct cng_gost28147_object 
		: cng_symmetric_object_op_i
	{
		cng_gost28147_object()
			: m_state( s_init )
		{}

		virtual void destroy_self(){
			this->~cng_gost28147_object();
		}

		virtual ULONG calc_encrypt_buffer_size(ULONG const input_size){
			if( input_size==0 ) STCRYPT_UNEXPECTED();

			return ( input_size%CALG_ID_G28147_89_BLOCKSIZE==0?input_size:( (input_size/CALG_ID_G28147_89_BLOCKSIZE+1)*CALG_ID_G28147_89_BLOCKSIZE) );

		}
		virtual ULONG calc_decrypt_buffer_size(ULONG const input_size){
			if( input_size==0 ) STCRYPT_UNEXPECTED();

			return ( input_size%CALG_ID_G28147_89_BLOCKSIZE==0?input_size:( (input_size/CALG_ID_G28147_89_BLOCKSIZE+1)*CALG_ID_G28147_89_BLOCKSIZE) );
		}

		DWORD block_length()const{
			return CALG_ID_G28147_89_BLOCKSIZE;
		}

		template <class LazyGetOutputBuffer>
		ULONG encrypt_(PUCHAR const input, ULONG const input_size, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags, LazyGetOutputBuffer const& get_output){

			if( iv && iv_size!=this->block_length() ) STCRYPT_THROW_EXCEPTION( exception::invalid_iv_size() );

			bool const do_pad = test_mask<decltype(flags)>( flags, BCRYPT_BLOCK_PADDING );
			if( input_size%this->block_length()!=0 && !do_pad ) STCRYPT_THROW_EXCEPTION( exception::bad_data() << exception::bad_data_einfo(input_size) );

			auto const required_output_buffer_size = this->calc_encrypt_buffer_size( input_size );
			if( output_size<required_output_buffer_size ) STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair(input_size, required_output_buffer_size) ) );


			state_select:
			switch( m_state ) {

				case s_init: {

					if(iv){ 
						self_()->init_encryption_(iv, iv_size);
					} else {
						self_()->init_encryption_();
					}

					m_state = s_encrypting;
					break;

				} case s_encrypting: {
					if( !iv ){
						// m_alg.stcrypt_reset_sync();
					} else {
						if( !m_alg.stcrypt_set_sync(iv, iv_size) ) STCRYPT_UNEXPECTED();
					}
					break;

				} case s_decrypting: {
					m_state = s_init;
					goto state_select;
					break;				

				} default: {
					STCRYPT_UNEXPECTED();
				}
			} // end switch

			auto const output = get_output();

			if(do_pad){
				auto const fill_w_zero_count = required_output_buffer_size-input_size;
				
				if(fill_w_zero_count) {
					std::fill_n(static_cast<BYTE*>(output)+input_size,fill_w_zero_count, 0);
				}
			}

			m_alg.ProcessBuffer(output, required_output_buffer_size);
			return required_output_buffer_size;
		}



		template <class LazyGetOutputBuffer>
		ULONG decrypt_(PUCHAR const input, ULONG const input_size, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags, LazyGetOutputBuffer const& get_output){

			if(iv && iv_size!=this->block_length()) STCRYPT_THROW_EXCEPTION( exception::invalid_iv_size() );

			bool const do_pad = test_mask<decltype(flags)>( flags, BCRYPT_BLOCK_PADDING );
			if( input_size%this->block_length()!=0 ) STCRYPT_THROW_EXCEPTION( exception::bad_data() << exception::bad_data_einfo(input_size) );

			auto const required_output_buffer_size = this->calc_decrypt_buffer_size( input_size );
			if( output_size<required_output_buffer_size ) STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair(input_size, required_output_buffer_size) ) );


			state_select:
			switch( m_state ) {

				case s_init: {

					if(iv){ 
						self_()->init_decryption_(iv, iv_size);
					} else {
						self_()->init_decryption_();
					}

					m_state = s_decrypting;
					break;

				} case s_decrypting: {
					if( !iv ){
						// m_alg.stcrypt_reset_sync();
					} else {
						if( !m_alg.stcrypt_set_sync(iv, iv_size) ) STCRYPT_UNEXPECTED();
					}
					break;

				} case s_encrypting: {
					m_state = s_init;
					goto state_select;
					break;				

				} default: {
					STCRYPT_UNEXPECTED();
				}
			} // end switch

			auto const output = get_output();

			m_alg.ProcessBuffer(output, required_output_buffer_size);
			return required_output_buffer_size;
		}

		virtual ULONG encrypt(PUCHAR const input, ULONG const input_size, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags){
			return this->encrypt_(input, input_size, output_size, iv, iv_size, flags, [input](){ return input; });
		}

		virtual ULONG encrypt(PUCHAR const input, ULONG const input_size, PUCHAR const output, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags){
			return this->encrypt_(input, input_size, output_size, iv, iv_size, flags, [=]()->PUCHAR{ 
				assert(input);
				assert(output);
				assert( input_size<=output_size );
				auto const r = memcpy_s(output, output_size, input, input_size); assert(r==0); (void)r;
				return output;
			});
		}


		virtual ULONG decrypt(PUCHAR const input, ULONG const input_size, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags){
			return this->decrypt_(input, input_size, output_size, iv, iv_size, flags, [input](){ return input; });
		}
		virtual ULONG decrypt(PUCHAR const input, ULONG const input_size, PUCHAR const output, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags){
			return this->decrypt_(input, input_size, output_size, iv, iv_size, flags, [=]()->PUCHAR{ 
				assert(input);
				assert(output);
				assert( input_size<=output_size );
				auto const r = memcpy_s(output, output_size, input, input_size); assert(r==0); (void)r;
				return output;
			});
		}
	private:

		enum state_t {s_init, s_encrypting, s_decrypting};

		state_t	m_state;

		SelfT* self_(){ return static_cast<SelfT*>(this); }

	protected:
		cryptoapi_key_blob_t	m_key_data;
		Gost28147				m_alg;
	};

	struct cng_gost28147_89_gamma_cbc_object
		: cng_gost28147_object<cng_gost28147_89_gamma_cbc_object> 
	{
		friend cng_gost28147_object<cng_gost28147_89_gamma_cbc_object> ;

		cng_gost28147_89_gamma_cbc_object(PUCHAR const secret, ULONG const secret_size)
		{
			if( m_key_data.key_component_size()!=secret_size ) STCRYPT_THROW_EXCEPTION( exception::bad_key() );
			m_key_data.fill_key_data_from_key_material(secret, secret_size, true, false, false);
		}

		~cng_gost28147_89_gamma_cbc_object(){

		}

		virtual void set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags){

			if( wcscmp(BCRYPT_INITIALIZATION_VECTOR , prop_name)==0 ){
				set_creation_iv_(prop_val, prop_val_size);
			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
			}

		}
		virtual void get_prop(LPCWSTR const prop_name,  PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags){
			assert(prop_name);

			if(flags) STCRYPT_THROW_EXCEPTION( exception::badflags() << exception::flags_einfo(flags) );

			if( wcscmp(BCRYPT_BLOCK_LENGTH, prop_name)==0 ){

				prop_val_size = cng_get_prop_impl( sizeof( decltype(this->block_length() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
					auto const block_length = this->block_length();
					auto const r = memcpy_s( dest, size, &block_length, sizeof(block_length) );	assert(!r);
				});

			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
			}
		}

	private:
		boost::optional < boost::array<UCHAR, CALG_ID_G28147_89_BLOCKSIZE> >  m_creation_iv;	//TODO:
	private:
		
		void set_creation_iv_(PUCHAR const iv, ULONG const size){
			
			m_creation_iv = boost::in_place();
			
			if( size!=m_creation_iv->size() ) STCRYPT_UNEXPECTED();

			if( memcpy_s(m_creation_iv->data(), m_creation_iv->size(), iv, size)!=0) STCRYPT_UNEXPECTED();
		}

		void init_encryption_(PUCHAR const iv, ULONG const iv_size){
			//assert(false); //dbg

			assert(iv_size==CALG_ID_G28147_89_BLOCKSIZE);

			if(!m_key_data.m_key){STCRYPT_UNEXPECTED();}

			TBLOCK256* const key256 = const_cast<TBLOCK256*>( &m_key_data.m_key->data );
			TGOSTDKE* const dke = m_key_data.m_dke ? const_cast<TGOSTDKE*>( &m_key_data.m_dke->data ) : 0;

			m_alg.Init(GOST28147_MODE_FEEDBACK_GAMMING, key256, dke, true, iv);
		}
		void init_encryption_(){
			if(!m_key_data.m_key){STCRYPT_UNEXPECTED();}

			TBLOCK256* const key256 = const_cast<TBLOCK256*>( &m_key_data.m_key->data );
			TGOSTDKE* const dke = m_key_data.m_dke ? const_cast<TGOSTDKE*>( &m_key_data.m_dke->data ) : 0;

			//dbg
// 			size_t key_crc = 0;
// 			for(unsigned int i =0; i<sizeof(TBLOCK256); ++i ){
// 				key_crc+=((BYTE*)key256)[i];
// 			}

			m_alg.Init(GOST28147_MODE_FEEDBACK_GAMMING, key256, dke, true);
		}
		void init_decryption_(PUCHAR const iv, ULONG const iv_size){
			//assert(false); //dbg

			assert(iv_size==CALG_ID_G28147_89_BLOCKSIZE);

			if(!m_key_data.m_key){STCRYPT_UNEXPECTED();}

			TBLOCK256* const key256 = const_cast<TBLOCK256*>( &m_key_data.m_key->data );
			TGOSTDKE* const dke = m_key_data.m_dke ? const_cast<TGOSTDKE*>( &m_key_data.m_dke->data ) : 0;

			m_alg.Init(GOST28147_MODE_FEEDBACK_GAMMING, key256, dke, false, iv);
		}
		void init_decryption_(){
			if(!m_key_data.m_key){STCRYPT_UNEXPECTED();}

			TBLOCK256* const key256 = const_cast<TBLOCK256*>( &m_key_data.m_key->data );
			TGOSTDKE* const dke = m_key_data.m_dke ? const_cast<TGOSTDKE*>( &m_key_data.m_dke->data ) : 0;

			//dbg
// 			size_t key_crc = 0;
// 			for(unsigned int i =0; i<sizeof(TBLOCK256); ++i ){
// 				key_crc+=((BYTE*)key256)[i];
// 			}

			m_alg.Init(GOST28147_MODE_FEEDBACK_GAMMING, key256, dke, false);
		}
	};


	void cng_gost28147_class::set_prop_chaining_mode_(wchar_t const*const chaining_mode_name){
		if( wcscmp(BCRYPT_CHAIN_MODE_CBC, chaining_mode_name)==0 ){
			this->feedback_gamming__select_();
		} else {
			STCRYPT_THROW_EXCEPTION( exception::invalid_property_value() << exception::prop_value_einfo(chaining_mode_name) );
		}

	}


	void cng_gost28147_class::set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags){
		assert(prop_name);
		assert(prop_val);

		if(flags) STCRYPT_THROW_EXCEPTION( exception::badflags() << exception::flags_einfo(flags) );

		if( wcscmp(BCRYPT_CHAINING_MODE, prop_name)==0 ){
			if(prop_val_size%sizeof(wchar_t)!=0) STCRYPT_THROW_EXCEPTION( exception::bad_data() );
			set_prop_chaining_mode_( reinterpret_cast<wchar_t const*const>(prop_val) );
		} else {
			STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
		}


	}


	void cng_gost28147_class::get_prop(LPCWSTR const prop_name,  PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags){
		assert(prop_name);

		if(flags) STCRYPT_THROW_EXCEPTION( exception::badflags() << exception::flags_einfo(flags) );

		if( wcscmp(BCRYPT_OBJECT_LENGTH, prop_name)==0 ){

			prop_val_size = cng_get_prop_impl( sizeof( decltype(this->symmetric_object_length() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
				auto const obj_length = this->symmetric_object_length();
				auto const r = memcpy_s( dest, size, &obj_length, sizeof(obj_length) );	assert(!r);
			});

		} else if( wcscmp(BCRYPT_BLOCK_LENGTH, prop_name)==0 ){

			prop_val_size = cng_get_prop_impl( sizeof( decltype(this->block_length() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
				auto const block_length = this->block_length();
				auto const r = memcpy_s( dest, size, &block_length, sizeof(block_length) );	assert(!r);
			});
		
		} else if( wcscmp(BCRYPT_KEY_LENGTHS, prop_name)==0 ){

			prop_val_size = cng_get_prop_impl( sizeof( BCRYPT_KEY_LENGTHS_STRUCT ) , prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
				assert(size>=sizeof(BCRYPT_KEY_LENGTHS_STRUCT));
				BCRYPT_KEY_LENGTHS_STRUCT& key_lengths = *reinterpret_cast<BCRYPT_KEY_LENGTHS_STRUCT*>(dest);
				this->key_lengths(key_lengths);
			});

		} else if( wcscmp(BCRYPT_KEY_LENGTH, prop_name)==0 ){

			prop_val_size = cng_get_prop_impl( sizeof( decltype(this->key_length() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
				auto const v = this->key_length();
				auto const r = memcpy_s( dest, size, &v, sizeof(v) );	assert(!r);
			});

		} else if( wcscmp(BCRYPT_KEY_STRENGTH , prop_name)==0 ){

			prop_val_size = cng_get_prop_impl( sizeof( decltype(this->key_strength() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
				auto const block_length = this->key_strength();
				auto const r = memcpy_s( dest, size, &block_length, sizeof(block_length) );	assert(!r);
			});

		} else {
			STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
		}
	}


	void cng_gost28147_class::feedback_gamming__select_(){
		m_impl_create = &cng_gost28147_class::feedback_gamming__create_;
		m_impl_object_length = &cng_gost28147_class::feedback_gamming__object_length_;
	}


	cng_symmetric_object_op_i_ptr cng_gost28147_class::feedback_gamming__create_(BYTE * const object_buffer, ULONG const object_buffer_size, PUCHAR const secret, ULONG const secret_size){
		void * const place = aligned_ptr_in_buffer<cng_gost28147_89_gamma_cbc_object>(object_buffer, object_buffer_size);
		if(!place) STCRYPT_THROW_EXCEPTION( exception::more_data() << exception::data_size_einfo( this->feedback_gamming__object_length_() ) );

		return cng_symmetric_object_op_i_ptr( new(place) cng_gost28147_89_gamma_cbc_object(secret, secret_size) );
	}

	void cng_gost28147_class::key_lengths(BCRYPT_KEY_LENGTHS_STRUCT& info){

		info.dwMinLength = info.dwMaxLength = sizeof( TBLOCK256 ) * 8;
		info.dwIncrement = 0;

	}

	DWORD cng_gost28147_class::key_strength(){
		return sizeof( TBLOCK256 ) * 8;
	}

	DWORD cng_gost28147_class::key_length()const{
		return sizeof( TBLOCK256 ) * 8;
	}



	DWORD cng_gost28147_class::feedback_gamming__object_length_(){
		return buffer_for_obj<cng_gost28147_89_gamma_cbc_object>::value;
	}

	DWORD cng_gost28147_class::block_length(){
		return CALG_ID_G28147_89_BLOCKSIZE;
	}

	
	DWORD cng_gost28147_class::symmetric_object_length(){
		assert(m_impl_object_length);

		return (this->*m_impl_object_length)();
	}


	cng_gost28147_class::cng_gost28147_class(){
		this->feedback_gamming__select_();
	}
	
	cng_symmetric_object_op_i_ptr cng_gost28147_class::create(BYTE * const object_buffer, ULONG const object_buffer_size, PUCHAR const secret, ULONG const secret_size){
		assert(m_impl_create);

		return (this->*m_impl_create)(object_buffer, object_buffer_size, secret, secret_size);
	}


}
//================================================================================================================================================
