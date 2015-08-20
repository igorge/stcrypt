//================================================================================================================================================
// FILE: strcypt-cng-gost34311.cpp
// (c) GIE 2010-08-10  15:09
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "strcypt-cng-gost34311.hpp"
#include "util-cng-get-prop.hpp"
#include "util-cng-obj-alloc.hpp"
#include "stcrypt-gost34311-impl.hpp"
//================================================================================================================================================
namespace stcrypt {

	struct cng_gost34311_object
		: cng_hash_object_op_i
	{
		typedef gost_34311_impl_t::hash_type hash_value_type;

		virtual void hash_data(UCHAR const * const data, ULONG const size);
		virtual void finalize_and_get_result(UCHAR * const buffer, ULONG const buffer_size);

		virtual void destroy_self(){
			this->~cng_gost34311_object();
		}

		cng_gost34311_object()
			: m_finalized ( false )
		{}
		~cng_gost34311_object(){
		}
	private:
		gost_34311_impl_t m_impl;
		bool	m_finalized;
	};




	void cng_gost34311_object::hash_data(UCHAR const * const data, ULONG const size){
		if( m_finalized ) STCRYPT_THROW_EXCEPTION( exception::hash_finilized() );

		m_impl.hash_data(data, size);
	}

	void cng_gost34311_object::finalize_and_get_result(UCHAR * const buffer, ULONG const buffer_size){
		if( m_finalized ) STCRYPT_THROW_EXCEPTION( exception::hash_finilized() );

		if( buffer_size!=sizeof(hash_value_type) ) STCRYPT_THROW_EXCEPTION( exception::bad_len() );
		m_impl.get_hash_value( *reinterpret_cast<hash_value_type*>(buffer) );

		m_finalized = true;
	}


	cng_hash_object_op_i_ptr cng_gost34311_class::create(BYTE * const object_buffer, ULONG const object_buffer_size){

		void * const place = aligned_ptr_in_buffer<cng_gost34311_object>(object_buffer, object_buffer_size);
		if(!place) STCRYPT_THROW_EXCEPTION( exception::more_data() << exception::data_size_einfo( this->hash_object_length() ) );

		return cng_hash_object_op_i_ptr( new(place) cng_gost34311_object() );
	}


	void cng_gost34311_class::get_prop(LPCWSTR const prop_name,  PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags){
		assert(prop_name);

		if(flags) STCRYPT_THROW_EXCEPTION( exception::badflags() << exception::flags_einfo(flags) );

		if( wcscmp(BCRYPT_HASH_BLOCK_LENGTH, prop_name)==0 ){

			prop_val_size = cng_get_prop_impl( sizeof( decltype(this->hash_block_length() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
				auto const block_length = this->hash_block_length();
				auto const r = memcpy_s( dest, size, &block_length, sizeof(block_length) );	assert(!r);
			});

		} else if( wcscmp(BCRYPT_OBJECT_LENGTH, prop_name)==0 ){

			prop_val_size = cng_get_prop_impl( sizeof( decltype(this->hash_object_length() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
				auto const object_length = this->hash_object_length();
				auto const r = memcpy_s( dest, size, &object_length , sizeof(object_length ) );	assert(!r);
			});


		} else if( wcscmp(BCRYPT_HASH_LENGTH, prop_name)==0 ){

			prop_val_size = cng_get_prop_impl( sizeof( decltype(this->hash_length() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
				auto const hash_length = this->hash_length();
				auto const r = memcpy_s( dest, size, &hash_length , sizeof(hash_length ) );	assert(!r);
			});

		} else {
			STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
		}
	}


	DWORD cng_gost34311_class::hash_object_length(){
		return buffer_for_obj<cng_gost34311_object>::value;
	}


	DWORD cng_gost34311_class::hash_length(){
		return sizeof(cng_gost34311_object::hash_value_type);
	}

}
//================================================================================================================================================
