//================================================================================================================================================
// FILE: stcrypt-gost28147_mac.cpp
// (c) GIE 2010-01-01  16:39
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-gost28147_mac.hpp"
//================================================================================================================================================
namespace stcrypt {

	gost_28147_mac_t::gost_28147_mac_t(boost::intrusive_ptr<gost28147_89_family_key_t> const& key)
		: m_initialized(false)
		, m_finilized(false)
		, m_key (key)
		, m_buffer_filled(0)
	{
		if( !m_key ) STCRYPT_THROW_EXCEPTION(exception::bad_key());

// 		DWORD const r = GOST28147AcquireContext(&m_ctx);
// 		if(r)STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(r));

	}

	gost_28147_mac_t::~gost_28147_mac_t(){
// 		DWORD const r = GOST28147DestroyContext(m_ctx);
// 		assert(!r);
	}

	boost::intrusive_ptr<hash_impl_base_t> gost_28147_mac_t::clone(){
		boost::intrusive_ptr<gost_28147_mac_t> cloned (new gost_28147_mac_t(m_key) );

		if(m_finilized){
			cloned->m_finilized = true;
			memcpy_s( &(cloned->m_hash_value), sizeof(cloned->m_hash_value),   &m_hash_value, sizeof(m_hash_value));
		} else if(m_initialized) {
			//cloned->init();
			cloned->m_alg.copy_state_from(m_alg);
			memcpy_s( &(cloned->m_buffer), sizeof(cloned->m_buffer),   &m_buffer, sizeof(m_buffer));
			cloned->m_buffer_filled = m_buffer_filled;
			cloned->m_initialized = true;
		}
		
		return cloned;
	}

	void gost_28147_mac_t::init()
	{
		if( m_initialized  ) return;

		gost28147_89_family_key_t::key_blob_type const& key_data = m_key->get_key_data();

		TBLOCK256* const key256 = const_cast<TBLOCK256*>( &key_data.m_key->data );
		TGOSTDKE* const dke = key_data.m_dke ? const_cast<TGOSTDKE*>( &key_data.m_dke->data ) : 0;

		m_alg.Init(GOST28147_MODE_MAC, key256, dke);
// 		DWORD const r = GOST28147InitMAC(m_ctx, dke, key256);
// 		if(r)STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(r));

		m_initialized = true;

	}

	void  gost_28147_mac_t::push_back_to_buffer_(BYTE const* data, size_t const size){
		assert( buffer_free_()>=size );
		std::copy(data, data+size, m_buffer+m_buffer_filled);
		m_buffer_filled+=size;
	}

	void   gost_28147_mac_t::flush_full_buffer_(){
		assert(buffer_free_()==0);
		flush_buffer_();
	}
	void   gost_28147_mac_t::flush_buffer_(){
		if(m_buffer_filled!=0){
			m_alg.ProcessBuffer(const_cast<void*>(reinterpret_cast<void const *>( m_buffer )), static_cast<DWORD>( m_buffer_filled ) );
			//STCRYPT_CHECK_CRYPTO( GOST28147ProcessBuffer(m_ctx, const_cast<void*>(reinterpret_cast<void const *>( m_buffer )), static_cast<DWORD>( m_buffer_filled ) ) );
			m_buffer_filled=0;
		}
	}



	void gost_28147_mac_t::hash_data(BYTE const * const data, size_t const len){
		if(m_finilized) STCRYPT_THROW_EXCEPTION(exception::hash_finilized());
		init();


		BYTE const * curr = data;
		size_t data_left_to_process = len;
		while(data_left_to_process!=0){
			size_t const transfer_to_buffer_count = (std::min)(buffer_free_(), data_left_to_process);
			assert(curr+transfer_to_buffer_count<=data+len);
			push_back_to_buffer_(curr,transfer_to_buffer_count);
			
			if(buffer_free_()==0)
				flush_full_buffer_();

			curr+=transfer_to_buffer_count;
			data_left_to_process-=transfer_to_buffer_count;
		}


// 		DWORD const r = GOST28147ProcessBuffer(m_ctx, const_cast<void*>(reinterpret_cast<void const *>( data )), static_cast<DWORD>( len ) );
// 		if(r)STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(r)
	}

	DWORD gost_28147_mac_t::get_alg_id(){
		return CALG_ID_G28147_89_MAC;
	}

	DWORD gost_28147_mac_t::get_hash_size(){
		return sizeof(hash_type);
	}

	void  gost_28147_mac_t::get_hash_value(BYTE* const data, DWORD const datalen){
		assert(datalen==sizeof(hash_type));
		assert(data);

		if(!m_finilized) {
			flush_buffer_();
			m_alg.GetMAC(reinterpret_cast<unsigned int*>(&m_hash_value));
// 			DWORD const r = GOST28147GetMAC(m_ctx, &m_hash_value);
// 			if(r)STCRYPT_THROW_EXCEPTION(exception::cryptolib_error() << exception::cryptolib_einfo(r)
			m_finilized = true;
		}

		memcpy(data, &m_hash_value, sizeof(hash_type));
	}

	boost::intrusive_ptr<hash_impl_base_t> gost_28147_mac_t::create_new(){
		return boost::intrusive_ptr<hash_impl_base_t>( new this_type(m_key) );
	}


	boost::intrusive_ptr<hash_impl_base_t> create_gost_28147_mac(key_base_ptr const& key){
		return boost::intrusive_ptr<hash_impl_base_t>( new gost_28147_mac_t( boost::dynamic_pointer_cast<gost28147_89_family_key_t>(key) ) );
	}


}
//================================================================================================================================================
