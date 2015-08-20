//================================================================================================================================================
// FILE: stcrypt-gost28147_mac.h
// (c) GIE 2010-01-01  16:39
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_GOST28147_MAC_2010_01_01_16_39
#define H_GUARD_STCRYPT_GOST28147_MAC_2010_01_01_16_39
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-key-gost28147_89.hpp"
#include "stcrypt-hash-base.hpp"
#include "stcrypt-cryptolib.hpp"
#include "GOST_28147_89.h"
//================================================================================================================================================
namespace stcrypt {

	struct gost_28147_mac_t 
		: hash_impl_base_t
	{
		typedef gost_28147_mac_t this_type;
		typedef TBLOCK64		 hash_type;

		explicit gost_28147_mac_t(boost::intrusive_ptr<gost28147_89_family_key_t> const & key);
		~gost_28147_mac_t();
		
		virtual void hash_data(BYTE const * const data, size_t const len);
		virtual DWORD get_alg_id();
		virtual DWORD get_hash_size();
		virtual void  get_hash_value(BYTE* const data, DWORD const datalen);
		virtual void  set_hash_value(BYTE const * const data){STCRYPT_UNIMPLEMENTED();}
		virtual boost::intrusive_ptr<hash_impl_base_t> create_new();
		virtual boost::intrusive_ptr<hash_impl_base_t> clone();

	private: 
		void init(); 
		size_t buffer_free_()const throw(){ return sizeof(m_buffer)-m_buffer_filled; }
		void   push_back_to_buffer_(BYTE const* data, size_t const size);
		inline void   flush_full_buffer_();
		inline void   flush_buffer_();

		boost::intrusive_ptr<gost28147_89_family_key_t> m_key;
		bool m_initialized;
		bool m_finilized;
		//cryptolib_context_t	m_ctx;
		Gost28147 m_alg;
		hash_type m_hash_value;
		TBLOCK64	m_buffer;
		size_t		m_buffer_filled;
	};

}
//================================================================================================================================================
#endif
//================================================================================================================================================
