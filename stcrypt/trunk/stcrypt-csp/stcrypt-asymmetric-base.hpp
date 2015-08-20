//================================================================================================================================================
// FILE: stcrypt-asymmetric-base.h
// (c) GIE 2010-01-09  18:14
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_ASYMMETRIC_BASE_2010_01_09_18_14
#define H_GUARD_STCRYPT_ASYMMETRIC_BASE_2010_01_09_18_14
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "util-atomic-counter.hpp"

#include "boost/intrusive_ptr.hpp"
#include <utility>
//================================================================================================================================================
namespace stcrypt {

	struct notify_key_destroyed_i {
		virtual void notify()=0;
	};

	/*! \brief base class for all symmetric ciphers
	 *
	 */
	struct asymmetric_cipher_base_t 
		: atomic_counter_def_impl_t
	{
		virtual size_t encrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len)=0;
		virtual size_t decrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len)=0;

		//! \result <in_buffer_size, out_buffer_size>
		virtual std::pair<size_t,size_t> buffers_sizes()=0;
		virtual size_t sign_size()=0;
		virtual void sign(BYTE const* const data, size_t const data_size, BYTE * const sign_buffer, size_t const sign_buffer_size)=0;
		virtual bool verify(BYTE const* const data, size_t const data_size, BYTE const * const sign_buffer, size_t const sign_buffer_sisze)=0;


	};
	typedef boost::intrusive_ptr<asymmetric_cipher_base_t> asymmetric_cipher_base_ptr;


}
//================================================================================================================================================
#endif
//================================================================================================================================================
