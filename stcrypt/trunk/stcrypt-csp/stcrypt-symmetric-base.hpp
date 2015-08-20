//================================================================================================================================================
// FILE: stcrypt-symmetric-base.h
// (c) GIE 2009-11-06  14:16
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_SYMMETRIC_BASE_2009_11_06_14_16
#define H_GUARD_STCRYPT_SYMMETRIC_BASE_2009_11_06_14_16
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-hash-base.hpp"
#include "util-atomic-counter.hpp"

#include "boost/intrusive_ptr.hpp"
//================================================================================================================================================
namespace stcrypt {

	/*! \brief base class for all symmetric ciphers
	 *
	 */
	struct symmetric_block_cipher_base_t 
		: atomic_counter_def_impl_t
	{
		//! \result size of encrypted\decrypted data
		virtual size_t process_data(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final)=0; 
		
		//! \brief checks input buffer\data sizes for validity
		virtual void validate_buffer(BYTE const * const data, size_t const data_len, size_t const buffer_len, bool const final)=0; 

		//! \result optimal buffer size for data_size size of data
		virtual size_t suggest_buffer_size(size_t const data_size)=0;

		virtual boost::intrusive_ptr<symmetric_block_cipher_base_t> clone()=0;

	};
	typedef boost::intrusive_ptr<symmetric_block_cipher_base_t> symmetric_block_cipher_base_ptr;


	/*! \brief Info and factory class for ciphers
	 *
	 */
	struct symmetric_block_cipher_info_block_i 
		: atomic_counter_def_impl_t
	{
		virtual size_t block_size()const=0;
		virtual symmetric_block_cipher_base_ptr create_encrypt()=0;
		virtual symmetric_block_cipher_base_ptr create_decrypt()=0;
	};
	typedef boost::intrusive_ptr<symmetric_block_cipher_info_block_i> symmetric_block_cipher_info_block_ptr;

}
//================================================================================================================================================
#endif
//================================================================================================================================================
