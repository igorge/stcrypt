//================================================================================================================================================
// FILE: stcrypt-dstu4145-cipher.h
// (c) GIE 2010-01-05  18:01
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_DSTU4145_CIPHER_2010_01_05_18_01
#define H_GUARD_STCRYPT_DSTU4145_CIPHER_2010_01_05_18_01
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-asymmetric-base.hpp"
#include "stcrypt-cryptolib.hpp"
//================================================================================================================================================
namespace stcrypt {

	struct dstu_4145_cryptoapi_key_t;

	struct dstu4145_cipher_t 
		: asymmetric_cipher_base_t
		, notify_key_destroyed_i
	{

		explicit dstu4145_cipher_t(dstu_4145_cryptoapi_key_t * const key);
		~dstu4145_cipher_t();

		virtual size_t encrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len);
		virtual size_t decrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len);
		virtual std::pair<size_t,size_t> buffers_sizes();
		virtual size_t sign_size();
		virtual void sign(BYTE const* const data, size_t const data_size, BYTE * const sign_buffer, size_t const sign_buffer_size);
		virtual bool verify(BYTE const* const data, size_t const data_size, BYTE const * const sign_buffer, size_t const sign_buffer_sisze);

		virtual void notify_key_destroyed_i::notify();

	private:
		void reset_key_();

	private:
		dstu_4145_cryptoapi_key_t * m_key;
		CL_CONTEXT					m_ctx;
	};

}
//================================================================================================================================================
#endif
//================================================================================================================================================
