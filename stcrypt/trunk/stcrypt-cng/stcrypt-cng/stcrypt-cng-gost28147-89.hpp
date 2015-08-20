//================================================================================================================================================
// FILE: stcrypt-cng-gost28147-89.h
// (c) GIE 2010-08-16  19:33
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_GOST28147_89_2010_08_16_19_33
#define H_GUARD_STCRYPT_CNG_GOST28147_89_2010_08_16_19_33
//================================================================================================================================================
#pragma once
//================================================================================================================================================

#include "stcrypt-cng-symmetric-provider.hpp"
#include "util-cng-obj-alloc.hpp"
//================================================================================================================================================
namespace stcrypt {

	//
	// BCRYPT_CHAIN_MODE_ECB -- map to GOST28147_MODE_SIMPLE_REPLACE
	// BCRYPT_CHAIN_MODE_CFB -- map to GOST28147_MODE_GAMMING
	// BCRYPT_CHAIN_MODE_CBC -- map to GOST28147_MODE_FEEDBACK_GAMMING
	//
	struct cng_gost28147_class 
		: cng_symmetric_class_op_i
	{
		cng_gost28147_class();
		~cng_gost28147_class(){}

		virtual void destroy_self(){delete this;}


		virtual void set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags);
		virtual void get_prop(LPCWSTR const prop_name,  PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags);

		virtual cng_symmetric_object_op_i_ptr create(BYTE * const object_buffer, ULONG const object_buffer_size, PUCHAR const secret, ULONG const secret_size);


		virtual DWORD symmetric_object_length();
		virtual DWORD block_length();
		virtual void key_lengths(BCRYPT_KEY_LENGTHS_STRUCT& info);
		virtual DWORD key_length()const;
		virtual DWORD key_strength();

	private:
		typedef cng_symmetric_object_op_i_ptr (cng_gost28147_class::*create_func_t)(BYTE * const object_buffer, ULONG const object_buffer_size, PUCHAR const secret, ULONG const secret_size);
		typedef DWORD (cng_gost28147_class::*object_length_func_t)();

		void set_prop_chaining_mode_(wchar_t const*const chaining_mode_name);


		// feedback gamming
		void feedback_gamming__select_();
		cng_symmetric_object_op_i_ptr feedback_gamming__create_(BYTE * const object_buffer, ULONG const object_buffer_size, PUCHAR const secret, ULONG const secret_size);
		DWORD feedback_gamming__object_length_();


		create_func_t			m_impl_create;
		object_length_func_t	m_impl_object_length;
	};



}
//================================================================================================================================================
#endif
//================================================================================================================================================
