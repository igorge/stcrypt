//================================================================================================================================================
// FILE: strcypt-cng-dstu4145.h
// (c) GIE 2010-08-25  16:30
//
//================================================================================================================================================
#ifndef H_GUARD_STRCYPT_CNG_DSTU4145_2010_08_25_16_30
#define H_GUARD_STRCYPT_CNG_DSTU4145_2010_08_25_16_30
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-cng-asymmetric-provider.hpp"
//================================================================================================================================================
namespace stcrypt {

	struct cng_dstu4145_class 
		: cng_asymmetric_class_op_i
	{
		virtual void destroy_self(){delete this;}
		virtual void set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags){
			STCRYPT_UNIMPLEMENTED();
		}

		virtual void get_prop(LPCWSTR const prop_name,  PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags);
		virtual cng_asymmetric_object_handle_ptr_t generate_key_pair(ULONG const key_bit_length, ULONG const dwFlags);
		virtual cng_asymmetric_object_handle_ptr_t import_key_pair(LPCWSTR const pszBlobType, PUCHAR const pbInput, ULONG const cbInput);


		DWORD cng_padding_schemes(){ return 0; /*BCRYPT_SUPPORTED_PAD_PKCS1_ENC;*/ /*BCRYPT_SUPPORTED_PAD_ROUTER;*/ /*TODO*/ }
	};

}
//================================================================================================================================================
#endif
//================================================================================================================================================
