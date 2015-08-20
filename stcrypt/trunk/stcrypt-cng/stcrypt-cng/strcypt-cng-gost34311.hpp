//================================================================================================================================================
// FILE: strcypt-cng-gost34311.h
// (c) GIE 2010-08-10  15:09
//
//================================================================================================================================================
#ifndef H_GUARD_STRCYPT_CNG_GOST34311_2010_08_10_15_09
#define H_GUARD_STRCYPT_CNG_GOST34311_2010_08_10_15_09
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "strcypt-cng-hash-provider.hpp"
//================================================================================================================================================
namespace stcrypt {

	struct cng_gost34311_class 
		: cng_hash_class_op_i
	{

		virtual void set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags){
			STCRYPT_UNIMPLEMENTED();
		}
		virtual void get_prop(LPCWSTR const prop_name,  PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags);

		virtual cng_hash_object_op_i_ptr create(BYTE * const object_buffer, ULONG const object_buffer_size);


		virtual DWORD hash_block_length(){
			return 32; //TODO:?
		}

		virtual DWORD hash_length();
		virtual DWORD hash_object_length();


		virtual void destroy_self(){
			delete this;
		}

		~cng_gost34311_class(){
		}

	};

}
//================================================================================================================================================
#endif
//================================================================================================================================================
