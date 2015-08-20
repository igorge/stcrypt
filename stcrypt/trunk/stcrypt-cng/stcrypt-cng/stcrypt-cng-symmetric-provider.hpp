//================================================================================================================================================
// FILE: 
// (c) GIE 2010-08-10
//
//================================================================================================================================================
#ifndef H_GUARD_STRCYPT_CNG_SYMMETRIC_PROVIDER_4463239854
#define H_GUARD_STRCYPT_CNG_SYMMETRIC_PROVIDER_4463239854
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"
#include "strcypt-cng-provider.hpp"


#include <boost/intrusive_ptr.hpp>
//================================================================================================================================================
namespace stcrypt {

	struct cng_symmetric_key_op_i 
		: cng_prop_op_i
	{
		virtual ULONG calc_encrypt_buffer_size(ULONG const input_size)=0;
		virtual ULONG calc_decrypt_buffer_size(ULONG const input_size)=0;

		//copy enc
		virtual ULONG encrypt(PUCHAR const input, ULONG const input_size, PUCHAR const output, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags)=0;
		virtual ULONG decrypt(PUCHAR const input, ULONG const input_size, PUCHAR const output, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags)=0;

		//in place
		virtual ULONG encrypt(PUCHAR const input, ULONG const input_size, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags)=0;
		virtual ULONG decrypt(PUCHAR const input, ULONG const input_size, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags)=0;
	};

	struct cng_symmetric_object_op_i 
		: cng_obj_ref 
		, cng_symmetric_key_op_i
	{
	};
	typedef boost::intrusive_ptr<cng_symmetric_object_op_i> cng_symmetric_object_op_i_ptr;


	struct cng_symmetric_class_op_i
		: cng_obj_ref
		, cng_prop_op_i
	{
		virtual cng_symmetric_object_op_i_ptr create(BYTE * const object_buffer, ULONG const object_buffer_size, PUCHAR const secret, ULONG const secret_size)=0;
		virtual DWORD block_length()=0;
		virtual DWORD symmetric_object_length()=0;
	};
	typedef boost::intrusive_ptr<cng_symmetric_class_op_i> cng_symmetric_class_op_i_ptr;

	cng_symmetric_class_op_i_ptr create_symmetric_class(LPCWSTR const alg_id);
	bool is_symmetric_alg_valid(LPCWSTR const alg_id);



}
//================================================================================================================================================
#endif
//================================================================================================================================================
