//================================================================================================================================================
// FILE: strcypt-cng-hash-provider.h
// (c) GIE 2010-08-10  15:10
//
//================================================================================================================================================
#ifndef H_GUARD_STRCYPT_CNG_HASH_PROVIDER_2010_08_10_15_10
#define H_GUARD_STRCYPT_CNG_HASH_PROVIDER_2010_08_10_15_10
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"
#include "strcypt-cng-provider.hpp"


#include <boost/intrusive_ptr.hpp>
//================================================================================================================================================
namespace stcrypt {

	struct cng_hash_object_op_i 
		: cng_obj_ref 
	{
		virtual void hash_data(UCHAR const * const data, ULONG const size)=0;
		virtual void finalize_and_get_result(UCHAR * const buffer, ULONG const buffer_size)=0;
	};
	typedef boost::intrusive_ptr<cng_hash_object_op_i> cng_hash_object_op_i_ptr;


	struct cng_hash_class_op_i
		: cng_obj_ref
		, cng_prop_op_i
	{
		virtual DWORD hash_block_length()=0;
		virtual DWORD hash_object_length()=0;
		virtual DWORD hash_length()=0;

		virtual cng_hash_object_op_i_ptr create(BYTE * const object_buffer, ULONG const object_buffer_size)=0;
	};
	typedef boost::intrusive_ptr<cng_hash_class_op_i> cng_hash_class_op_i_ptr;

	cng_hash_class_op_i_ptr create_hash_class(LPCWSTR const alg_id);
	bool is_hash_alg_valid(LPCWSTR const alg_id);

}
//================================================================================================================================================
#endif
//================================================================================================================================================
