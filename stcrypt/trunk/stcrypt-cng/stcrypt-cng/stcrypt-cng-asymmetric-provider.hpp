//================================================================================================================================================
// FILE: strcypt-cng-asymmetric.h
// (c) GIE 2010-08-25  16:29
//
//================================================================================================================================================
#ifndef H_GUARD_STRCYPT_CNG_ASYMMETRIC_2010_08_25_16_29
#define H_GUARD_STRCYPT_CNG_ASYMMETRIC_2010_08_25_16_29
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"
#include "strcypt-cng-provider.hpp"
#include "util-cng-handle-two-stage-variant.hpp"

#include <boost/intrusive_ptr.hpp>
#include <boost/tuple/tuple.hpp>
//================================================================================================================================================
namespace stcrypt {

	struct cng_asymmetric_key_op_i {
		virtual DWORD key_strength()=0;
		virtual DWORD key_length()=0;// in bits

		virtual DWORD sign_hash(PBYTE const input, DWORD const input_size, PBYTE output, DWORD const output_size,  ULONG const flags)=0;
		virtual bool verify_signature(PBYTE const hash, DWORD const hash_size, PBYTE signature, DWORD const signature_size,  ULONG const flags)=0;
		virtual DWORD signature_size()=0;
		
		virtual ULONG key_blob_size(LPCWSTR pszBlobType)=0;
		virtual ULONG export_key_blob(LPCWSTR pszBlobType, PUCHAR pbOutput,  ULONG cbOutput)=0;


		virtual boost::tuple<size_t,size_t> buffers_sizes()const=0;

		virtual ULONG calc_encrypt_buffer_size(ULONG const input_size)=0;
		virtual ULONG calc_decrypt_buffer_size(ULONG const input_size)=0;

		//copy enc
		virtual ULONG encrypt(PUCHAR const input, ULONG const input_size, PUCHAR const output, ULONG const output_size)=0;
		virtual ULONG decrypt(PUCHAR const input, ULONG const input_size, PUCHAR const output, ULONG const output_size)=0;
		//virtual ULONG decrypt(PUCHAR const input, ULONG const input_size, PUCHAR const output, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags)=0;

		//in place
		//virtual ULONG encrypt(PUCHAR const input, ULONG const input_size, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags)=0;
		//virtual ULONG decrypt(PUCHAR const input, ULONG const input_size, ULONG const output_size, PUCHAR const iv, ULONG const iv_size, ULONG const flags)=0;
	};


	struct cng_asymmetric_object_op_i 
		: cng_obj_ref 
		, cng_asymmetric_key_op_i
	{
	};
	typedef boost::intrusive_ptr<cng_asymmetric_object_op_i> cng_asymmetric_object_op_i_ptr_t;


	struct cng_asymmetric_object_ctor_op_i 
		: cng_obj_ref 
		//, cng_asymmetric_key_op_i
	{
		virtual cng_asymmetric_object_op_i_ptr_t create()=0;
	};
	typedef boost::intrusive_ptr<cng_asymmetric_object_ctor_op_i> cng_asymmetric_object_ctor_op_i_ptr_t;

	typedef cng_handle_varian_t<cng_asymmetric_object_ctor_op_i, cng_asymmetric_object_op_i> cng_asymmetric_object_handle_t;
	typedef boost::intrusive_ptr<cng_asymmetric_object_handle_t>	cng_asymmetric_object_handle_ptr_t;


	struct cng_asymmetric_class_op_i
		: cng_obj_ref
		, cng_prop_op_i
	{
		virtual cng_asymmetric_object_handle_ptr_t generate_key_pair(ULONG const key_bit_length, ULONG const dwFlags)=0;
		virtual cng_asymmetric_object_handle_ptr_t import_key_pair(LPCWSTR const pszBlobType, PUCHAR const pbInput, ULONG const cbInput)=0;
		//virtual cng_asymmetric_object_op_i_ptr create(BYTE * const object_buffer, ULONG const object_buffer_size, PUCHAR const secret, ULONG const secret_size)=0;
		//virtual DWORD block_length()=0;
		//virtual DWORD asymmetric_object_length()=0;
	};
	typedef boost::intrusive_ptr<cng_asymmetric_class_op_i> cng_asymmetric_class_op_i_ptr;

	cng_asymmetric_class_op_i_ptr create_asymmetric_class(LPCWSTR const alg_id);
	bool is_asymmetric_alg_valid(LPCWSTR const alg_id);

}

//================================================================================================================================================
#endif
//================================================================================================================================================
