//================================================================================================================================================
// FILE: stcrypt-cng-keystorage-provider.h
// (c) GIE 2010-08-26  14:02
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_KEYSTORAGE_PROVIDER_2010_08_26_14_02
#define H_GUARD_STCRYPT_CNG_KEYSTORAGE_PROVIDER_2010_08_26_14_02
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "util-cng-handle-two-stage-variant.hpp"
#include "stcrypt-exceptions.hpp"
#include "strcypt-cng-provider.hpp"
#include "stcrypt-cng-buffer.hpp"

#include <boost/intrusive_ptr.hpp>
//================================================================================================================================================
namespace stcrypt {


	struct cng_n_key_class_op_i;
	struct cng_n_key_object_op_i;
	struct cng_keystorage_class_op_i;

	typedef cng_handle_varian_t<cng_n_key_class_op_i, cng_n_key_object_op_i> cng_n_key_handle_impl_t;
	typedef boost::intrusive_ptr<cng_n_key_handle_impl_t> cng_n_key_handle_op_i_ptr_t;

	struct cng_n_key_object_op_i 
		: cng_obj_ref 
		, cng_prop_op_i
	{
		virtual void sign_hash(VOID * const pPaddingInfo, PBYTE const pbHashValue, DWORD const cbHashValue, PBYTE const pbSignature, DWORD const cbSignaturee, DWORD * const pcbResult, DWORD const dwFlags)=0;
		virtual bool verify_signature(VOID * const pPaddingInfo, PBYTE const pbHashValue, DWORD const cbHashValue, PBYTE const pbSignature, DWORD const cbSignaturee, DWORD const dwFlags)=0;

		virtual DWORD asym_decrypt(PBYTE const pbInput, DWORD const cbInput, VOID * const pPaddingInfo, PBYTE const pbOutput, DWORD const cbOutput, DWORD const dwFlags)=0;

		virtual cng_keystorage_class_op_i* provider()=0;
		virtual void set_window_handle(HWND const hwnd)=0;
	};
	typedef boost::intrusive_ptr<cng_n_key_object_op_i> cng_n_key_object_op_i_ptr_t;

	struct cng_n_key_class_op_i 
		: cng_obj_ref 
		, cng_prop_op_i
	{
		virtual cng_n_key_object_op_i_ptr_t	create()=0;
		virtual cng_n_key_object_op_i_ptr_t	open()=0;
		virtual void set_window_handle(HWND const hwnd)=0;
		virtual void set_export_policy(DWORD const policy)=0;
		virtual void set_ui_policy(NCRYPT_UI_POLICY const& policy)=0;
		virtual void set_length(DWORD const length)=0;
		virtual void set_key_usage(DWORD const key_usage)=0;
	};
	typedef boost::intrusive_ptr<cng_n_key_class_op_i> cng_n_key_class_op_i_ptr_t;



	struct cng_keystorage_class_op_i
		: cng_obj_ref
		, cng_prop_op_i
	{
		virtual cng_n_key_handle_op_i_ptr_t create_key(LPCWSTR const alg_id, LPCWSTR const key_name, DWORD const legacy_key_spec, bool const is_machine_key, DWORD const flags)=0;
		virtual cng_n_key_handle_op_i_ptr_t create_ephemeral_key(LPCWSTR const alg_id, DWORD const legacy_key_spec, DWORD const flags)=0;
		virtual cng_n_key_handle_op_i_ptr_t open_key(LPCWSTR const key_name, DWORD const legacy_key_spec, bool const is_machine_key, DWORD const flags)=0;

		virtual cng_n_key_handle_op_i_ptr_t import_ephemeral_key(NCRYPT_KEY_HANDLE const export_key, LPCWSTR const pszBlobType, PBYTE const pbData, DWORD const cbData, DWORD const dwFlags)=0;
		virtual DWORD export_key(cng_n_key_object_op_i *const key_to_export, NCRYPT_KEY_HANDLE const export_key, LPCWSTR const pszBlobType, NCryptBufferDesc *const pParameterList , PBYTE const pbOutput, DWORD const cbOutput, DWORD const dwFlags)=0;
		virtual DWORD key_blob_size(cng_n_key_object_op_i *const key_to_export, NCRYPT_KEY_HANDLE const export_key, LPCWSTR const pszBlobType, NCryptBufferDesc *const pParameterList, DWORD const dwFlags)=0;

		virtual stcrypt::buffer_t enum_keys_init(bool const is_machine_keys)=0;
		virtual bool enum_keys_current(void* const state, NCryptKeyName*const key_name)=0;

		virtual unsigned int enumerate_algorithms(DWORD const dwAlgOperations, NCryptAlgorithmName *& ppAlgList)=0;
	};
	typedef boost::intrusive_ptr<cng_keystorage_class_op_i> cng_keystorage_class_op_i_ptr;

	cng_keystorage_class_op_i_ptr create_keystorage_class();
	bool is_keystorage_alg_valid(LPCWSTR const alg_id);

}
//================================================================================================================================================
#endif
//================================================================================================================================================
