// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"

#include "stcrypt-cng-dllmain-common.hpp"
#include "util-fun-parameter-printer-cng-struct.hpp"
#include "stcrypt-debug-logger.hpp"
#include "stcrypt-crypto-alg-ids.h"
#include "strcypt-cng-hash-provider.hpp"
#include "stcrypt-cng-symmetric-provider.hpp"
#include "stcrypt-cng-asymmetric-provider.hpp"
#include "stcrypt-cng-status.hpp"
#include "stcrypt-exceptions.hpp"
#include "stcrypt-cng-exception-filter.hpp"
#include "util-bittest.hpp"

#include <bcrypt.h>

namespace stcrypt {
	HMODULE this_module_handle = 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		stcrypt::this_module_handle = hModule;
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		try{ stcrypt::logger::unload_for_thread();}catch(...){assert(false);}
		break;
	case DLL_PROCESS_DETACH:
		try{stcrypt::logger::before_unload();}catch(...){assert(false);}
		break;
	}
	return TRUE;
}

namespace stcrypt { namespace {

} }

//================================================================================================================================================
//
// STCRYPT_Asymmetric func table
//
//

NTSTATUS
	WINAPI
	STCRYPT_AsymmOpenCipherProvider(
	__out   BCRYPT_ALG_HANDLE   *phAlgorithm,
	__in    LPCWSTR             pszAlgId,
	__in    DWORD               dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
		CSP_LOG_TRACE

		STC_PP({
			STC_OUT_P(any, phAlgorithm);
			STC_IN_P(string, pszAlgId);
			STC_IN_P(dword, dwFlags);
		});

		if(!phAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if( stcrypt::test_if_any_out_of_mask<ULONG>(dwFlags, BCRYPT_ALG_HANDLE_HMAC_FLAG) ) STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );
		if( stcrypt::test_mask<ULONG>(dwFlags, BCRYPT_ALG_HANDLE_HMAC_FLAG) ) STCRYPT_THROW_EXCEPTION( stcrypt::exception::hmac_not_supported() );

		auto const& asymmetric_class = stcrypt::create_asymmetric_class( pszAlgId );

		intrusive_ptr_add_ref( asymmetric_class.get() );
		*phAlgorithm = static_cast<void*>( asymmetric_class.get() ) ;

		CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS
	WINAPI
	STCRYPT_AsymmGetCipherProperty(
	__in                                        BCRYPT_HANDLE   hObject,
	__in                                        LPCWSTR pszProperty,
	__out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
	__in                                        ULONG   cbOutput,
	__out                                       ULONG   *pcbResult,
	__in                                        ULONG   dwFlags
	){

		STC_PP({
			STC_IN_P(any, hObject);
			STC_IN_P(string, pszProperty);
			STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult),  pbOutput);
			STC_IN_P(dword, cbOutput);
			STC_OUT_P(dword, pcbResult);
			STC_IN_P(dword, dwFlags);
		});


			CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
			CSP_LOG_TRACE
			stcrypt::get_cng_object_property_impl(hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
			CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS
	WINAPI
	STCRYPT_AsymmSetCipherProperty(
	__inout                 BCRYPT_HANDLE   hObject,
	__in                    LPCWSTR pszProperty,
	__in_bcount(cbInput)    PUCHAR   pbInput,
	__in                    ULONG   cbInput,
	__in                    ULONG   dwFlags
	)
{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(any, hObject);
		STC_IN_P(string, pszProperty);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
		STC_IN_P(dword, cbInput);
		STC_IN_P(dword, dwFlags);
	});


	STCRYPT_UNIMPLEMENTED();
	stcrypt::set_cng_object_property(hObject, pszProperty, pbInput, cbInput, dwFlags);

	CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS
	WINAPI
	STCRYPT_AsymmCloseCipherProvider(
	__inout BCRYPT_ALG_HANDLE   hAlgorithm,
	__in    DWORD               dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
		CSP_LOG_TRACE 

		STC_PP({
			STC_IN_P(any, hAlgorithm);
			STC_IN_P(dword, dwFlags);
		});


		if(!hAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(dwFlags) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

		stcrypt::cng_asymmetric_class_op_i_ptr const assym_class( static_cast<stcrypt::cng_asymmetric_class_op_i*>( hAlgorithm ), false );
		
		CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS WINAPI STCRYPT_AsymmGenerateKeyPair (
	__inout  BCRYPT_ALG_HANDLE hAlgorithm,
	__out    BCRYPT_KEY_HANDLE *phKey,
	__in     ULONG dwLength,
	__in     ULONG dwFlags
	){
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE


	STC_PP({
		STC_IN_P(any, hAlgorithm);
		STC_OUT_P(any, phKey);
		STC_IN_P(dword, dwLength);
		STC_IN_P(dword, dwFlags);
	});


	if(!hAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!phKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const asymm_class = static_cast<stcrypt::cng_asymmetric_class_op_i*>( hAlgorithm );
	auto const asymm_key_handle = asymm_class->generate_key_pair(dwLength, dwFlags);

	intrusive_ptr_add_ref( asymm_key_handle.get() );
	*phKey = static_cast<void*>( asymm_key_handle.get() ) ;

	CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS WINAPI STCRYPT_AsymmFinalizeKeyPair(
	__inout  BCRYPT_KEY_HANDLE hKey,
	__in     ULONG dwFlags
	){
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(any, hKey);
		STC_IN_P(dword, dwFlags);
	});


	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if( dwFlags ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::badflags() << stcrypt::exception::flags_einfo(dwFlags) );
	auto const asymm_key_handle = static_cast<stcrypt::cng_asymmetric_object_handle_t*>( hKey );
	auto const asymm_key_ctor = asymm_key_handle->get<stcrypt::cng_asymmetric_object_ctor_op_i>();
	auto const asymm_key = asymm_key_ctor->create();
	asymm_key_handle->set( asymm_key.get() );

	CNG_CSP_CPP_EXCEPTION_GUARD_END
}



NTSTATUS
	WINAPI
	STCRYPT_AsymmEncrypt(
	__inout                                     BCRYPT_KEY_HANDLE hKey,
	__in_bcount(cbInput)                        PUCHAR   pbInput,
	__in                                        ULONG   cbInput,
	__in_opt                                    VOID    *pPaddingInfo,
	__inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
	__in                                        ULONG   cbIV,
	__out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
	__in                                        ULONG   cbOutput,
	__out                                       ULONG   *pcbResult,
	__in                                        ULONG   dwFlags
	)

{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(any, hKey);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
		STC_IN_P(dword, cbInput);
		STC_IN_P(hex_auto, pPaddingInfo);
		STC_IN_P(dword, cbIV);
		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult),  pbOutput);
		STC_IN_P(dword, cbOutput);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});

	STCRYPT_CHECK( dwFlags==BCRYPT_PAD_PKCS1 );

	STCRYPT_CHECK_EX(pbIV==0, stcrypt::exception::invalid_parameter());
	STCRYPT_CHECK_EX(cbIV==0, stcrypt::exception::invalid_parameter());

	STCRYPT_CHECK_EX(hKey,		stcrypt::exception::invalid_parameter_handle() );
	STCRYPT_CHECK_EX(pbInput,	stcrypt::exception::invalid_parameter() );
	STCRYPT_CHECK_EX(!pPaddingInfo,	stcrypt::exception::invalid_parameter() );
	STCRYPT_CHECK_EX(pcbResult,		stcrypt::exception::invalid_parameter() );

	auto const asymm_key_handle = stcrypt::cng_object_from_handle<stcrypt::cng_asymmetric_object_handle_t*>( hKey );
	auto const asymm_key = asymm_key_handle->get<stcrypt::cng_asymmetric_object_op_i>();

	if( !pbOutput ) {
		*pcbResult = asymm_key->calc_encrypt_buffer_size( cbInput );
	} else {
		if( pbInput==pbOutput ){ //in place
			STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		} else { //copy
			*pcbResult = asymm_key->encrypt(pbInput, cbInput, pbOutput, cbOutput);
		}
	}

	CNG_CSP_CPP_EXCEPTION_GUARD_END
}


NTSTATUS
	WINAPI
	STCRYPT_AsymmDecrypt(
	__inout                                     BCRYPT_KEY_HANDLE   hKey,
	__in_bcount(cbInput)                        PUCHAR   pbInput,
	__in                                        ULONG   cbInput,
	__in_opt                                    VOID    *pPaddingInfo,
	__inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
	__in                                        ULONG   cbIV,
	__out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
	__in                                        ULONG   cbOutput,
	__out                                       ULONG   *pcbResult,
	__in                                        ULONG   dwFlags
	)
{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(any, hKey);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
		STC_IN_P(dword, cbInput);
		STC_IN_P(hex_auto, pPaddingInfo);
		STC_IN_P(dword, cbIV);
		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult),  pbOutput);
		STC_IN_P(dword, cbOutput);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});

	STCRYPT_CHECK( dwFlags==BCRYPT_PAD_PKCS1 );

	STCRYPT_CHECK_EX(pbIV==0, stcrypt::exception::invalid_parameter());
	STCRYPT_CHECK_EX(cbIV==0, stcrypt::exception::invalid_parameter());

	STCRYPT_CHECK_EX(hKey,		stcrypt::exception::invalid_parameter_handle() );
	STCRYPT_CHECK_EX(pbInput,	stcrypt::exception::invalid_parameter() );
	STCRYPT_CHECK_EX(!pPaddingInfo,	stcrypt::exception::invalid_parameter() );
	STCRYPT_CHECK_EX(pcbResult,		stcrypt::exception::invalid_parameter() );
	
	auto const asymm_key_handle = stcrypt::cng_object_from_handle<stcrypt::cng_asymmetric_object_handle_t*>( hKey );
	auto const asymm_key = asymm_key_handle->get<stcrypt::cng_asymmetric_object_op_i>();


	if( !pbOutput ) {
		*pcbResult = asymm_key->calc_decrypt_buffer_size( cbInput );
	} else {
		if( pbInput==pbOutput ){ //in place
			STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		} else { //copy
			*pcbResult = asymm_key->decrypt(pbInput, cbInput, pbOutput, cbOutput);
		}
	}
	
	CNG_CSP_CPP_EXCEPTION_GUARD_END
}


NTSTATUS  WINAPI STCRYPT_AsymmImportKeyPair(
	__in     BCRYPT_ALG_HANDLE hAlgorithm,
	__inout  BCRYPT_KEY_HANDLE hImportKey,
	__in     LPCWSTR pszBlobType,
	__out    BCRYPT_KEY_HANDLE *phKey,
	__in     PUCHAR pbInput,
	__in     ULONG cbInput,
	__in     ULONG dwFlags
	){
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(any, hAlgorithm);
		STC_IN_P(any, hImportKey);
		STC_IN_P(string, pszBlobType);
		STC_OUT_P(any, phKey);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
		STC_IN_P(dword, cbInput);
		STC_IN_P(dword, dwFlags);
	});

	UNREFERENCED_PARAMETER(hImportKey);

	if(!hAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pszBlobType) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!phKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pbInput) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const asymm_class = stcrypt::cng_object_from_handle<stcrypt::cng_asymmetric_class_op_i*>( hAlgorithm );
	auto const asymm_key_handle = asymm_class->import_key_pair(pszBlobType, pbInput, cbInput);

	intrusive_ptr_add_ref( asymm_key_handle.get() );
	*phKey = static_cast<void*>( asymm_key_handle.get() ) ;


	CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS WINAPI STCRYPT_AsymmExportKey(
	__in   BCRYPT_KEY_HANDLE hKey,
	__in   BCRYPT_KEY_HANDLE hExportKey,
	__in   LPCWSTR pszBlobType,
	__out  PUCHAR pbOutput,
	__in   ULONG cbOutput,
	__out  ULONG *pcbResult,
	__in   ULONG dwFlags
	){
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(any, hKey);
		STC_IN_P(any, hExportKey);
		STC_IN_P(string, pszBlobType);
		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult),  pbOutput);
		STC_IN_P(dword, cbOutput);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});


	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(hExportKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pszBlobType) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pcbResult) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const b_key_handle = stcrypt::cng_object_from_handle<stcrypt::cng_asymmetric_object_handle_t*>( hKey );
	auto const b_key = b_key_handle->get<stcrypt::cng_asymmetric_object_op_i>();

	if( !pbOutput ){
		*pcbResult = b_key->key_blob_size(pszBlobType);
	} else {
		*pcbResult = b_key->export_key_blob(pszBlobType, pbOutput, cbOutput);
	}

	CNG_CSP_CPP_EXCEPTION_GUARD_END
}



NTSTATUS WINAPI STCRYPT_AsymmDestroyKey(__inout  BCRYPT_KEY_HANDLE hKey){
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(any, hKey);
	});


	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );

	stcrypt::cng_asymmetric_object_handle_ptr_t const assym_handle ( static_cast<stcrypt::cng_asymmetric_object_handle_t*>( hKey ), false );

	CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS WINAPI  STCRYPT_AsymmSignHash(
	__in      BCRYPT_KEY_HANDLE hKey,
	__in_opt  VOID *pPaddingInfo,
	__in      PBYTE pbInput,
	__in      DWORD cbInput,
	__out     PBYTE pbOutput,
	__in      DWORD cbOutput,
	__out     DWORD *pcbResult,
	__in      ULONG dwFlags
	){
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(any, hKey);
		STC_IN_P(hex_auto, pPaddingInfo);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
		STC_IN_P(dword, cbInput);
		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult),  pbOutput);
		STC_IN_P(dword, cbOutput);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});


	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pbInput) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pcbResult) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const asymm_handle = stcrypt::cng_object_from_handle<stcrypt::cng_asymmetric_object_handle_t*>(hKey);
	auto const asym_b_key = asymm_handle->get<stcrypt::cng_asymmetric_object_op_i>();


	if( !pbOutput ) {
		*pcbResult = asym_b_key->signature_size( /*cbInput*/ );
	} else {
		*pcbResult = asym_b_key->sign_hash(pbInput, cbInput, pbOutput, cbOutput, dwFlags);
	}

	CNG_CSP_CPP_EXCEPTION_GUARD_END
}


NTSTATUS WINAPI STCRYPT_AsymmVerifySignature(
	__in      BCRYPT_KEY_HANDLE hKey,
	__in_opt  VOID *pPaddingInfo,
	__in      PUCHAR pbHash,
	__in      ULONG cbHash,
	__in      PUCHAR pbSignature,
	__in      ULONG cbSignature,
	__in      ULONG dwFlags
	){
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(any, hKey);
		STC_IN_P(hex_auto, pPaddingInfo);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbHash, cbHash),  pbHash);
		STC_IN_P(dword, cbHash);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbSignature, cbSignature),  pbSignature);
		STC_IN_P(dword, cbSignature);
		STC_IN_P(dword, dwFlags);
	});


	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pbHash) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pbSignature) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const asymm_handle = stcrypt::cng_object_from_handle<stcrypt::cng_asymmetric_object_handle_t*>(hKey);
	auto const asym_b_key = asymm_handle->get<stcrypt::cng_asymmetric_object_op_i>();

	if( !asym_b_key->verify_signature(pbHash, cbHash, pbSignature, cbSignature, dwFlags) ) {
		STCRYPT_THROW_EXCEPTION( stcrypt::exception::signature_verification_failed() );
	}

	CNG_CSP_CPP_EXCEPTION_GUARD_END
}



BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE STCRYPT_AsymmCipherFunctionTable={
	BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE_VERSION_1,
	STCRYPT_AsymmOpenCipherProvider,
	STCRYPT_AsymmGetCipherProperty,
	STCRYPT_AsymmSetCipherProperty,
	STCRYPT_AsymmCloseCipherProvider,
	STCRYPT_AsymmGenerateKeyPair,
	STCRYPT_AsymmFinalizeKeyPair,
	STCRYPT_AsymmEncrypt,
	STCRYPT_AsymmDecrypt,
	STCRYPT_AsymmImportKeyPair,
	STCRYPT_AsymmExportKey,
	STCRYPT_AsymmDestroyKey,
	STCRYPT_AsymmSignHash,
	STCRYPT_AsymmVerifySignature
};

	NTSTATUS WINAPI GetAsymmetricEncryptionInterface(
	__in   LPCWSTR pszProviderName,
	__in   LPCWSTR pszAlgId,
	__out  BCRYPT_ASYMMETRIC_ENCRYPTION_FUNCTION_TABLE **ppFunctionTable,
	__in   DWORD dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(string, pszProviderName);
			STC_IN_P(string, pszAlgId);
			STC_OUT_P(hex_auto, ppFunctionTable);
			STC_IN_P(dword, dwFlags);
		});


		
		UNREFERENCED_PARAMETER(dwFlags);

		if(!pszProviderName) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(!ppFunctionTable) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		stcrypt::validate_provider_name(pszProviderName);

		if( !stcrypt::is_asymmetric_alg_valid(pszAlgId) ) STCRYPT_THROW_EXCEPTION( stcrypt::exception::badalg() );

		*ppFunctionTable = &STCRYPT_AsymmCipherFunctionTable;
	
		CNG_CSP_CPP_EXCEPTION_GUARD_END
	}


//================================================================================================================================================
//
// STCRYPT_Symmetric func table
//
//
NTSTATUS
	WINAPI
	STCRYPT_SymmOpenCipherProvider(
	__out   BCRYPT_ALG_HANDLE   *phAlgorithm,
	__in    LPCWSTR             pszAlgId,
	__in    DWORD               dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
		CSP_LOG_TRACE 
		
		STC_PP({
			STC_OUT_P(any, phAlgorithm);
			STC_IN_P(hex_auto, pszAlgId);
			STC_IN_P(dword, dwFlags);
		});


		if(!phAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if( stcrypt::test_if_any_out_of_mask<ULONG>(dwFlags, BCRYPT_ALG_HANDLE_HMAC_FLAG) ) STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );
		if( stcrypt::test_mask<ULONG>(dwFlags, BCRYPT_ALG_HANDLE_HMAC_FLAG) ) STCRYPT_THROW_EXCEPTION( stcrypt::exception::hmac_not_supported() );

		auto const& symmetric_class = stcrypt::create_symmetric_class( pszAlgId );

		intrusive_ptr_add_ref( symmetric_class.get() );
		*phAlgorithm = static_cast<void*>( symmetric_class.get() ) ;

		CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS
	WINAPI
	STCRYPT_SymmGetCipherProperty(
	__in                                        BCRYPT_HANDLE   hObject,
	__in                                        LPCWSTR pszProperty,
	__out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
	__in                                        ULONG   cbOutput,
	__out                                       ULONG   *pcbResult,
	__in                                        ULONG   dwFlags
	)
{
			CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
			CSP_LOG_TRACE


			STC_PP({
				STC_IN_P(any, hObject);
				STC_IN_P(string, pszProperty);
				STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult),  pbOutput);
				STC_IN_P(dword, cbOutput);
				STC_OUT_P(dword, pcbResult);
				STC_IN_P(dword, dwFlags);
			});


			stcrypt::get_cng_object_property_impl(hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
			CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS
	WINAPI
	STCRYPT_SymmSetCipherProperty(
	__inout                 BCRYPT_HANDLE   hObject,
	__in                    LPCWSTR pszProperty,
	__in_bcount(cbInput)    PUCHAR   pbInput,
	__in                    ULONG   cbInput,
	__in                    ULONG   dwFlags
	)
{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(any, hObject);
		STC_IN_P(string, pszProperty);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
		STC_IN_P(dword, cbInput);
		STC_IN_P(dword, dwFlags);
	});

	stcrypt::set_cng_object_property(hObject, pszProperty, pbInput, cbInput, dwFlags);

	CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS
	WINAPI
	STCRYPT_SymmCloseCipherProvider(
	__inout BCRYPT_ALG_HANDLE   hAlgorithm,
	__in    DWORD               dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(any, hAlgorithm);
			STC_IN_P(dword, dwFlags);
		});

		
		if(!hAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(dwFlags) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

		stcrypt::cng_symmetric_class_op_i_ptr const hash_class( static_cast<stcrypt::cng_symmetric_class_op_i*>( hAlgorithm ), false );
		
		CNG_CSP_CPP_EXCEPTION_GUARD_END
}


NTSTATUS
	WINAPI
	STCRYPT_SymmGenerateKey(
	__inout                         BCRYPT_ALG_HANDLE   hAlgorithm,
	__out                           BCRYPT_KEY_HANDLE   *phKey,
	__out_bcount_full(cbKeyObject)  PUCHAR   pbKeyObject,
	__in                            ULONG   cbKeyObject,
	__in_bcount(cbSecret)           PUCHAR   pbSecret,
	__in                            ULONG   cbSecret,
	__in                            ULONG   dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(any, hAlgorithm);
			STC_OUT_P(any, phKey);
			STC_OUT_P(hex_auto, pbKeyObject); //we don need to dump obj in-memory repr
			STC_IN_P(dword, cbKeyObject);
			STC_IN_P_EX(array_any, stcrypt::pp_a(pbSecret, cbSecret),  pbSecret);
			STC_IN_P(dword, cbSecret);
			STC_IN_P(dword, dwFlags);
		});


		if(!hAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
		if(!phKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(!pbKeyObject) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

		if(!pbSecret) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

		
		auto const symmetric_class = static_cast<stcrypt::cng_symmetric_class_op_i*>( hAlgorithm );
		auto const symmetric_object = symmetric_class->create( pbKeyObject, cbKeyObject, pbSecret, cbSecret);
		intrusive_ptr_add_ref( symmetric_object.get() );

		*phKey = static_cast<void*>( symmetric_object.get() );
		
		CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS
	WINAPI
	STCRYPT_SymmEncrypt(
	__inout                                     BCRYPT_KEY_HANDLE hKey,
	__in_bcount(cbInput)                        PUCHAR   pbInput,
	__in                                        ULONG   cbInput,
	__in_opt                                    VOID    *pPaddingInfo,
	__inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
	__in                                        ULONG   cbIV,
	__out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
	__in                                        ULONG   cbOutput,
	__out                                       ULONG   *pcbResult,
	__in                                        ULONG   dwFlags
	)

{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(any, hKey);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
		STC_IN_P(dword, cbInput);
		STC_IN_P(hex_auto, pPaddingInfo); 
		STC_INOUT_P_EX(array_any, stcrypt::pp_a(pbIV, cbIV),  pbIV);
		STC_IN_P(dword, cbIV);
		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pbOutput),  pbOutput);
		STC_IN_P(dword, cbOutput);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});

	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pbInput) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(pPaddingInfo) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pcbResult) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const symmetric_object = static_cast<stcrypt::cng_symmetric_object_op_i*>( hKey );
	
	if( !pbOutput ) {
		*pcbResult = symmetric_object->calc_encrypt_buffer_size( cbInput );
	} else {
		if( pbInput==pbOutput ){ //in place
			*pcbResult = symmetric_object->encrypt(pbInput, cbInput, cbOutput, pbIV, cbIV, dwFlags);
		} else { //copy
			*pcbResult = symmetric_object->encrypt(pbInput, cbInput, pbOutput, cbOutput, pbIV, cbIV, dwFlags);
		}
	}

	
	CNG_CSP_CPP_EXCEPTION_GUARD_END
}


NTSTATUS
	WINAPI
	STCRYPT_SymmDecrypt(
	__inout                                     BCRYPT_KEY_HANDLE   hKey,
	__in_bcount(cbInput)                        PUCHAR   pbInput,
	__in                                        ULONG   cbInput,
	__in_opt                                    VOID    *pPaddingInfo,
	__inout_bcount_opt(cbIV)                    PUCHAR   pbIV,
	__in                                        ULONG   cbIV,
	__out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
	__in                                        ULONG   cbOutput,
	__out                                       ULONG   *pcbResult,
	__in                                        ULONG   dwFlags
	)
{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(any, hKey);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
		STC_IN_P(dword, cbInput);
		STC_IN_P(hex_auto, pPaddingInfo); 
		STC_INOUT_P_EX(array_any, stcrypt::pp_a(pbIV, cbIV),  pbIV);
		STC_IN_P(dword, cbIV);
		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pbOutput),  pbOutput);
		STC_IN_P(dword, cbOutput);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});


	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pbInput) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(pPaddingInfo) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pcbResult) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const symmetric_object = static_cast<stcrypt::cng_symmetric_object_op_i*>( hKey );
	
	if( !pbOutput ) {
		*pcbResult = symmetric_object->calc_decrypt_buffer_size( cbInput );
	} else {
		if( pbInput==pbOutput ){ //in place
			*pcbResult = symmetric_object->decrypt(pbInput, cbInput, cbOutput, pbIV, cbIV, dwFlags);
		} else { //copy
			*pcbResult = symmetric_object->decrypt(pbInput, cbInput, pbOutput, cbOutput, pbIV, cbIV, dwFlags);
		}
	}
	
	CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS
	WINAPI
	STCRYPT_SymmImportKey(
	__in                            BCRYPT_ALG_HANDLE hAlgorithm,
	__in_opt                        BCRYPT_KEY_HANDLE hImportKey,
	__in                            LPCWSTR pszBlobType,
	__out                           BCRYPT_KEY_HANDLE *phKey,
	__out_bcount_full(cbKeyObject)  PUCHAR   pbKeyObject,
	__in                            ULONG   cbKeyObject,
	__in_bcount(cbInput)            PUCHAR   pbInput,
	__in                            ULONG   cbInput,
	__in                            ULONG   dwFlags
	)
{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 
	
	STCRYPT_UNIMPLEMENTED(); 
	
	CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS
	WINAPI
	STCRYPT_SymmExportKey(
	__in                                        BCRYPT_KEY_HANDLE   hKey,
	__in_opt                                    BCRYPT_KEY_HANDLE   hExportKey,
	__in                                        LPCWSTR pszBlobType,
	__out_bcount_part_opt(cbOutput, *pcbResult) PUCHAR   pbOutput,
	__in                                        ULONG   cbOutput,
	__out                                       ULONG   *pcbResult,
	__in                                        ULONG   dwFlags
	)
{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE
	
	STCRYPT_UNIMPLEMENTED(); 
	
	CNG_CSP_CPP_EXCEPTION_GUARD_END
}


NTSTATUS
	WINAPI
	STCRYPT_SymmDuplicateKey(
	__in                            BCRYPT_KEY_HANDLE   hKey,
	__out                           BCRYPT_KEY_HANDLE   *phNewKey,
	__out_bcount_full(cbKeyObject)  PUCHAR   pbKeyObject,
	__in                            ULONG   cbKeyObject,
	__in                            ULONG   dwFlags
	)
{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE 
	
	STCRYPT_UNIMPLEMENTED(); 
	
	CNG_CSP_CPP_EXCEPTION_GUARD_END
}


NTSTATUS
	WINAPI
	STCRYPT_SymmDestroyKey(
	__inout BCRYPT_KEY_HANDLE   hKey
	)
{
	CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(any, hKey);
	});

	
	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );

	stcrypt::cng_symmetric_object_op_i_ptr( static_cast<stcrypt::cng_symmetric_object_op_i*>( hKey ), false );
	
	CNG_CSP_CPP_EXCEPTION_GUARD_END
}

BCRYPT_CIPHER_FUNCTION_TABLE STCRYPT_SymmCipherFunctionTable = {
	BCRYPT_CIPHER_INTERFACE_VERSION_1,
	STCRYPT_SymmOpenCipherProvider,
	STCRYPT_SymmGetCipherProperty,
	STCRYPT_SymmSetCipherProperty,
	STCRYPT_SymmCloseCipherProvider,
	STCRYPT_SymmGenerateKey,
	STCRYPT_SymmEncrypt,
	STCRYPT_SymmDecrypt,
	STCRYPT_SymmImportKey,
	STCRYPT_SymmExportKey,
	STCRYPT_SymmDuplicateKey,
	STCRYPT_SymmDestroyKey,
};

NTSTATUS WINAPI GetCipherInterface(
	__in   LPCWSTR pszProviderName,
	__in   LPCWSTR pszAlgId,
	__out  BCRYPT_CIPHER_FUNCTION_TABLE **ppFunctionTable,
	__in   ULONG dwFlags
	){

		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(string, pszProviderName);
			STC_IN_P(string, pszAlgId);
			STC_OUT_P(hex_auto, ppFunctionTable);
			STC_IN_P(dword, dwFlags);
		});

		
		UNREFERENCED_PARAMETER(dwFlags);

		if(!pszProviderName) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(!ppFunctionTable) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		stcrypt::validate_provider_name(pszProviderName);

		if( !stcrypt::is_symmetric_alg_valid(pszAlgId) ) STCRYPT_THROW_EXCEPTION( stcrypt::exception::badalg() );

		*ppFunctionTable = &STCRYPT_SymmCipherFunctionTable;

	
		
		CNG_CSP_CPP_EXCEPTION_GUARD_END
}


//================================================================================================================================================
//
// Hash func table
//
//

//
// return STATUS_PORT_UNREACHABLE to trigger CNG failover
//
NTSTATUS WINAPI STCRYPT_OpenHashProvider(
	__out  BCRYPT_ALG_HANDLE *phAlgorithm,
	__in   LPCWSTR pszAlgId,
	__in   ULONG dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_OUT_P(any, phAlgorithm);
			STC_IN_P(string, pszAlgId);
			STC_IN_P(dword, dwFlags);
		});


		if(!phAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if( stcrypt::test_if_any_out_of_mask<ULONG>(dwFlags, BCRYPT_ALG_HANDLE_HMAC_FLAG) ) STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );
		if( stcrypt::test_mask<ULONG>(dwFlags, BCRYPT_ALG_HANDLE_HMAC_FLAG) ) STCRYPT_THROW_EXCEPTION( stcrypt::exception::hmac_not_supported() );

		stcrypt::cng_hash_class_op_i_ptr const& hash_class = stcrypt::create_hash_class( pszAlgId );

		intrusive_ptr_add_ref( hash_class.get() );
		*phAlgorithm = static_cast<void*>( hash_class.get() ) ;

		CNG_CSP_CPP_EXCEPTION_GUARD_END

}


NTSTATUS WINAPI STCRYPT_GetHashProperty(
	__in   BCRYPT_HANDLE hObject,
	__in   LPCWSTR pszProperty,
	__out  PUCHAR pbOutput,
	__in   ULONG cbOutput,
	__out  ULONG *pcbResult,
	__in   ULONG dwFlags
	){
			CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
			CSP_LOG_TRACE

			STC_PP({
				STC_IN_P(any, hObject);
				STC_IN_P(string, pszProperty);
				STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pbOutput),  pbOutput);
				STC_IN_P(dword, cbOutput);
				STC_OUT_P(dword, pcbResult);
				STC_IN_P(dword, dwFlags);
			});

			stcrypt::get_cng_object_property_impl(hObject, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
			CNG_CSP_CPP_EXCEPTION_GUARD_END
}

NTSTATUS WINAPI STCRYPT_SetHashProperty(
	__inout  BCRYPT_HANDLE hObject,
	__in     LPCWSTR pszProperty,
	__in     PUCHAR pbInput,
	__in     ULONG cbInput,
	__in     ULONG dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(any, hObject);
			STC_IN_P(string, pszProperty);
			STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
			STC_IN_P(dword, cbInput);
			STC_IN_P(dword, dwFlags);
		});

		STCRYPT_UNIMPLEMENTED();

		CNG_CSP_CPP_EXCEPTION_GUARD_END

}


NTSTATUS WINAPI STCRYPT_CloseHashProvider(
	__inout  BCRYPT_ALG_HANDLE hAlgorithm,
	__in     ULONG dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(any, hAlgorithm);
			STC_IN_P(dword, dwFlags);
		});


		if(!hAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(dwFlags) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

		stcrypt::cng_hash_class_op_i_ptr const hash_class( static_cast<stcrypt::cng_hash_class_op_i*>( hAlgorithm ), false );

		CNG_CSP_CPP_EXCEPTION_GUARD_END

}

NTSTATUS WINAPI STCRYPT_CreateHash(
	__inout   BCRYPT_ALG_HANDLE hAlgorithm,
	__out     BCRYPT_HASH_HANDLE *phHash,
	__out     PUCHAR pbHashObject,
	__in      ULONG cbHashObject,
	__in_opt  PUCHAR pbSecret,
	__in_opt  ULONG cbSecret,
	__in      ULONG dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(any, hAlgorithm);
			STC_OUT_P(any, phHash);
			STC_OUT_P(hex_auto, pbHashObject);
			STC_IN_P(dword, cbHashObject);
			STC_IN_P_EX(array_any, stcrypt::pp_a(pbSecret, cbSecret),  pbSecret);
			STC_IN_P(dword, cbSecret);
			STC_IN_P(dword, dwFlags);
		});


		UNREFERENCED_PARAMETER(dwFlags);

		if(!hAlgorithm) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
		if(!phHash) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(!pbHashObject) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

		if(pbSecret) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

		auto const hash_class = static_cast<stcrypt::cng_hash_class_op_i*>( hAlgorithm );
		auto const hash_object = hash_class->create(pbHashObject, cbHashObject);
		intrusive_ptr_add_ref( hash_object.get() );

		*phHash = static_cast<void*>( hash_object.get() );

		CNG_CSP_CPP_EXCEPTION_GUARD_END

}

NTSTATUS WINAPI STCRYPT_HashData(
	__inout  BCRYPT_HASH_HANDLE hHash,
	__in     PUCHAR pbInput,
	__in     ULONG cbInput,
	__in     ULONG dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(any, hHash);
			STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
			STC_IN_P(dword, cbInput);
			STC_IN_P(dword, dwFlags);
		});


		if(!hHash) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
		if(!pbInput) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

		UNREFERENCED_PARAMETER(dwFlags);

		auto const hash_object = static_cast<stcrypt::cng_hash_object_op_i*>( hHash );
		hash_object->hash_data( pbInput, cbInput );

		CNG_CSP_CPP_EXCEPTION_GUARD_END

}


NTSTATUS WINAPI STCRYPT_FinishHash(
	__inout  BCRYPT_HASH_HANDLE hHash,
	__out    PUCHAR pbOutput,
	__in     ULONG cbOutput,
	__in     ULONG dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(any, hHash);
			STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput),  pbOutput);
			STC_IN_P(dword, cbOutput);
			STC_IN_P(dword, dwFlags);
		});


		if(!hHash) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
		if(!pbOutput) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(dwFlags) STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );

		auto const hash_object = static_cast<stcrypt::cng_hash_object_op_i*>( hHash );
		hash_object->finalize_and_get_result(pbOutput, cbOutput);

		CNG_CSP_CPP_EXCEPTION_GUARD_END

}

NTSTATUS WINAPI STCRYPT_DuplicateHash(
	__in   BCRYPT_HASH_HANDLE hHash,
	__out  BCRYPT_HASH_HANDLE *phNewHash,
	__out  PUCHAR pbHashObject,
	__in   ULONG cbHashObject,
	__in   ULONG dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STCRYPT_UNIMPLEMENTED();

		CNG_CSP_CPP_EXCEPTION_GUARD_END

}

NTSTATUS WINAPI STCRYPT_DestroyHash(
	__inout  BCRYPT_HASH_HANDLE hHash
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(any, hHash);
		});


		if(!hHash) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );

		stcrypt::cng_hash_object_op_i_ptr( static_cast<stcrypt::cng_hash_object_op_i*>( hHash ), false );

		CNG_CSP_CPP_EXCEPTION_GUARD_END
}

BCRYPT_HASH_FUNCTION_TABLE STCRYPT_HashFunctionTable = 
{
	BCRYPT_HASH_INTERFACE_VERSION_1,
	STCRYPT_OpenHashProvider,
	STCRYPT_GetHashProperty,
	STCRYPT_SetHashProperty,
	STCRYPT_CloseHashProvider,
	STCRYPT_CreateHash,
	STCRYPT_HashData,
	STCRYPT_FinishHash,
	STCRYPT_DuplicateHash,
	STCRYPT_DestroyHash
};



NTSTATUS WINAPI GetHashInterface(
	__in   LPCWSTR pszProviderName, 
	__in   LPCWSTR pszAlgId, 
	__out  BCRYPT_HASH_FUNCTION_TABLE **ppFunctionTable, 
	__in   ULONG dwFlags)
{
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(string, pszProviderName);
			STC_IN_P(string, pszAlgId);
			STC_OUT_P(hex_auto, ppFunctionTable);
			STC_IN_P(dword, dwFlags);
		});


		UNREFERENCED_PARAMETER(dwFlags);

		if(!pszProviderName) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(!ppFunctionTable) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		stcrypt::validate_provider_name(pszProviderName);

		if( !stcrypt::is_hash_alg_valid(pszAlgId) ) STCRYPT_THROW_EXCEPTION( stcrypt::exception::badalg() );

		*ppFunctionTable = &STCRYPT_HashFunctionTable;

		CNG_CSP_CPP_EXCEPTION_GUARD_END
}
//================================================================================================================================================

	NTSTATUS WINAPI GetSecretAgreementInterface(
	__in   LPCWSTR pszProviderName,
	__in   LPCWSTR pszAlgId,
	__out  BCRYPT_SECRET_AGREEMENT_FUNCTION_TABLE **ppFunctionTable,
	__in   ULONG dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STCRYPT_UNIMPLEMENTED();

		CNG_CSP_CPP_EXCEPTION_GUARD_END
	}


	NTSTATUS WINAPI GetRngInterface(
		__in   LPCWSTR pszProviderName,
		__out  BCRYPT_RNG_FUNCTION_TABLE **ppFunctionTable,
		__in   ULONG dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STCRYPT_UNIMPLEMENTED();

		CNG_CSP_CPP_EXCEPTION_GUARD_END
	}

