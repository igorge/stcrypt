//================================================================================================================================================
// FILE: stcrypt-cng-keystorage-provider-dllmain.cpp
// (c) GIE 2011-02-07  16:25
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
//#include "stcrypt-cng-keystorage-provider-dllmain.hpp"
//================================================================================================================================================

#include "stcrypt-cng-buffer.hpp"
#include "stcrypt-cng-dllmain-common.hpp"
#include "stcrypt-cng-keystorage-provider.hpp"
#include "util-fun-parameter-printer-cng-struct.hpp"
#include "stcrypt-debug-logger.hpp"
#include "stcrypt-exceptions.hpp"
#include "stcrypt-cng-exception-filter.hpp"
#include "util-bittest.hpp"

#include <bcrypt.h>
#include <ncrypt.h>
//================================================================================================================================================
namespace {

}


//================================================================================================================================================
//
// STCRYPT_KeyStorage func table
//
//

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPOpenProvider(
	__out   NCRYPT_PROV_HANDLE *phProvider,
	__in    LPCWSTR pszProviderName,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(string, pszProviderName);
		STC_IN_P(dword, dwFlags);
		STC_OUT_P(nprov_handle, phProvider);
	});
	
	if(!phProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pszProviderName) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	//if(dwFlags) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() ); no flags are defined BUT ms outlook 2010 passes one

	stcrypt::validate_provider_name(pszProviderName);

	auto const& keystorage_class = stcrypt::create_keystorage_class();

	intrusive_ptr_add_ref( keystorage_class.get() );
	*phProvider = reinterpret_cast<NCRYPT_PROV_HANDLE>( static_cast<void*>( keystorage_class.get() ) );
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPOpenKey(
	__inout NCRYPT_PROV_HANDLE hProvider,
	__out   NCRYPT_KEY_HANDLE *phKey,
	__in    LPCWSTR pszKeyName,
	__in_opt DWORD  dwLegacyKeySpec,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_OUT_P(nkey_handle, phKey);
		STC_IN_P(string, pszKeyName);
		STC_IN_P(dword, dwLegacyKeySpec);
		STC_IN_P(dword, dwFlags);
	});

	
	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!phKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pszKeyName) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	bool const is_machine_key = stcrypt::test_mask<DWORD>(dwFlags, NCRYPT_MACHINE_KEY_FLAG);

	auto const keystorage_class = stcrypt::cng_object_from_handle<stcrypt::cng_keystorage_class_op_i*>( hProvider );

	auto const n_key_handle = keystorage_class->open_key( pszKeyName, dwLegacyKeySpec, is_machine_key, dwFlags);

	intrusive_ptr_add_ref( n_key_handle.get() );
	*phKey = reinterpret_cast<NCRYPT_KEY_HANDLE>( static_cast<void*>( n_key_handle.get() ) );
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}


SECURITY_STATUS
	WINAPI
	STCRYPT_KSPCreatePersistedKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__out   NCRYPT_KEY_HANDLE *phKey,
	__in    LPCWSTR pszAlgId,
	__in_opt LPCWSTR pszKeyName,
	__in    DWORD   dwLegacyKeySpec,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_OUT_P(nkey_handle, phKey);
		STC_IN_P(string, pszAlgId);
		STC_IN_P(string, pszKeyName);
		STC_IN_P(dword, dwLegacyKeySpec);
		STC_IN_P(dword, dwFlags);
	});


	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!phKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pszAlgId) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	bool const is_machine_key = stcrypt::test_mask<DWORD>(dwFlags, NCRYPT_MACHINE_KEY_FLAG);
	bool const is_silent_context = stcrypt::test_mask<decltype(dwFlags)>( dwFlags, NCRYPT_SILENT_FLAG );
	(void)is_silent_context ;

	auto const keystorage_class = stcrypt::cng_object_from_handle<stcrypt::cng_keystorage_class_op_i*>( hProvider );

	auto const n_key_handle = pszKeyName?keystorage_class->create_key( pszAlgId, pszKeyName, dwLegacyKeySpec, is_machine_key, dwFlags):keystorage_class->create_ephemeral_key( pszAlgId, dwLegacyKeySpec, dwFlags);

	intrusive_ptr_add_ref( n_key_handle.get() );
	*phKey = reinterpret_cast<NCRYPT_KEY_HANDLE>( static_cast<void*>( n_key_handle.get() ) );
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}



SECURITY_STATUS
	WINAPI
	STCRYPT_KSPGetProviderProperty(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    LPCWSTR pszProperty,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(string, pszProperty);

		STC_OUT_P(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult) );

	});


	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pszProperty) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	stcrypt::get_cng_object_property_impl(hProvider, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}


SECURITY_STATUS
	WINAPI
	STCRYPT_KSPGetKeyProperty(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in    LPCWSTR pszProperty,
	__out_bcount(cbOutput) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(nkey_handle, hKey);
		STC_IN_P(string, pszProperty);

		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult),  pbOutput);

		STC_IN_P(dword, cbOutput);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});

	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pszProperty) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );



	stcrypt::get_cng_object_property_impl(hKey, pszProperty, pbOutput, cbOutput, pcbResult, dwFlags);
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPSetProviderProperty(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    LPCWSTR pszProperty,
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN CSP_LOG_TRACE STCRYPT_UNIMPLEMENTED(); CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPSetKeyProperty(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__inout NCRYPT_KEY_HANDLE hKey,
	__in    LPCWSTR pszProperty,
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 


	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(nkey_handle, hKey);
		STC_IN_P(string, pszProperty);

		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);

		STC_IN_P(dword, cbInput);
		STC_IN_P(dword, dwFlags);
	});

	
	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pszProperty) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pbInput) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	stcrypt::set_cng_object_property(hKey, pszProperty, pbInput, cbInput, dwFlags);

	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPFinalizeKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(nkey_handle, hKey);
		STC_IN_P(dword, dwFlags);
	});

	//NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG
	
	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );

	STCRYPT_CHECK_EX( !stcrypt::test_if_any_out_of_mask<DWORD>(dwFlags, NCRYPT_NO_KEY_VALIDATION|NCRYPT_SILENT_FLAG), stcrypt::exception::invalid_parameter() ); // currently just ignore allowed set of flags
	//if(dwFlags) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const cng_n_key_handle = stcrypt::cng_object_from_handle<stcrypt::cng_n_key_handle_impl_t*>( hKey );
	auto const cng_n_key_class = cng_n_key_handle->get<stcrypt::cng_n_key_class_op_i>();
	
	auto const cng_n_key_object = cng_n_key_class->create();
	cng_n_key_handle->set( cng_n_key_object.get() );

	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPDeleteKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__inout NCRYPT_KEY_HANDLE hKey,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN CSP_LOG_TRACE STCRYPT_UNIMPLEMENTED(); CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPFreeKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(nkey_handle, hKey);
	});

	
	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );

	stcrypt::cng_n_key_handle_op_i_ptr_t( stcrypt::cng_object_from_handle<stcrypt::cng_n_key_handle_impl_t*>( hKey ), false );

	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}



SECURITY_STATUS
	WINAPI
	STCRYPT_KSPFreeBuffer(
	__deref PVOID   pvInput)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(hex_auto, pvInput);
	});

	stcrypt::buffer_t::free( pvInput );
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}


SECURITY_STATUS
	WINAPI
	STCRYPT_KSPEncrypt(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    VOID *pPaddingInfo,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN CSP_LOG_TRACE STCRYPT_UNIMPLEMENTED(); CNG_CSP_N_CPP_EXCEPTION_GUARD_END}


SECURITY_STATUS
	WINAPI
	STCRYPT_KSPDecrypt(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_bcount(cbInput) PBYTE pbInput,
	__in    DWORD   cbInput,
	__in    VOID *pPaddingInfo,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(nkey_handle, hKey);
		STC_IN_P(hex_auto, pPaddingInfo);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbInput, cbInput),  pbInput);
		STC_IN_P(dword, cbInput);
		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult),  pbOutput);
		STC_IN_P(dword, cbOutput);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});

	
	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pcbResult) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const cng_n_key_handle = stcrypt::cng_object_from_handle<stcrypt::cng_n_key_handle_impl_t*>( hKey );
	auto const cng_n_key_object = cng_n_key_handle->get<stcrypt::cng_n_key_object_op_i>();

	*pcbResult = cng_n_key_object->asym_decrypt(pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, dwFlags);
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}


SECURITY_STATUS
	WINAPI
	STCRYPT_KSPIsAlgSupported(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    LPCWSTR pszAlgId,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN CSP_LOG_TRACE STCRYPT_UNIMPLEMENTED(); CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}


SECURITY_STATUS
	WINAPI
	STCRYPT_KSPEnumAlgorithms(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    DWORD   dwAlgOperations,
	__out   DWORD * pdwAlgCount,
	__deref_out_ecount(*pdwAlgCount) NCryptAlgorithmName **ppAlgList,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 
	
	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pdwAlgCount) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!ppAlgList) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const storage_provider = stcrypt::cng_object_from_handle<stcrypt::cng_keystorage_class_op_i*>( hProvider );

	*pdwAlgCount = storage_provider->enumerate_algorithms(dwAlgOperations, *ppAlgList);
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}


SECURITY_STATUS
WINAPI
STCRYPT_KSPEnumKeys(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in_opt LPCWSTR pszScope,
	__deref_out NCryptKeyName **ppKeyName,
	__inout PVOID * ppEnumState,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE

	STCRYPT_CHECK_EX(ppKeyName, stcrypt::exception::invalid_parameter() );
	STCRYPT_CHECK_EX(ppEnumState, stcrypt::exception::invalid_parameter() );

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(string, pszScope);
		STC_IN_P(dword, dwFlags);
	});

	auto const storage_provider = stcrypt::cng_object_from_handle<stcrypt::cng_keystorage_class_op_i*>( hProvider );

	if( *ppEnumState ) { //continue enum

		if(!*ppKeyName){

			stcrypt::buffer_t key_name_buffer( sizeof(NCryptKeyName) );
			STCRYPT_CHECK_EX( storage_provider->enum_keys_current( *ppEnumState, static_cast<NCryptKeyName*>( key_name_buffer.data() ) ), stcrypt::exception::no_more_items() );
			*ppKeyName = static_cast<NCryptKeyName*>( key_name_buffer.release() );

		} else {
			STCRYPT_CHECK_EX( storage_provider->enum_keys_current( *ppEnumState, *ppKeyName ), stcrypt::exception::no_more_items() );
		}

	} else { // restart

		bool const is_machine_key = stcrypt::test_mask<DWORD>(dwFlags, NCRYPT_MACHINE_KEY_FLAG);

		auto state = storage_provider->enum_keys_init(is_machine_key);

		if(!*ppKeyName){

			stcrypt::buffer_t key_name_buffer( sizeof(NCryptKeyName) );
			STCRYPT_CHECK_EX( storage_provider->enum_keys_current( state.data(), static_cast<NCryptKeyName*>( key_name_buffer.data() ) ), stcrypt::exception::no_more_items() );
			*ppKeyName = static_cast<NCryptKeyName*>( key_name_buffer.release() );

		} else {
			STCRYPT_CHECK_EX( storage_provider->enum_keys_current( state.data(), *ppKeyName ), stcrypt::exception::no_more_items() );
		}

		*ppEnumState = state.release();

	}
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPImportKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in_opt NCRYPT_KEY_HANDLE hImportKey,
	__in    LPCWSTR pszBlobType,
	__in_opt NCryptBufferDesc *pParameterList,
	__out   NCRYPT_KEY_HANDLE *phKey,
	__in_bcount(cbData) PBYTE pbData,
	__in    DWORD   cbData,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(nkey_handle, hImportKey);
		STC_IN_P(string, pszBlobType);
		STC_IN_P(hex_auto, pParameterList);
		STC_OUT_P(nkey_handle, phKey);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbData, cbData),  pbData);
		STC_IN_P(dword, cbData);
		STC_IN_P(dword, dwFlags);
	});


	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!phKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pszBlobType) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const storage_provider = stcrypt::cng_object_from_handle<stcrypt::cng_keystorage_class_op_i*>( hProvider );
	auto const cng_n_key_handle = storage_provider->import_ephemeral_key( hImportKey, pszBlobType, pbData, cbData, dwFlags);

	if( !stcrypt::test_mask<decltype(dwFlags)>(dwFlags, NCRYPT_DO_NOT_FINALIZE_FLAG) ){
		auto const cng_n_key_class = cng_n_key_handle->get<stcrypt::cng_n_key_class_op_i>();

		auto const cng_n_key_object = cng_n_key_class->create();
		cng_n_key_handle->set( cng_n_key_object.get() );

	}

	intrusive_ptr_add_ref( cng_n_key_handle.get() );
	*phKey = reinterpret_cast<NCRYPT_KEY_HANDLE>( static_cast<void*>( cng_n_key_handle.get() ) );
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPExportKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_opt NCRYPT_KEY_HANDLE hExportKey,
	__in    LPCWSTR pszBlobType,
	__in_opt NCryptBufferDesc *pParameterList,
	__out_bcount_part_opt(cbOutput, *pcbResult) PBYTE pbOutput,
	__in    DWORD   cbOutput,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(nkey_handle, hExportKey);
		STC_IN_P(string, pszBlobType);
		STC_IN_P(hex_auto, pParameterList);
		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbOutput, cbOutput, pcbResult),  pbOutput);
		STC_IN_P(dword, cbOutput);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});

	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pszBlobType) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	if(!pcbResult) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const cng_n_key_handle = stcrypt::cng_object_from_handle<stcrypt::cng_n_key_handle_impl_t*>( hKey );
	auto const cng_n_key_object = cng_n_key_handle->get<stcrypt::cng_n_key_object_op_i>();
	
	auto const cng_keystorage = cng_n_key_object->provider();

	if( cng_keystorage!=stcrypt::cng_object_from_handle<stcrypt::cng_keystorage_class_op_i*>( hProvider ) ){
		STCRYPT_UNEXPECTED();
	}

	if( pbOutput ){
		*pcbResult = cng_keystorage->export_key( cng_n_key_object, hExportKey, pszBlobType, pParameterList, pbOutput, cbOutput, dwFlags);
	} else {
		*pcbResult = cng_keystorage->key_blob_size( cng_n_key_object, hExportKey, pszBlobType, pParameterList, dwFlags);
	}
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}


SECURITY_STATUS
	WINAPI
	STCRYPT_KSPSignHash(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_opt    VOID  *pPaddingInfo,
	__in_bcount(cbHashValue) PBYTE pbHashValue,
	__in    DWORD   cbHashValue,
	__out_bcount_part_opt(cbSignaturee, *pcbResult) PBYTE pbSignature,
	__in    DWORD   cbSignaturee,
	__out   DWORD * pcbResult,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(nkey_handle, hKey);
		STC_IN_P(hex_auto, pPaddingInfo);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbHashValue, cbHashValue),  pbHashValue);
		STC_IN_P(dword, cbHashValue);
		STC_OUT_P_EX(array_any, stcrypt::pp_a(pbSignature, cbSignaturee, pcbResult),  pbSignature);
		STC_IN_P(dword, cbSignaturee);
		STC_OUT_P(dword, pcbResult);
		STC_IN_P(dword, dwFlags);
	});


	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!pcbResult) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

	auto const cng_n_key_handle = stcrypt::cng_object_from_handle<stcrypt::cng_n_key_handle_impl_t*>( hKey );
	auto const cng_n_key_object = cng_n_key_handle->get<stcrypt::cng_n_key_object_op_i>();

	cng_n_key_object->sign_hash(pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignaturee, pcbResult, dwFlags);
	
	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}



SECURITY_STATUS
	WINAPI
	STCRYPT_KSPVerifySignature(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hKey,
	__in_opt    VOID *pPaddingInfo,
	__in_bcount(cbHashValue) PBYTE pbHashValue,
	__in    DWORD   cbHashValue,
	__in_bcount(cbSignaturee) PBYTE pbSignature,
	__in    DWORD   cbSignaturee,
	__in    DWORD   dwFlags)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
		STC_IN_P(nkey_handle, hKey);
		STC_IN_P(hex_auto, pPaddingInfo);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbHashValue, cbHashValue),  pbHashValue);
		STC_IN_P(dword, cbHashValue);
		STC_IN_P_EX(array_any, stcrypt::pp_a(pbSignature, cbSignaturee),  pbSignature);
		STC_IN_P(dword, cbSignaturee);
		STC_IN_P(dword, dwFlags);
	});

	
	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
	if(!hKey) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );

	auto const cng_n_key_handle = stcrypt::cng_object_from_handle<stcrypt::cng_n_key_handle_impl_t*>( hKey );
	auto const cng_n_key_object = cng_n_key_handle->get<stcrypt::cng_n_key_object_op_i>();

	if( !cng_n_key_object->verify_signature(pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignaturee, dwFlags) ){
		STCRYPT_THROW_EXCEPTION( stcrypt::exception::signature_verification_failed() );
	}

	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPFreeProvider(
	__in    NCRYPT_PROV_HANDLE hProvider)
{
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN 
	CSP_LOG_TRACE 
	

	STC_PP({
		STC_IN_P(nprov_handle, hProvider);
	});

	if(!hProvider) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );

	stcrypt::cng_keystorage_class_op_i_ptr( stcrypt::cng_object_from_handle<stcrypt::cng_keystorage_class_op_i*>( hProvider ), false );

	CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPNotifyChangeKey(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__inout HANDLE *phEvent,
	__in    DWORD   dwFlags)
{
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(phEvent);
	UNREFERENCED_PARAMETER(dwFlags);
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN CSP_LOG_TRACE STCRYPT_UNIMPLEMENTED(); CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}


SECURITY_STATUS
	WINAPI
	STCRYPT_KSPSecretAgreement(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_KEY_HANDLE hPrivKey,
	__in    NCRYPT_KEY_HANDLE hPubKey,
	__out   NCRYPT_SECRET_HANDLE *phAgreedSecret,
	__in    DWORD   dwFlags)
{
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(hPrivKey);
	UNREFERENCED_PARAMETER(hPubKey);
	UNREFERENCED_PARAMETER(phAgreedSecret);
	UNREFERENCED_PARAMETER(dwFlags);
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN CSP_LOG_TRACE STCRYPT_UNIMPLEMENTED(); CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}


SECURITY_STATUS
	WINAPI
	STCRYPT_KSPDeriveKey(
	__in        NCRYPT_PROV_HANDLE   hProvider,
	__in_opt    NCRYPT_SECRET_HANDLE hSharedSecret,
	__in        LPCWSTR              pwszKDF,
	__in_opt    NCryptBufferDesc     *pParameterList,
	__out_bcount_part_opt(cbDerivedKey, *pcbResult) PUCHAR pbDerivedKey,
	__in        DWORD                cbDerivedKey,
	__out       DWORD                *pcbResult,
	__in        ULONG                dwFlags)
{
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(hSharedSecret);
	UNREFERENCED_PARAMETER(pwszKDF);
	UNREFERENCED_PARAMETER(pParameterList);
	UNREFERENCED_PARAMETER(pbDerivedKey);
	UNREFERENCED_PARAMETER(cbDerivedKey);
	UNREFERENCED_PARAMETER(pcbResult);
	UNREFERENCED_PARAMETER(dwFlags);
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN CSP_LOG_TRACE STCRYPT_UNIMPLEMENTED(); CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPFreeSecret(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in    NCRYPT_SECRET_HANDLE hSharedSecret)
{
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(hSharedSecret);
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN CSP_LOG_TRACE STCRYPT_UNIMPLEMENTED(); CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}

SECURITY_STATUS
	WINAPI
	STCRYPT_KSPPromptUser(
	__in    NCRYPT_PROV_HANDLE hProvider,
	__in_opt NCRYPT_KEY_HANDLE hKey,
	__in    LPCWSTR  pszOperation,
	__in    DWORD   dwFlags)
{
	UNREFERENCED_PARAMETER(hProvider);
	UNREFERENCED_PARAMETER(hKey);
	UNREFERENCED_PARAMETER(pszOperation);
	UNREFERENCED_PARAMETER(dwFlags);
	CNG_CSP_N_CPP_EXCEPTION_GUARD_BEGIN CSP_LOG_TRACE STCRYPT_UNIMPLEMENTED(); CNG_CSP_N_CPP_EXCEPTION_GUARD_END
}





NCRYPT_KEY_STORAGE_FUNCTION_TABLE STCRYPT_KeyStorageFunctionTable ={
	NCRYPT_KEY_STORAGE_INTERFACE_VERSION,
	STCRYPT_KSPOpenProvider,
	STCRYPT_KSPOpenKey,
	STCRYPT_KSPCreatePersistedKey,
	STCRYPT_KSPGetProviderProperty,
	STCRYPT_KSPGetKeyProperty,
	STCRYPT_KSPSetProviderProperty,
	STCRYPT_KSPSetKeyProperty,
	STCRYPT_KSPFinalizeKey,
	STCRYPT_KSPDeleteKey,
	STCRYPT_KSPFreeProvider,
	STCRYPT_KSPFreeKey,
	STCRYPT_KSPFreeBuffer,
	STCRYPT_KSPEncrypt,
	STCRYPT_KSPDecrypt,
	STCRYPT_KSPIsAlgSupported,
	STCRYPT_KSPEnumAlgorithms,
	STCRYPT_KSPEnumKeys,
	STCRYPT_KSPImportKey,
	STCRYPT_KSPExportKey,
	STCRYPT_KSPSignHash,
	STCRYPT_KSPVerifySignature,
	STCRYPT_KSPPromptUser,
	STCRYPT_KSPNotifyChangeKey,
	STCRYPT_KSPSecretAgreement,
	STCRYPT_KSPDeriveKey,
	STCRYPT_KSPFreeSecret
};



NTSTATUS WINAPI GetKeyStorageInterface(
	__in   LPCWSTR pszProviderName,
	__out  NCRYPT_KEY_STORAGE_FUNCTION_TABLE **ppFunctionTable,
	__in   DWORD dwFlags
	){
		CNG_CSP_CPP_EXCEPTION_GUARD_BEGIN 
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(string, pszProviderName);
			STC_OUT_P(hex_auto, ppFunctionTable);
			STC_IN_P(dword, dwFlags);
		});

		UNREFERENCED_PARAMETER(dwFlags);

		if(!pszProviderName) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		if(!ppFunctionTable) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
		stcrypt::validate_provider_name(pszProviderName);

		*ppFunctionTable = &STCRYPT_KeyStorageFunctionTable;
	
		
		CNG_CSP_CPP_EXCEPTION_GUARD_END

}

//================================================================================================================================================
