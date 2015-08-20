//================================================================================================================================================
// FILE: stcrypt-cng-oid-func.h
// (c) GIE 2010-09-13  16:39
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_OID_FUNC_2010_09_13_16_39
#define H_GUARD_STCRYPT_CNG_OID_FUNC_2010_09_13_16_39
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include <wincrypt.h>
#include <ncrypt.h>
//================================================================================================================================================
BOOL WINAPI STCRYPT_ExportPublicKeyInfoEx2 (
	__in NCRYPT_KEY_HANDLE hNCryptKey,
	__in DWORD dwCertEncodingType,
	__in LPSTR pszPublicKeyObjId,
	__in DWORD dwFlags,
	__in_opt void *pvAuxInfo,
	__out_bcount_part_opt(*pcbInfo, *pcbInfo) PCERT_PUBLIC_KEY_INFO pInfo,
	__inout DWORD *pcbInfo
	);


BOOL WINAPI STCRYPT_SignAndEncodeHash(
	__in     NCRYPT_KEY_HANDLE hKey,
	__in     DWORD dwCertEncodingType,
	__in     PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
	__in     void *pvDecodedSignPara,
	__in     LPCWSTR pwszCNGPubKeyAlgid,
	__in     LPCWSTR pwszCNGHashAlgid,
	__in     BYTE *pbComputedHash,
	__in     DWORD cbComputedHash,
	__out    BYTE *pbSignature,
	__inout  DWORD *pcbSignature
	);

// PFN_CRYPT_VERIFY_ENCODED_SIGNATURE_FUNC
BOOL WINAPI STCRYPT_VerifyEncodedSignature(
	__in      DWORD dwCertEncodingType,
	__in      PCERT_PUBLIC_KEY_INFO pPubKeyInfo,
	__in      PCRYPT_ALGORITHM_IDENTIFIER pSignatureAlgorithm,
	__in_opt  void *pvDecodedSignPara,
	__in      LPCWSTR pwszCNGPubKeyAlgid,
	__in      LPCWSTR pwszCNGHashAlgid,
	__in      BYTE *pbComputedHash,
	__in      DWORD cbComputedHash,
	__in      BYTE *pbSignature,
	__in      DWORD cbSignature
	);

//================================================================================================================================================
#endif
//================================================================================================================================================
