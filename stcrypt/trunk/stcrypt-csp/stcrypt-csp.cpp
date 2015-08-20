// stcrypt-csp.cpp : Defines the entry point for the DLL application.
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "util-bittest.hpp"
#include "stcrypt-key-factory.hpp"
#include "stcrypt-hash-base.hpp"
#include "stcrypt-csp.h"
#include "stcrypt-csp-factory.hpp"
#include "util-fun-param-printer.hpp"

#include "boost/intrusive_ptr.hpp"
#include "boost/format.hpp"
#include "boost/scope_exit.hpp"

#include "test-here.hpp"
//================================================================================================================================================
//#include <windows.h>
#include <wincrypt.h>
#include <cspdk.h>
#include <stdexcept>
//================================================================================================================================================
#ifdef _MANAGED
#pragma managed(push, off)
#endif
//================================================================================================================================================
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		{
			stcrypt::test__();
		}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
    return TRUE;
}
//================================================================================================================================================
#ifdef _MANAGED
#pragma managed(pop)
#endif
//================================================================================================================================================
BOOL WINAPI
CPAcquireContext(
    OUT HCRYPTPROV *phProv,
    IN  LPCSTR szContainer,
    IN  DWORD dwFlags,
    IN  PVTableProvStruc pVTable)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((phProv,stcrypt::param_dump_via_ptr(phProv))) ((szContainer,stcrypt::param_dump_str(szContainer)))  ((dwFlags,stcrypt::param_dump_hex(dwFlags))) ((pVTable, (void*)pVTable)) );

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( stcrypt::create_csp(szContainer, dwFlags,pVTable) );
	if( this_csp )
	{
		*phProv =  reinterpret_cast<HCRYPTPROV>( static_cast<void*>( this_csp.get() ) ); 
		intrusive_ptr_add_ref( this_csp.get() );
	}
	else
	{

	}

	CSP_CPP_EXCEPTION_GUARD_END
}
//================================================================================================================================================


/*
 -      CPReleaseContext
 -
 *      Purpose:
 *               The CPReleaseContext function is used to release a
 *               context created by CryptAcquireContext.
 *
 *     Parameters:
 *               IN  phProv        -  Handle to a CSP
 *               IN  dwFlags       -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPReleaseContext(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwFlags)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv))((dwFlags,stcrypt::param_dump_hex(dwFlags))) );

	
	
	if(dwFlags) {STCRYPT_THROW_EXCEPTION(stcrypt::exception::badflags());}

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ), false);

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPGenKey
 -
 *  Purpose:
 *                Generate cryptographic keys
 *
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      Algid   -  Algorithm identifier
 *               IN      dwFlags -  Flags values
 *               OUT     phKey   -  Handle to a generated key
 *
 *  Returns:
 */

BOOL WINAPI
CPGenKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv))((Algid,Algid))((dwFlags,stcrypt::param_dump_hex(dwFlags)))((phKey,stcrypt::param_dump_via_ptr(phKey))) );

	if(!phKey)
		STCRYPT_UNEXPECTED();

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
	stcrypt::key_base_ptr this_key (this_csp->generate_key(Algid, dwFlags) );

	*phKey = reinterpret_cast<HCRYPTKEY>( static_cast<void*>( this_key.get() ) ); 
	intrusive_ptr_add_ref( this_key.get() );

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPDeriveKey
 -
 *  Purpose:
 *                Derive cryptographic keys from base data
 *
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      Algid      -  Algorithm identifier
 *               IN      hBaseData -   Handle to base data
 *               IN      dwFlags    -  Flags values
 *               OUT     phKey      -  Handle to a generated key
 *
 *  Returns:
 */

BOOL WINAPI
CPDeriveKey(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS(  ((hProv,hProv))((Algid,Algid))((hHash,hHash))((dwFlags,stcrypt::param_dump_hex(dwFlags)))((phKey,stcrypt::param_dump_via_ptr(phKey))) );

	if( !reinterpret_cast<void const*>(hHash) )
		STCRYPT_THROW_EXCEPTION( stcrypt::exception::bad_hash() );

	if(!phKey)
		STCRYPT_UNEXPECTED();

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
	boost::intrusive_ptr<stcrypt::hash_impl_base_t> this_hash ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );
	stcrypt::key_base_ptr this_key (this_csp->derive_key(Algid, dwFlags, this_hash ) );

	*phKey = reinterpret_cast<HCRYPTKEY>( static_cast<void*>( this_key.get() ) ); 
	intrusive_ptr_add_ref( this_key.get() );

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPDestroyKey
 -
 *  Purpose:
 *                Destroys the cryptographic key that is being referenced
 *                with the hKey parameter
 *
 *
 *  Parameters:
 *               IN      hProv  -  Handle to a CSP
 *               IN      hKey   -  Handle to a key
 *
 *  Returns:
 */

BOOL WINAPI
CPDestroyKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv))((hKey,hKey)) );

	stcrypt::key_base_ptr this_key ( static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hKey) ), false);

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPSetKeyParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hKey    -  Handle to a key
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
    CSP_CPP_EXCEPTION_GUARD_BEGIN
    CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((hKey,hKey)) ((dwParam,dwParam)) ((pbData,stcrypt::param_dump_array(pbData,4/*note: size depends on type, so dump first 4 bytes for id*/  ))) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) );

	if(dwFlags!=0) STCRYPT_THROW_EXCEPTION(stcrypt::exception::badflags() << stcrypt::exception::flags_einfo(dwFlags));

	stcrypt::key_base_ptr this_key ( static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hKey) ) );
	this_key->set_param(dwParam, pbData);

    CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPGetKeyParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a key
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hKey       -  Handle to a key
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetKeyParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((hKey,hKey)) ((dwParam,dwParam)) ((pbData,stcrypt::param_dump_array(pbData,pcbDataLen))) ((pcbDataLen,stcrypt::param_dump_via_ptr(pcbDataLen))) ((dwFlags,stcrypt::param_dump_hex(dwFlags)))  );

	try {

		if( !pcbDataLen ) {STCRYPT_UNEXPECTED();}
		if( dwFlags!=0 ) {STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );}

		stcrypt::key_base_ptr this_key ( static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hKey) ) );
		this_key->get_param(dwParam,pbData,pcbDataLen);

	} catch(stcrypt::exception::more_data const&){
		throw;		
	} catch(...) {
		*pcbDataLen = 0;
		throw;
	}

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPSetProvParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((dwParam,dwParam)) ((pbData,stcrypt::param_dump_array(pbData,4/*note: size depends on type, so dump first 4 bytes for id*/  ))) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) );

	STCRYPT_UNIMPLEMENTED();

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPGetProvParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a provider
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN OUT  pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetProvParam(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;


	STC_DUMP_PARAMS( ((hProv,hProv)) ((dwParam,dwParam)) ((pbData,stcrypt::param_dump_array(pbData,pcbDataLen))) ((pcbDataLen,stcrypt::param_dump_via_ptr(pcbDataLen))) ((dwFlags,stcrypt::param_dump_hex(dwFlags)))  );

	try {
		
		if( !pcbDataLen ) {STCRYPT_UNEXPECTED();}

		boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
		this_csp->get_param(dwParam, pbData, pcbDataLen, dwFlags);

	} catch(stcrypt::exception::more_data const&){
		throw;		
	} catch(...) {
		*pcbDataLen = 0;
		throw;
	}

    CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPSetHashParam
 -
 *  Purpose:
 *                Allows applications to customize various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv   -  Handle to a CSP
 *               IN      hHash   -  Handle to a hash
 *               IN      dwParam -  Parameter number
 *               IN      pbData  -  Pointer to data
 *               IN      dwFlags -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPSetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    IN  CONST BYTE *pbData,
    IN  DWORD dwFlags)
{
    CSP_CPP_EXCEPTION_GUARD_BEGIN
    CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv))((hHash,hHash)) ((dwParam,dwParam)) ((pbData,stcrypt::param_dump_array(pbData,4/*note: size depends on type, so dump first 4 bytes for id*/  ))) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) );


	if( dwFlags!=0 ) {STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );}

	boost::intrusive_ptr<stcrypt::hash_impl_base_t> this_hash ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );
	this_hash->set_param(dwParam, pbData);

    CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPGetHashParam
 -
 *  Purpose:
 *                Allows applications to get various aspects of the
 *                operations of a hash
 *
 *  Parameters:
 *               IN      hProv      -  Handle to a CSP
 *               IN      hHash      -  Handle to a hash
 *               IN      dwParam    -  Parameter number
 *               OUT     pbData     -  Pointer to data
 *               IN      pdwDataLen -  Length of parameter data
 *               IN      dwFlags    -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPGetHashParam(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwParam,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD dwFlags)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((hHash,hHash)) ((dwParam,dwParam)) ((pbData,stcrypt::param_dump_array(pbData,pcbDataLen))) ((pcbDataLen,stcrypt::param_dump_via_ptr(pcbDataLen))) ((dwFlags,stcrypt::param_dump_hex(dwFlags)))  );

	try {
		
		if( !pcbDataLen ) {STCRYPT_UNEXPECTED();}
		if( dwFlags!=0 ) {STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );}

		boost::intrusive_ptr<stcrypt::hash_impl_base_t> this_hash ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );
		this_hash->get_param(dwParam, pbData, pcbDataLen);

	} catch(stcrypt::exception::more_data const&){
		throw;		
	} catch(...) {
		*pcbDataLen = 0;
		throw;
	}

    CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPExportKey
 -
 *  Purpose:
 *                Export cryptographic keys out of a CSP in a secure manner
 *
 *
 *  Parameters:
 *               IN  hProv         - Handle to the CSP user
 *               IN  hKey          - Handle to the key to export
 *               IN  hPubKey       - Handle to exchange public key value of
 *                                   the destination user
 *               IN  dwBlobType    - Type of key blob to be exported
 *               IN  dwFlags       - Flags values
 *               OUT pbData        -     Key blob data
 *               IN OUT pdwDataLen - Length of key blob in bytes
 *
 *  Returns:
 */

BOOL WINAPI
CPExportKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwBlobType,
    IN  DWORD dwFlags,
    OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((hKey,hKey))((hPubKey,hPubKey))((dwBlobType,dwBlobType))((dwFlags,stcrypt::param_dump_hex(dwFlags)))((pbData, stcrypt::param_dump_array(pbData, pcbDataLen)))((pcbDataLen,stcrypt::param_dump_via_ptr(pcbDataLen))) );


	if(!hKey)
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::bad_key());

	if( dwFlags )
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::badflags());

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
	stcrypt::key_base_ptr this_key (  static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hKey) )  );
	stcrypt::key_base_ptr this_public_key (  static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hPubKey) )  );

	this_csp->export_key(this_key, this_public_key, dwBlobType, dwFlags, pbData, pcbDataLen);

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPImportKey
 -
 *  Purpose:
 *                Import cryptographic keys
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the CSP user
 *               IN  pbData    -  Key blob data
 *               IN  dwDataLen -  Length of the key blob data
 *               IN  hPubKey   -  Handle to the exchange public key value of
 *                                the destination user
 *               IN  dwFlags   -  Flags values
 *               OUT phKey     -  Pointer to the handle to the key which was
 *                                Imported
 *
 *  Returns:
 */

BOOL WINAPI
CPImportKey(
    IN  HCRYPTPROV hProv,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  HCRYPTKEY hPubKey,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;


	#define STC_CPImportKey_PARAMS \
		((hProv,hProv))\
		((pbData,stcrypt::param_dump_array(pbData,cbDataLen) ))\
		((cbDataLen,cbDataLen))((hPubKey,hPubKey))\
		((dwFlags,stcrypt::param_dump_hex(dwFlags)))\
		((phKey,stcrypt::param_dump_via_ptr(phKey) ))	\
		/**/


	STC_DUMP_PARAMS( STC_CPImportKey_PARAMS );


	if(!phKey)
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::bad_key());
	//if(!hPubKey)
	//	STCRYPT_THROW_EXCEPTION(stcrypt::exception::bad_key());

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
	stcrypt::key_base_ptr this_public_key (  static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hPubKey) )  );

	stcrypt::key_base_ptr const imported_key = this_csp->import_key(this_public_key, dwFlags, pbData, cbDataLen);

	*phKey = reinterpret_cast<HCRYPTKEY>( static_cast<void*>( imported_key.get() ) ); 
	intrusive_ptr_add_ref( imported_key.get() );

	CSP_CPP_EXCEPTION_GUARD_END

}


/*
 -  CPEncrypt
 -
 *  Purpose:
 *                Encrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of plaintext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be encrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    encrypted
 *               IN dwBufLen       -  Size of Data buffer
 *
 *  Returns:
 */

BOOL WINAPI
CPEncrypt(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen,
    IN  DWORD cbBufLen)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv))  ((hKey,hKey)) ((hHash,hHash)) ((fFinal,fFinal)) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) ((pbData,stcrypt::param_dump_array(pbData, pcbDataLen))) ((pcbDataLen,stcrypt::param_dump_via_ptr(pcbDataLen))) ((cbBufLen,cbBufLen)) );

	try {
		
		if( !pcbDataLen ) {STCRYPT_UNEXPECTED();}
		if( dwFlags!=0 ) {STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );}

		boost::intrusive_ptr<stcrypt::hash_impl_base_t> hasher ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );
		
		stcrypt::key_base_ptr this_key (  static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hKey) )  );
		*pcbDataLen = static_cast<DWORD>( static_cast<stcrypt::cryptoapi_key_inplace_op_i*>(this_key.get())->invoke_cipher_encrypt(pbData, *pcbDataLen, cbBufLen, hasher.get(), fFinal!=0 ) );

	} catch(...) {
		*pcbDataLen = 0;
		throw;
	}

    CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPDecrypt
 -
 *  Purpose:
 *                Decrypt data
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the CSP user
 *               IN  hKey          -  Handle to the key
 *               IN  hHash         -  Optional handle to a hash
 *               IN  Final         -  Boolean indicating if this is the final
 *                                    block of ciphertext
 *               IN  dwFlags       -  Flags values
 *               IN OUT pbData     -  Data to be decrypted
 *               IN OUT pdwDataLen -  Pointer to the length of the data to be
 *                                    decrypted
 *
 *  Returns:
 */

BOOL WINAPI
CPDecrypt(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  HCRYPTHASH hHash,
    IN  BOOL fFinal,
    IN  DWORD dwFlags,
    IN OUT LPBYTE pbData,
    IN OUT LPDWORD pcbDataLen)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv))  ((hKey,hKey)) ((hHash,hHash)) ((fFinal,fFinal)) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) ((pbData,stcrypt::param_dump_array(pbData, pcbDataLen))) ((pcbDataLen,stcrypt::param_dump_via_ptr(pcbDataLen))) );

	try {

		if( !pcbDataLen ) {STCRYPT_UNEXPECTED();}
		if( dwFlags!=0 ) {STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );}

		boost::intrusive_ptr<stcrypt::hash_impl_base_t> hasher ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );

		stcrypt::key_base_ptr this_key (  static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hKey) )  );
		*pcbDataLen = static_cast<DWORD>( static_cast<stcrypt::cryptoapi_key_inplace_op_i*>(this_key.get())->invoke_cipher_decrypt(pbData, *pcbDataLen, *pcbDataLen, hasher.get(), fFinal!=0 ) );

	} catch(...) {
		*pcbDataLen = 0;
		throw;
	}

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPCreateHash
 -
 *  Purpose:
 *                initate the hashing of a stream of data
 *
 *
 *  Parameters:
 *               IN  hUID    -  Handle to the user identifcation
 *               IN  Algid   -  Algorithm identifier of the hash algorithm
 *                              to be used
 *               IN  hKey   -   Optional handle to a key
 *               IN  dwFlags -  Flags values
 *               OUT pHash   -  Handle to hash object
 *
 *  Returns:
 */

BOOL WINAPI
CPCreateHash(
    IN  HCRYPTPROV hProv,
    IN  ALG_ID Algid,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((Algid,Algid)) ((hKey,hKey)) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) ((phHash,stcrypt::param_dump_via_ptr(phHash))) );


	assert(dwFlags==0);
	assert(phHash);

	stcrypt::key_base_ptr this_key ( static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hKey) ) );

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
	boost::intrusive_ptr<stcrypt::hash_impl_base_t> hash = this_csp->create_hash(Algid, this_key);
	
	*phHash = reinterpret_cast<HCRYPTHASH>( static_cast<void*>( hash.get() ) ); 
	intrusive_ptr_add_ref( hash.get() );

    CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPHashData
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a stream of data
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  pbData    -  Pointer to data to be hashed
 *               IN  dwDataLen -  Length of the data to be hashed
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPHashData(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbData,
    IN  DWORD cbDataLen,
    IN  DWORD dwFlags)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((hHash,hHash)) ((pbData,stcrypt::param_dump_array(pbData,cbDataLen))) ((cbDataLen,cbDataLen)) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) );


	if( stcrypt::test_mask<DWORD>(dwFlags,CRYPT_USERDATA) ){
		STCRYPT_UNIMPLEMENTED();
	} else {
		if( dwFlags!=0 ) {STCRYPT_THROW_EXCEPTION( stcrypt::exception::badflags() );}
	}

	boost::intrusive_ptr<stcrypt::hash_impl_base_t> this_hash ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );
	this_hash->hash_data(pbData, cbDataLen);


	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPHashSessionKey
 -
 *  Purpose:
 *                Compute the cryptograghic hash on a key object.
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *               IN  hKey      -  Handle to a key object
 *               IN  dwFlags   -  Flags values
 *
 *  Returns:
 *               CRYPT_FAILED
 *               CRYPT_SUCCEED
 */

BOOL WINAPI
CPHashSessionKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  HCRYPTKEY hKey,
    IN  DWORD dwFlags)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((hHash,hHash)) ((hKey,hKey)) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) );

	if( dwFlags )
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::badflags());

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
	stcrypt::key_base_ptr this_key (  static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hKey) )  );
    boost::intrusive_ptr<stcrypt::hash_impl_base_t> this_hash ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );

	this_csp->hash_key(this_hash,this_key);

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPSignHash
 -
 *  Purpose:
 *                Create a digital signature from a hash
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  dwKeySpec    -  Key pair to that is used to sign with
 *               IN  sDescription -  Description of data to be signed
 *               IN  dwFlags      -  Flags values
 *               OUT pbSignature  -  Pointer to signature data
 *               IN OUT dwHashLen -  Pointer to the len of the signature data
 *
 *  Returns:
 */

BOOL WINAPI
CPSignHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  DWORD dwKeySpec,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags,
    OUT LPBYTE pbSignature,
    IN OUT LPDWORD pcbSigLen)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((hHash,hHash)) ((dwKeySpec,dwKeySpec)) /*((szDescription,szDescription))*/ ((dwFlags,stcrypt::param_dump_hex(dwFlags))) ((pbSignature,stcrypt::param_dump_array(pbSignature, pcbSigLen))) ((pcbSigLen,stcrypt::param_dump_via_ptr(pcbSigLen))) );

	if( dwFlags )
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::badflags());

	if( !reinterpret_cast<void const*>(hHash) )
		STCRYPT_THROW_EXCEPTION( stcrypt::exception::bad_hash() );


	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
	boost::intrusive_ptr<stcrypt::hash_impl_base_t> this_hash ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );
	this_csp->sign_hash(this_hash,dwKeySpec,pbSignature,pcbSigLen);

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPDestroyHash
 -
 *  Purpose:
 *                Destroy the hash object
 *
 *
 *  Parameters:
 *               IN  hProv     -  Handle to the user identifcation
 *               IN  hHash     -  Handle to hash object
 *
 *  Returns:
 */

BOOL WINAPI
CPDestroyHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((hHash,hHash)));

	boost::intrusive_ptr<stcrypt::hash_impl_base_t> this_hash ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ), false);

    CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPVerifySignature
 -
 *  Purpose:
 *                Used to verify a signature against a hash object
 *
 *
 *  Parameters:
 *               IN  hProv        -  Handle to the user identifcation
 *               IN  hHash        -  Handle to hash object
 *               IN  pbSignture   -  Pointer to signature data
 *               IN  dwSigLen     -  Length of the signature data
 *               IN  hPubKey      -  Handle to the public key for verifying
 *                                   the signature
 *               IN  sDescription -  String describing the signed data
 *               IN  dwFlags      -  Flags values
 *
 *  Returns:
 */

BOOL WINAPI
CPVerifySignature(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  CONST BYTE *pbSignature,
    IN  DWORD cbSigLen,
    IN  HCRYPTKEY hPubKey,
    IN  LPCWSTR szDescription,
    IN  DWORD dwFlags)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((hHash,hHash)) ((pbSignature,stcrypt::param_dump_array(pbSignature,cbSigLen))) ((cbSigLen,cbSigLen)) ((hPubKey,hPubKey)) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) );

	if( dwFlags )
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::badflags());

	if( !reinterpret_cast<void const*>(hHash) )
		STCRYPT_THROW_EXCEPTION( stcrypt::exception::bad_hash() );


	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
	boost::intrusive_ptr<stcrypt::hash_impl_base_t> this_hash ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );
	stcrypt::key_base_ptr this_key (  static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hPubKey) )  );

	this_csp->verify_hash(this_hash,this_key,pbSignature,cbSigLen);

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPGenRandom
 -
 *  Purpose:
 *                Used to fill a buffer with random bytes
 *
 *
 *  Parameters:
 *               IN  hProv         -  Handle to the user identifcation
 *               IN  dwLen         -  Number of bytes of random data requested
 *               IN OUT pbBuffer   -  Pointer to the buffer where the random
 *                                    bytes are to be placed
 *
 *  Returns:
 */

BOOL WINAPI
CPGenRandom(
    IN  HCRYPTPROV hProv,
    IN  DWORD cbLen,
    OUT LPBYTE pbBuffer)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((cbLen,cbLen)) ((pbBuffer,stcrypt::param_dump_array(pbBuffer,cbLen))) );

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );
	this_csp->gen_random(pbBuffer, cbLen);

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPGetUserKey
 -
 *  Purpose:
 *                Gets a handle to a permanent user key
 *
 *
 *  Parameters:
 *               IN  hProv      -  Handle to the user identifcation
 *               IN  dwKeySpec  -  Specification of the key to retrieve
 *               OUT phUserKey  -  Pointer to key handle of retrieved key
 *
 *  Returns:
 */

BOOL WINAPI
CPGetUserKey(
    IN  HCRYPTPROV hProv,
    IN  DWORD dwKeySpec,
    OUT HCRYPTKEY *phUserKey)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS( ((hProv,hProv)) ((dwKeySpec,dwKeySpec)) ((phUserKey,stcrypt::param_dump_via_ptr(phUserKey))) );


	if(!phUserKey)
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::bad_key());
	*phUserKey=0;

	boost::intrusive_ptr<stcrypt::csp_t> this_csp ( static_cast<stcrypt::csp_t*>( reinterpret_cast<void*>(hProv) ) );

	stcrypt::key_base_ptr const user_key = this_csp->get_user_key(dwKeySpec);

	*phUserKey = reinterpret_cast<HCRYPTKEY>( static_cast<void*>( user_key.get() ) ); 
	intrusive_ptr_add_ref( user_key.get() );

	CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPDuplicateHash
 -
 *  Purpose:
 *                Duplicates the state of a hash and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hHash          -  Handle to a hash
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phHash         -  Handle to the new hash
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateHash(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTHASH hHash,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTHASH *phHash)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS(((hProv,hProv)) ((hHash,hHash)) ((pdwReserved,pdwReserved)) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) ((phHash,stcrypt::param_dump_via_ptr(phHash))) );

	if(!hProv)
		STCRYPT_UNEXPECTED();
	if(!hHash)
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::bad_hash());
	if(!phHash)
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::bad_hash());
	if(pdwReserved)
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::invalid_parameter());

	*phHash=0;

	boost::intrusive_ptr<stcrypt::hash_impl_base_t> this_hash ( static_cast<stcrypt::hash_impl_base_t*>( reinterpret_cast<void*>(hHash) ) );

	boost::intrusive_ptr<stcrypt::hash_impl_base_t> hash = this_hash->clone();
	
	*phHash = reinterpret_cast<HCRYPTHASH>( static_cast<void*>( hash.get() ) ); 
	intrusive_ptr_add_ref( hash.get() );

    CSP_CPP_EXCEPTION_GUARD_END
}


/*
 -  CPDuplicateKey
 -
 *  Purpose:
 *                Duplicates the state of a key and returns a handle to it.
 *                This is an optional entry.  Typically it only occurs in
 *                SChannel related CSPs.
 *
 *  Parameters:
 *               IN      hUID           -  Handle to a CSP
 *               IN      hKey           -  Handle to a key
 *               IN      pdwReserved    -  Reserved
 *               IN      dwFlags        -  Flags
 *               IN      phKey          -  Handle to the new key
 *
 *  Returns:
 */

BOOL WINAPI
CPDuplicateKey(
    IN  HCRYPTPROV hProv,
    IN  HCRYPTKEY hKey,
    IN  LPDWORD pdwReserved,
    IN  DWORD dwFlags,
    OUT HCRYPTKEY *phKey)
{
	CSP_CPP_EXCEPTION_GUARD_BEGIN
	CSP_LOG_TRACE;

	STC_DUMP_PARAMS(((hProv,hProv)) ((hKey,hKey)) ((pdwReserved,pdwReserved)) ((dwFlags,stcrypt::param_dump_hex(dwFlags))) ((phKey,stcrypt::param_dump_via_ptr(phKey))) );


	if(!hProv)
		STCRYPT_UNEXPECTED();
	if(!hKey)
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::bad_key());
	if(!phKey)
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::bad_key());
	if(pdwReserved)
		STCRYPT_THROW_EXCEPTION(stcrypt::exception::invalid_parameter());

	*phKey=0;

	boost::intrusive_ptr<stcrypt::cryptoapi_key_base_t> this_key ( static_cast<stcrypt::cryptoapi_key_base_t*>( reinterpret_cast<void*>(hKey) ) );

	boost::intrusive_ptr<stcrypt::cryptoapi_key_base_t> clone = this_key->clone();
	
	*phKey = reinterpret_cast<HCRYPTKEY>( static_cast<void*>( clone.get() ) ); 
	intrusive_ptr_add_ref( clone.get() );

    CSP_CPP_EXCEPTION_GUARD_END
}
//================================================================================================================================================
