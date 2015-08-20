//================================================================================================================================================
// FILE: stcrypt-cng-oid-func-register.cpp
// (c) GIE 2010-09-13  16:08
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-oid-func-register.hpp"
//================================================================================================================================================
#include "stcrypt-cng-dll-utils.hpp"
#include "stcrypt-debug.hpp"
#include "stcrypt-cng-register-exception.hpp"
#include "stcrypt-crypto-alg-ids.h"

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>

#include <boost/preprocessor/cat.hpp>
#include <boost/preprocessor/stringize.hpp>
//================================================================================================================================================
namespace stcrypt {

#define STCRYPT_INSTALL_DUMMY_EX(operation,id)	\
	{operation, BOOST_PP_CAT("STCRYPT_CatchAllDummy", BOOST_PP_STRINGIZE(id) ), OID_HASH_G34311},	\
	{operation, BOOST_PP_CAT("STCRYPT_CatchAllDummy", BOOST_PP_STRINGIZE(id) ), OID_DSTU4145_PUBKEY},	\
	{operation, BOOST_PP_CAT("STCRYPT_CatchAllDummy", BOOST_PP_STRINGIZE(id) ), OID_G34311_DSTU4145_SIGN},	\
	{operation, BOOST_PP_CAT("STCRYPT_CatchAllDummy", BOOST_PP_STRINGIZE(id) ), OID_HASH_G34311},	\
	{operation, BOOST_PP_CAT("STCRYPT_CatchAllDummy", BOOST_PP_STRINGIZE(id) ), OID_G28147_89_GAMMA_CBC},	\
	/**/

#define STCRYPT_INSTALL_DUMMY(operation) STCRYPT_INSTALL_DUMMY_EX(operation, 0)	


	namespace {
		struct oid_reg_info {
			char const* impl_function_name;
			char const* function_name;
			char const* oid;
		};

		oid_reg_info const oids_reg[] = {

			STCRYPT_INSTALL_DUMMY(CRYPT_OID_ENCODE_OBJECT_EX_FUNC)
			STCRYPT_INSTALL_DUMMY(CRYPT_OID_DECODE_OBJECT_EX_FUNC)
			STCRYPT_INSTALL_DUMMY(CRYPT_OID_EXTRACT_ENCODED_SIGNATURE_PARAMETERS_FUNC)
			STCRYPT_INSTALL_DUMMY(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_FROM_BCRYPT_HANDLE_FUNC)
			STCRYPT_INSTALL_DUMMY(CRYPT_OID_IMPORT_PRIVATE_KEY_INFO_FUNC)
			STCRYPT_INSTALL_DUMMY(CRYPT_OID_EXPORT_PRIVATE_KEY_INFO_FUNC)
			STCRYPT_INSTALL_DUMMY(CMSG_OID_EXPORT_MAIL_LIST_FUNC)
			STCRYPT_INSTALL_DUMMY(CMSG_OID_EXPORT_KEY_TRANS_FUNC)
			STCRYPT_INSTALL_DUMMY(CMSG_OID_GEN_CONTENT_ENCRYPT_KEY_FUNC)
			STCRYPT_INSTALL_DUMMY(CMSG_OID_IMPORT_KEY_AGREE_FUNC)
			STCRYPT_INSTALL_DUMMY(CMSG_OID_IMPORT_KEY_TRANS_FUNC)
			STCRYPT_INSTALL_DUMMY(CMSG_OID_IMPORT_MAIL_LIST_FUNC)
			STCRYPT_INSTALL_DUMMY(CMSG_OID_EXPORT_MAIL_LIST_FUNC)
			STCRYPT_INSTALL_DUMMY(CMSG_OID_CNG_IMPORT_CONTENT_ENCRYPT_KEY_FUNC)

			STCRYPT_INSTALL_DUMMY_EX(CRYPT_OID_VERIFY_ENCODED_SIGNATURE_FUNC,1)
			STCRYPT_INSTALL_DUMMY_EX(CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC,2)
			STCRYPT_INSTALL_DUMMY_EX(CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC,3)
			STCRYPT_INSTALL_DUMMY_EX(CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC,4)

			{CRYPT_OID_EXPORT_PUBLIC_KEY_INFO_EX2_FUNC, "STCRYPT_ExportPublicKeyInfoEx2", OID_DSTU4145_PUBKEY},

			{CRYPT_OID_IMPORT_PUBLIC_KEY_INFO_EX2_FUNC, "STCRYPT_ImportPublicKeyInfoEx2", OID_DSTU4145_PUBKEY},

			{CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, "STCRYPT_SignAndEncodeHash", OID_G34311_DSTU4145_SIGN},
			
			{CRYPT_OID_SIGN_AND_ENCODE_HASH_FUNC, "STCRYPT_SignAndEncodeHash", OID_DSTU4145_PUBKEY}, // ??

			{CRYPT_OID_VERIFY_ENCODED_SIGNATURE_FUNC, "STCRYPT_VerifyEncodedSignature", OID_G34311_DSTU4145_SIGN},
			{CRYPT_OID_VERIFY_ENCODED_SIGNATURE_FUNC, "STCRYPT_VerifyEncodedSignature", OID_DSTU4145_PUBKEY},			//TODO: CryptMsgControl searches for PUB key oid to verify signature, wtf?
			//{CRYPT_OID_VERIFY_ENCODED_SIGNATURE_FUNC, "STCRYPT_VerifyEncodedSignature", OID_HASH_G34311},			//TODO: CryptMsgControl searches for PUB key oid to verify signature, wtf?

			{CRYPT_OID_ENCODE_OBJECT_EX_FUNC, "STCRYPT_CryptEncodeObjectEx", OID_HASH_G34311},
			{CRYPT_OID_ENCODE_OBJECT_EX_FUNC, "STCRYPT_CryptEncodeObjectEx", OID_DSTU4145_PUBKEY},
			{CRYPT_OID_ENCODE_OBJECT_EX_FUNC, "STCRYPT_CryptEncodeObjectEx", OID_G34311_DSTU4145_SIGN},

			{CRYPT_OID_DECODE_OBJECT_EX_FUNC, "STCRYPT_CryptDencodeObjectEx", OID_HASH_G34311},
			{CRYPT_OID_DECODE_OBJECT_EX_FUNC, "STCRYPT_CryptDencodeObjectEx", OID_DSTU4145_PUBKEY},
			{CRYPT_OID_DECODE_OBJECT_EX_FUNC, "STCRYPT_CryptDencodeObjectEx", OID_G34311_DSTU4145_SIGN},





		};
	} // end anon ns

	void cng_register_oid_funcs(){

		CSP_LOG_TRACE

		auto const& dll_path = self_dll_path();

		std::for_each( boost::begin(oids_reg), boost::end(oids_reg), [&](oid_reg_info const& v){
			if(!CryptRegisterOIDFunction(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,	v.impl_function_name,  v.oid, dll_path.c_str(), v.function_name )){
				assert(false);
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_func_registration_failed() <<  exception::error_str_einfo(v.impl_function_name) ) ;
			}
		});

		
	}


	void cng_unregister_oid_funcs(){
		STCRYPT_UNIMPLEMENTED();
	}

}
//================================================================================================================================================
