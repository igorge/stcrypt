//================================================================================================================================================
// FILE: stcrypt-cng-oid-register.cpp
// (c) GIE 2010-09-12  00:38
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-oid-register.hpp"

#include "stcrypt-crypto-alg-ids.h"
#include "stcrypt-cng-register-exception.hpp"
//================================================================================================================================================
namespace stcrypt {

	namespace {

		void register_hash_alg_oids(){

			CRYPT_OID_INFO oidInfo={0};

			oidInfo.cbSize = sizeof(CRYPT_OID_INFO);

			oidInfo.pszOID=OID_HASH_G34311;
			oidInfo.pwszName= NAME_HASH_G34311;
			oidInfo.dwGroupId =	CRYPT_HASH_ALG_OID_GROUP_ID;
			oidInfo.Algid = CALG_OID_INFO_CNG_ONLY;

			oidInfo.ExtraInfo.cbData=0;
			oidInfo.ExtraInfo.pbData=0;

			oidInfo.pwszCNGAlgid = CNG_G34311_ALGORITHM;
			oidInfo.pwszCNGExtraAlgid = L"";

			if( !CryptRegisterOIDInfo(&oidInfo, 0) ) {
				auto const err = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_registration_failed() << exception::getlasterror_einfo(err) );
			}
			

		} // end of register_hasg_alg_oids

		void unregister_hash_alg_oids(){
			CRYPT_OID_INFO oidInfo={0};

			oidInfo.pszOID=OID_HASH_G34311;
			oidInfo.dwGroupId =	CRYPT_HASH_ALG_OID_GROUP_ID;

			if( !CryptUnregisterOIDInfo(&oidInfo) ){
				auto const err = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_registration_failed() << exception::getlasterror_einfo(err) );
			}
		}

		void register_public_key_alg_oids(){

			CRYPT_OID_INFO oidInfo={0};

			oidInfo.cbSize = sizeof(CRYPT_OID_INFO);

			oidInfo.pszOID=OID_DSTU4145_PUBKEY;
			oidInfo.pwszName=NAME_DSTU4145_PUBKEY;
			oidInfo.dwGroupId =	CRYPT_PUBKEY_ALG_OID_GROUP_ID;
			oidInfo.Algid = CALG_OID_INFO_CNG_ONLY;

			oidInfo.ExtraInfo.cbData=0;
			oidInfo.ExtraInfo.pbData=0;

			oidInfo.pwszCNGAlgid = CNG_DSTU4145;
			oidInfo.pwszCNGExtraAlgid = L"";

			if( !CryptRegisterOIDInfo(&oidInfo, 0) ) {
				auto const err = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_registration_failed() << exception::getlasterror_einfo(err) );
			}

		}


		void unregister_public_key_alg_oids(){
			CRYPT_OID_INFO oidInfo={0};

			oidInfo.pszOID=OID_DSTU4145_PUBKEY;
			oidInfo.dwGroupId =	CRYPT_PUBKEY_ALG_OID_GROUP_ID;

			if( !CryptUnregisterOIDInfo(&oidInfo) ){
				auto const err = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_registration_failed() << exception::getlasterror_einfo(err) );
			}
		}


		void register_sign_alg_oids(){

			CRYPT_OID_INFO oidInfo={0};

			oidInfo.cbSize = sizeof(CRYPT_OID_INFO);

			oidInfo.pszOID=OID_G34311_DSTU4145_SIGN;
			oidInfo.pwszName=NAME_G34311_DSTU4145_SIGN;
			oidInfo.dwGroupId =	CRYPT_SIGN_ALG_OID_GROUP_ID;
			oidInfo.Algid = CALG_OID_INFO_CNG_ONLY;

			oidInfo.ExtraInfo.cbData=0;
			oidInfo.ExtraInfo.pbData=0;

			oidInfo.pwszCNGAlgid = CNG_G34311_ALGORITHM;
			oidInfo.pwszCNGExtraAlgid = CNG_DSTU4145;

			if( !CryptRegisterOIDInfo(&oidInfo, 0) ) {
				auto const err = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_registration_failed() << exception::getlasterror_einfo(err) );
			}

		}


		void unregister_sign_alg_oids(){
			CRYPT_OID_INFO oidInfo={0};

			oidInfo.pszOID=OID_G34311_DSTU4145_SIGN;
			oidInfo.dwGroupId =	CRYPT_SIGN_ALG_OID_GROUP_ID;

			if( !CryptUnregisterOIDInfo(&oidInfo) ){
				auto const err = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_registration_failed() << exception::getlasterror_einfo(err) );
			}
		}


		void register_symm_alg_oids(){

			DWORD extra_info = 256; //TODO: ??

			CRYPT_OID_INFO oidInfo={0};

			oidInfo.cbSize = sizeof(CRYPT_OID_INFO);

			oidInfo.pszOID=OID_G28147_89_GAMMA_CBC;
			oidInfo.pwszName=NAME_G28147_89_GAMMA_CBC;
			oidInfo.dwGroupId =	CRYPT_ENCRYPT_ALG_OID_GROUP_ID;
			oidInfo.Algid = CALG_OID_INFO_CNG_ONLY;

			oidInfo.ExtraInfo.cbData=sizeof(extra_info);
			oidInfo.ExtraInfo.pbData=reinterpret_cast<BYTE*>( &extra_info );

			oidInfo.pwszCNGAlgid = CNG_G28147_89;
			oidInfo.pwszCNGExtraAlgid = L"";

			if( !CryptRegisterOIDInfo(&oidInfo, 0) ) {
				auto const err = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_registration_failed() << exception::getlasterror_einfo(err) );
			}

		}


		void unregister_symm_alg_oids(){
			CRYPT_OID_INFO oidInfo={0};

			oidInfo.pszOID=OID_G28147_89_GAMMA_CBC;
			oidInfo.dwGroupId =	CRYPT_ENCRYPT_ALG_OID_GROUP_ID;

			if( !CryptUnregisterOIDInfo(&oidInfo) ){
				auto const err = GetLastError();
				STCRYPT_THROW_EXCEPTION( exception::reg::oid_registration_failed() << exception::getlasterror_einfo(err) );
			}
		}


	} // end of anon ns

	void cng_register_oids(){

		register_hash_alg_oids();
		register_public_key_alg_oids();
		register_symm_alg_oids();
		register_sign_alg_oids();

	}

	void cng_unregister_oids(){

		unregister_sign_alg_oids();
		unregister_symm_alg_oids();
		unregister_public_key_alg_oids();
		unregister_hash_alg_oids();

	}

}
//================================================================================================================================================
