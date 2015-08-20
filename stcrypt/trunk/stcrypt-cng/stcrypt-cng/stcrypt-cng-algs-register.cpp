//================================================================================================================================================
// FILE: stcrypt-cng-algs-register.cpp
// (c) GIE 2010-09-12  00:38
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-algs-register.hpp"
//================================================================================================================================================
#include "stcrypt-debug.hpp"
#include "stcrypt-exceptions.hpp"

#include "stcrypt-crypto-alg-ids.h"

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>

#include <bcrypt.h>
//================================================================================================================================================
#define STC_ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))
//================================================================================================================================================
namespace stcrypt {

	void cng_register_algorithms(){
		CSP_LOG_TRACE
		
		//hash  reg
		PWSTR	cng_hash_functions[1] = {0};
		cng_hash_functions[0]=CNG_G34311_ALGORITHM;


		CRYPT_INTERFACE_REG	cng_prov_intrface_hash = {0};
		cng_prov_intrface_hash.dwInterface = BCRYPT_HASH_INTERFACE;
		cng_prov_intrface_hash.dwFlags = CRYPT_LOCAL;
		cng_prov_intrface_hash.cFunctions = STC_ARRAY_SIZE(cng_hash_functions);
		cng_prov_intrface_hash.rgpszFunctions = &cng_hash_functions[0];

		//symm reg
		PWSTR	cng_symm_functions[1] = {0};
		cng_symm_functions[0]=CNG_G28147_89;


		CRYPT_INTERFACE_REG	cng_prov_intrface_symm = {0};
		cng_prov_intrface_symm.dwInterface = BCRYPT_CIPHER_INTERFACE;
		cng_prov_intrface_symm.dwFlags = CRYPT_LOCAL;
		cng_prov_intrface_symm.cFunctions = STC_ARRAY_SIZE(cng_symm_functions);
		cng_prov_intrface_symm.rgpszFunctions = &cng_symm_functions[0];

		//asym
		PWSTR	cng_asymm_functions[1] = {0};
		cng_asymm_functions[0]=CNG_DSTU4145;


		CRYPT_INTERFACE_REG	cng_prov_intrface_asymm = {0};
		cng_prov_intrface_asymm.dwInterface = BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE;
		cng_prov_intrface_asymm.dwFlags = CRYPT_LOCAL;
		cng_prov_intrface_asymm.cFunctions = STC_ARRAY_SIZE(cng_asymm_functions);
		cng_prov_intrface_asymm.rgpszFunctions = &cng_asymm_functions[0];

		//storage
		PWSTR	cng_keystorage_functions[1] = {0};
		cng_keystorage_functions[0]=NCRYPT_KEY_STORAGE_ALGORITHM;


		CRYPT_INTERFACE_REG	cng_prov_intrface_keystorage = {0};
		cng_prov_intrface_keystorage.dwInterface = NCRYPT_KEY_STORAGE_INTERFACE;
		cng_prov_intrface_keystorage.dwFlags = CRYPT_LOCAL;
		cng_prov_intrface_keystorage.cFunctions = STC_ARRAY_SIZE(cng_keystorage_functions);
		cng_prov_intrface_keystorage.rgpszFunctions = &cng_keystorage_functions[0];

		//rng
		PWSTR	cng_rng_functions[1] = {0};
		cng_rng_functions[0]=BCRYPT_RNG_ALGORITHM;


		CRYPT_INTERFACE_REG	cng_prov_intrface_rng = {0};
		cng_prov_intrface_rng.dwInterface = BCRYPT_RNG_INTERFACE;
		cng_prov_intrface_rng.dwFlags = CRYPT_LOCAL;
		cng_prov_intrface_rng.cFunctions = STC_ARRAY_SIZE(cng_rng_functions);
		cng_prov_intrface_rng.rgpszFunctions = &cng_rng_functions[0];

		//secret agr
		PWSTR	cng_secret_agr_functions[1] = {0};
		cng_secret_agr_functions[0]=BCRYPT_DH_ALGORITHM;


		CRYPT_INTERFACE_REG	cng_prov_intrface_secret_agr = {0};
		cng_prov_intrface_secret_agr.dwInterface = BCRYPT_SECRET_AGREEMENT_INTERFACE;
		cng_prov_intrface_secret_agr.dwFlags = CRYPT_LOCAL;
		cng_prov_intrface_secret_agr.cFunctions = STC_ARRAY_SIZE(cng_secret_agr_functions);
		cng_prov_intrface_secret_agr.rgpszFunctions = &cng_secret_agr_functions[0];

		//common reg
		PCRYPT_INTERFACE_REG cng_prov_intrfaces[] = {
			&cng_prov_intrface_hash,
			&cng_prov_intrface_symm,
			&cng_prov_intrface_asymm,
			&cng_prov_intrface_keystorage,
			&cng_prov_intrface_rng,
			&cng_prov_intrface_secret_agr
		};

		CRYPT_IMAGE_REG	   	cng_prov_use_mode_info = {0};
		cng_prov_use_mode_info.pszImage = L"stcrypt-cng.dll"; //TODO: extract name from rt module
		cng_prov_use_mode_info.cInterfaces = STC_ARRAY_SIZE(cng_prov_intrfaces);
		cng_prov_use_mode_info.rgpInterfaces = &cng_prov_intrfaces[0];

		PWSTR prov_aliases[] = {
			CNG_STCRYPT_KEYSTORAGE
		};

		CRYPT_PROVIDER_REG	cng_prov_reg_info = {0};
		cng_prov_reg_info.rgpszAliases = &prov_aliases[0];
		cng_prov_reg_info.cAliases = STC_ARRAY_SIZE(prov_aliases);
		cng_prov_reg_info.pUM = &cng_prov_use_mode_info;

		NTSTATUS const r1 = BCryptRegisterProvider(STCRYPT_PROVIDER_NAME_W, CRYPT_OVERWRITE, &cng_prov_reg_info);
		if(r1!=STATUS_SUCCESS) STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(r1) );

		struct context_reg_info_t {
			ULONG	m_interface;
			LPCWSTR m_function;
			ULONG	m_priority;
		};

		context_reg_info_t context_reg_info[]={
			{NCRYPT_KEY_STORAGE_INTERFACE,				NCRYPT_KEY_STORAGE_ALGORITHM,	CRYPT_PRIORITY_BOTTOM},
			{BCRYPT_HASH_INTERFACE,						CNG_G34311_ALGORITHM,			CRYPT_PRIORITY_TOP},
			{BCRYPT_CIPHER_INTERFACE,					CNG_G28147_89,					CRYPT_PRIORITY_TOP},
			{BCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE,	CNG_DSTU4145,					CRYPT_PRIORITY_TOP},
			{BCRYPT_RNG_INTERFACE,						BCRYPT_RNG_ALGORITHM,	CRYPT_PRIORITY_BOTTOM}
		};

		std::for_each( boost::begin(context_reg_info), boost::end(context_reg_info), [](context_reg_info_t const& ri){
			NTSTATUS const r2 = BCryptAddContextFunctionProvider(
				CRYPT_LOCAL, 
				NULL, // Default context.
				ri.m_interface, 
				ri.m_function,
				STCRYPT_PROVIDER_NAME_W,
				ri.m_priority);

			if(r2!=STATUS_SUCCESS)  STCRYPT_THROW_EXCEPTION( exception::cng_call() << exception::ntstatus_einfo(r2) );;
		} );

 		
	}

	void cng_unregister_algorithms(){

	}

} // end stcrypt ns

//================================================================================================================================================
