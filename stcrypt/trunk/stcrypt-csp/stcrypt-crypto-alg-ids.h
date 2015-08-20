//================================================================================================================================================
// FILE: crypto_alg_ids.h
// (c) GIE 2009-10-27  13:22
//
//================================================================================================================================================
#ifndef H_GUARD_CRYPTO_ALG_IDS_2009_10_27_13_22
#define H_GUARD_CRYPTO_ALG_IDS_2009_10_27_13_22
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#define CALG_ID_G28147_89_BLOCKSIZE 8
#define STCRYPT_PROVIDER_NAME_W L"STCRYPT"
#define STCRYPT_PROVIDER_NAME_A "STCRYPT"
//TODO: find proper way to assign ids
#define STCRYPT_PROVIDER_TYPE 30

#define CNG_STCRYPT_KEYSTORAGE L"STCRYPT-KEYSTORAGE1"

#define ALG_TYPE_DSTU4145                    (10 << 9)

#define ALG_SID_HASH_G34311	30
#define ALG_SID_G28147_89_SIMPLE 31
#define ALG_SID_G28147_89_GAMMA 32
#define ALG_SID_G28147_89_GAMMA_CBC 33
#define ALG_SID_G28147_89_MAC 34

#define ALG_SID_DSTU4145_ANY 35


#define CALG_ID_HASH_G34311			(ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_HASH_G34311)
#define CALG_ID_G28147_89_MAC		(ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_G28147_89_MAC)

#define CALG_ID_G28147_89_SIMPLE	(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_G28147_89_SIMPLE)
#define CALG_ID_G28147_89_GAMMA		(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_G28147_89_GAMMA)
#define CALG_ID_G28147_89_GAMMA_CBC	(ALG_CLASS_DATA_ENCRYPT|ALG_TYPE_BLOCK|ALG_SID_G28147_89_GAMMA_CBC)

#define CNG_G28147_89	L"G28147-89"

#define CALG_DSTU4145_KEYX           (ALG_CLASS_KEY_EXCHANGE|ALG_TYPE_DSTU4145|ALG_SID_DSTU4145_ANY)
#define CALG_DSTU4145_SIGN           (ALG_CLASS_SIGNATURE|ALG_TYPE_DSTU4145|ALG_SID_DSTU4145_ANY)

#define CNG_DSTU4145	L"DSTU4145"
#define CNG_DSTU4145_BLOB_MAGIC_PUBLIC	(ULONG)(0x32445453UL)
#define CNG_DSTU4145_BLOB_MAGIC_PRIVATE	(ULONG)(0x31445453UL)

#define NCNG_DSTU4145	CNG_DSTU4145

//TODO: assign proper OIDs

// xxx!2 - enc
#define OID_G28147_89_GAMMA_CBC "1.2.804.2.1.1.1.1.2.11"  /*TODO: find proper*/
#define NAME_G28147_89_GAMMA_CBC L"GOST-28147-GAMMA-CBC"


// xxx!1 -- hash
#define OID_HASH_G34311			"1.2.804.2.1.1.1.1.2.1" 
#define NAME_HASH_G34311	L"GOST-3411 HASH"
#define CNG_G34311_ALGORITHM	L"G34311"

// xxx!3 -- key alg
#define OID_DSTU4145_SIGN  "1.2.804.2.1.1.1.1.6.1"		/*TODO: find proper*/
#define NAME_DSTU4145_SIGN	L"DSTU-4145 KEY"

#define NAME_DSTU4145_PUBKEY	L"DSTU-4145 KEY"
#define OID_DSTU4145_PUBKEY  "1.2.804.2.1.1.1.1.6.1"		/*TODO: find proper*/

// xxx!4 -- key alg + hash
#define OID_G34311_DSTU4145     "1.2.804.2.1.1.1.1.3.1.1.2.9"
#define NAME_G34311_DSTU4145	L"GOST-34311-DSTU-4145 HASH+KEY"
#define CALG_G34311_DSTU4145	333 /*TODO*/


#define OID_G34311_DSTU4145_SIGN     "1.2.804.2.1.1.1.1.3.1.1.2.9"
#define NAME_G34311_DSTU4145_SIGN	L"GOST-34311-DSTU-4145 HASH+KEY"

//#define CNG_G34311_DSTU4145_SIGN	L"G34311_DSTU4145_SIGN"


//TODO: remove
#define SCTRYPT_ALG_OID 1,2,840,113549,1,1,1


//================================================================================================================================================
#endif
//================================================================================================================================================
