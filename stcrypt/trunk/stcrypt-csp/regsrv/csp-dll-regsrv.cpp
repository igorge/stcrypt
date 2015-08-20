//================================================================================================================================================
// FILE: csp-dll-regsrv.cpp
// (c) GIE 2010-03-02  14:53
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
//#include "csp-dll-regsrv.hpp"
#include "../stcrypt-debug.hpp"
#include "../stcrypt-exceptions.hpp"
#include "../stcrypt-crypto-alg-ids.h"
#include "../util-fun-param-printer.hpp"

#include <sstream>

#include "BIT_STRING.h"

#include <WinCrypt.h>

#include <stdexcept>
#include <vector>
//================================================================================================================================================
namespace stcrypt {

    void register_oids(){

int const rc = CryptSetProvider(
		STCRYPT_PROVIDER_NAME_W,
		STCRYPT_PROVIDER_TYPE
	);
    if(!rc) STCRYPT_UNEXPECTED();


        {// HASH alg
            CRYPT_OID_INFO oidInfo={0};

            oidInfo.cbSize = sizeof(CRYPT_OID_INFO);

            oidInfo.pszOID=OID_HASH_G34311;
            oidInfo.pwszName= NAME_HASH_G34311;
            oidInfo.dwGroupId =	CRYPT_HASH_ALG_OID_GROUP_ID;
            oidInfo.Algid = CALG_ID_HASH_G34311;
            oidInfo.ExtraInfo.cbData=0;
            oidInfo.ExtraInfo.pbData=0;

            int const rc = CryptRegisterOIDInfo(&oidInfo,0);
            if(rc)
                printf("\nHash algorithm registered");
            else {
                throw std::exception("Error registering hash algorithm");
            }

        }


        { // pubkey alg
			std::vector<DWORD> extra_data;
			extra_data.resize(3,0);
			extra_data[2]=256; //bit length?

            CRYPT_OID_INFO oidInfo={0};

            oidInfo.cbSize = sizeof(CRYPT_OID_INFO);

            oidInfo.pszOID=OID_DSTU4145_SIGN;
            oidInfo.pwszName=NAME_DSTU4145_SIGN;
            oidInfo.dwGroupId =	CRYPT_PUBKEY_ALG_OID_GROUP_ID;
            oidInfo.Algid = CALG_DSTU4145_SIGN;

			oidInfo.ExtraInfo.cbData=extra_data.size()*sizeof(DWORD);
			oidInfo.ExtraInfo.pbData=reinterpret_cast<BYTE*>(&extra_data[0]);

            int const rc = CryptRegisterOIDInfo(&oidInfo,0);
            if(rc)
                printf("\nHash algorithm registered");
            else {
                throw std::exception("Error registering hash algorithm");
            }

        }


        { // signing alg -- key alg + key
            std::vector<DWORD> extra_data;
            extra_data.resize(3,0);
            extra_data[0]=CALG_DSTU4145_SIGN;
			extra_data[1]=0; // flags
            extra_data[2]=STCRYPT_PROVIDER_TYPE;


            CRYPT_OID_INFO oidInfo={0};

            oidInfo.cbSize = sizeof(CRYPT_OID_INFO);

            oidInfo.pszOID=OID_G34311_DSTU4145;
            oidInfo.pwszName= NAME_G34311_DSTU4145;
            oidInfo.dwGroupId =	CRYPT_SIGN_ALG_OID_GROUP_ID;
            oidInfo.Algid = CALG_G34311_DSTU4145;
			
            oidInfo.ExtraInfo.cbData=extra_data.size()*sizeof(DWORD);
            oidInfo.ExtraInfo.pbData=reinterpret_cast<BYTE*>(&extra_data[0]);

            BOOL const rc = CryptRegisterOIDInfo(&oidInfo,0);
            if(!rc) {
                throw std::exception("Error registering OID_G34311_DSTU4145 algorithm");
            }

        }

		{// CALG_ID_G28147_89_GAMMA_CBC

			CRYPT_OID_INFO oidInfo={0};

			oidInfo.cbSize = sizeof(CRYPT_OID_INFO);

			oidInfo.pszOID=OID_G28147_89_GAMMA_CBC;
			oidInfo.pwszName= NAME_G28147_89_GAMMA_CBC;
			oidInfo.dwGroupId =	CRYPT_ENCRYPT_ALG_OID_GROUP_ID;
			oidInfo.Algid = CALG_ID_G28147_89_GAMMA_CBC;

			//oidInfo.ExtraInfo.cbData=extra_data.size()*sizeof(DWORD);
			//oidInfo.ExtraInfo.pbData=reinterpret_cast<BYTE*>(&extra_data[0]);

			BOOL const rc = CryptRegisterOIDInfo(&oidInfo,0);
			if(!rc) {
				throw std::exception("Error registering OID_G34311_DSTU4145 algorithm");
			}

		}

        {

            if(!CryptRegisterOIDFunction(
                X509_ASN_ENCODING,                  // Encoding type
                "CryptDllEncodePublicKeyAndParameters", 
                //"CryptDllExportPublicKeyInfoEx",
                //CRYPT_OID_ENCODE_OBJECT_EX_FUNC,       // Function name
                OID_DSTU4145_SIGN,             // OID
                L"c:\\work\\workcrypto\\stcrypt\\trunk\\debug\\stcrypt-csp.dll",                     // Dll name
                "STCRYPT_EncodePublicKeyAndParameters"   // Override function
                ))                                  //   name
            {
				assert(false);
                throw std::exception("Error registering CryptRegisterOIDFunction()");
            }

			if(!CryptRegisterOIDFunction(
				X509_ASN_ENCODING,                  // Encoding type
				"CryptDllConvertPublicKeyInfo", 
				OID_DSTU4145_SIGN,             // OID
				L"c:\\work\\workcrypto\\stcrypt\\trunk\\debug\\stcrypt-csp.dll",                     // Dll name
				"STCRYPT_ConvertPublicKeyInfo"   // Override function
				))                                  //   name
			{
				assert(false);
				throw std::exception("Error registering CryptRegisterOIDFunction()");
			}



        }


    }

}

BOOL WINAPI DUMMY1(){

    return FALSE;

}

BOOL WINAPI DUMMY2(){

    return FALSE;

}
BOOL WINAPI DUMMY3(){

    return FALSE;

}
BOOL WINAPI DUMMY4(){

    return FALSE;

}

BOOL WINAPI dedeNewCertificateTypeEncodeObject(
    IN DWORD /*dwCertEncodingType*/,
    IN LPCSTR /*lpszStructType*/,
    IN PCTL_USAGE pInfo,
    OUT BYTE *pbEncoded,
    IN OUT DWORD *pcbEncoded)
{
    return FALSE;
    //Encoding logic goes here.
}

namespace impl { namespace { 

	int aatoycert_t__x509_save__out(const void *buffer, size_t size, void *key) {
		assert(key);

		if(size!=0){
			assert(buffer);
			std::ostream & out_stream = *static_cast<std::ostream*>(key);
			if( out_stream.bad() ) {
				assert(!"stream.bad()");
				return -1;
			}
			BOOST_STATIC_ASSERT(sizeof(size_t)==sizeof(std::streamsize));
			out_stream.write( static_cast<char const*>( buffer ), static_cast<std::streamsize>( size ) );
			if( !out_stream.good() ) {
				assert(!"!stream.good()");
				return -1;
			}
		} else {
			STCRYPT_LOG_PRINT_EX("x509asn-warning","ASN.1 generator requested 0-sized write");
		}

		return 0;            
	} }

BOOL WINAPI STCRYPT_EncodePublicKeyAndParameters(
	DWORD dwCertEncodingType,  // IN
	LPCSTR lpszStructType,     // IN Ц OID алгоритма
	const void* pvStructInfo,    // IN Ц така€ же структура, как на выходе ConvertPublicKeyInfo
	DWORD  nStructLen,  // IN Ц длина входной структуры
	DWORD  dwFlags,     // IN Ц обычно 0
	DWORD  Unk,         // неизвестно
	BYTE** pbPubKey,    // OUT Ц открытый ключ в ASN.1 DER
	DWORD* pcPubKeyLen, // OUT Ц длина открытого ключа 
	BYTE** pbParams,    // OUT Ц параметры открытого ключа
	DWORD* pcParamsLen  // OUT Ц длина параметров
	){

		CSP_LOG_TRACE

		STC_DUMP_PARAMS( ((dwCertEncodingType,dwCertEncodingType)) 
						 ((lpszStructType,stcrypt::param_dump_str(lpszStructType))) 
						 ((pvStructInfo,stcrypt::param_dump_array(reinterpret_cast<BYTE const*>(pvStructInfo),nStructLen))) 
						 ((nStructLen,nStructLen)) 
						 ((dwFlags,dwFlags)) ((Unk,Unk))
						 ((pbPubKey,stcrypt::param_dump_array_via_ptr(pbPubKey,pcPubKeyLen))) 
						 ((pcPubKeyLen,stcrypt::param_dump_via_ptr(pcPubKeyLen)))
						 ((pbParams,stcrypt::param_dump_array_via_ptr(pbParams, pcParamsLen)))
						 ((pcParamsLen,stcrypt::param_dump_via_ptr(pcParamsLen))) 
						 );

		BIT_STRING_t data_out={0}; //TODO!!! free on scope exit

		data_out.buf = (uint8_t *)alloca(nStructLen);

		data_out.size = static_cast<int>(nStructLen); //nothrow
		memcpy(data_out.buf, pvStructInfo, nStructLen); //nothrow
		data_out.bits_unused = 0; //nothrow

		std::ostringstream cert_blob_to_sign;

		if( der_encode(&asn_DEF_BIT_STRING, &data_out, impl::aatoycert_t__x509_save__out, static_cast<void*>( & static_cast<std::ostream&>( cert_blob_to_sign ) ) ).encoded==-1 ) {
			STCRYPT_UNEXPECTED();
		}
		std::string const& encoded_key_blob = cert_blob_to_sign.str();
		*pcPubKeyLen=encoded_key_blob.size();
		*pbPubKey = reinterpret_cast<BYTE*>( LocalAlloc(0, encoded_key_blob.size()) ); //TODO!!! check who owns memory
		assert(*pbPubKey);

		memcpy(*pbPubKey, encoded_key_blob.data(), encoded_key_blob.size());


		return TRUE;
}

std::string param_dump(CRYPT_OBJID_BLOB const&v){
	std::ostringstream os;
	os <<"(CRYPT_OBJID_BLOB ";
	os<< stcrypt::param_dump_array(v.pbData, v.cbData) << " "<<v.cbData;
	os<< ")";

	return os.str();

}

std::string param_dump(CRYPT_ALGORITHM_IDENTIFIER const&v){
	std::ostringstream os;
	os <<"(CRYPT_ALGORITHM_IDENTIFIER ";
	os <<stcrypt::param_dump_str(v.pszObjId) <<" ";
	os <<param_dump(v.Parameters);
	os<< ")";

	return os.str();
}

std::string param_dump(CRYPT_BIT_BLOB const&v){
	std::ostringstream os;
	os <<"(CRYPT_BIT_BLOB ";
	os<< stcrypt::param_dump_array(v.pbData, v.cbData) << " "<<v.cbData << " " << v.cUnusedBits;
	os<< ")";

	return os.str();
}

std::string param_dump(CERT_PUBLIC_KEY_INFO const& v){
	std::ostringstream os;
	os << "(CERT_PUBLIC_KEY_INFO ";
	os << param_dump(v.Algorithm)<<" ";
	os << param_dump(v.PublicKey);
	os <<")";

	return os.str();
}

std::string param_dump(CERT_PUBLIC_KEY_INFO const*const v){
	std::ostringstream os;
	os << "@"<<static_cast<void const*>(v)<<"=";
	if(v){
		os <<param_dump(*v);
	} else {
		os << "<NULL>";
	}

	return os.str();
}


BOOL WINAPI STCRYPT_ConvertPublicKeyInfo(
								   DWORD dwCertEncodingType,   // IN - 
								   // IN Ц буфер с ключом Ц указатель на структуру CERT_PUBLIC_KEY_INFO
								   VOID *EncodedKeyInfo, 
								   DWORD dwAlg,        // IN Ц AlgId ключа
								   DWORD dwFlags,      // IN Ц обычно 0
								   // OUT  Ц двойной указатель на структуру. 
								   // ¬ заголовке структуры идет сначала PUBLICKEYSTRUC, затем DSSPUBKEY, 
								   // а затем сам ключ с параметрами.
								   BYTE** ppStructInfo,  
								   DWORD* StructLen    // OUT  Ц длина структуры
								   ){
CSP_LOG_TRACE

	CERT_PUBLIC_KEY_INFO* cert_public_key_info = reinterpret_cast<CERT_PUBLIC_KEY_INFO*>(EncodedKeyInfo);

		STC_DUMP_PARAMS( ((dwCertEncodingType,dwCertEncodingType)) 
						 ((dwAlg,dwAlg))
						 ((dwFlags,dwFlags))	
						 ((ppStructInfo,stcrypt::param_dump_array_via_ptr(ppStructInfo, StructLen)))
						 ((StructLen,stcrypt::param_dump_via_ptr(StructLen)))
						 ((cert_public_key_info,param_dump(cert_public_key_info)))		
						 );


	//if(dwAlg!=CALG_DSTU4145_SIGN)
		//return FALSE; TODO!!!

	if(cert_public_key_info->PublicKey.cUnusedBits!=0){
		STCRYPT_UNEXPECTED1("bad ASN.1 key blob");
	}

	BIT_STRING_t * data_out=0; //TODO!!! free on scope exit

	asn_dec_rval_t const status = ber_decode(0, &asn_DEF_BIT_STRING, (void**)(&data_out), cert_public_key_info->PublicKey.pbData, cert_public_key_info->PublicKey.cbData );
	if( status.code!=RC_OK ){ //TODO
		ASN_STRUCT_FREE(asn_DEF_BIT_STRING, data_out);
		STCRYPT_UNEXPECTED1("ber_decode have failed");
	}

	*StructLen = data_out->size;
	*ppStructInfo = reinterpret_cast<BYTE*>( HeapAlloc(GetProcessHeap(), 0, data_out->size) );
	memcpy(*ppStructInfo, data_out->buf, data_out->size);

	return TRUE;
	

return FALSE;
}



} // ns impl



STDAPI DllRegisterServer(void)
{
    CSP_LOG_TRACE

    try {
        stcrypt::register_oids();

    } catch(...) {
        //TODO:
        return E_FAIL;
    }
    return S_OK;
}

STDAPI DllUnregisterServer(void)
{
    CSP_LOG_TRACE

    try {
        
    } catch(...) {
        //TODO:
        return E_FAIL;
    }
    return S_OK;
}

//================================================================================================================================================
