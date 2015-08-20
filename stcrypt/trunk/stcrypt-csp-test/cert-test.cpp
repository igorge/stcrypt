//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include <WinCrypt.h>
#include <iostream>
//================================================================================================================================================
#include "csp-test-common.hpp"

#include "../stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../stcrypt-csp/stcrypt-crypto-alg-ids.h"
#include "../stcrypt-csp/stcrypt-mspki-helpers.hpp"


#include "boost/scope_exit.hpp"

#include <vector>
//================================================================================================================================================


void import_into_ms_store2(PCCERT_CONTEXT ms_cert_ctx, std::wstring const& cert_store_name ){




		HCERTSTORE const ms_cert_store = CertOpenStore (
		CERT_STORE_PROV_SYSTEM,
		0,
		0,
		/* CERT_STORE_OPEN_EXISTING_FLAG | */
		CERT_SYSTEM_STORE_CURRENT_USER, //CERT_SYSTEM_STORE_LOCAL_MACHINE,
		cert_store_name.c_str());

	if(ms_cert_store==0) STCRYPT_UNEXPECTED1("CertOpenStore have failed");

	BOOST_SCOPE_EXIT( (ms_cert_store) ){
		BOOL const r = CertCloseStore (ms_cert_store,0);
		assert(r!=0);
	} BOOST_SCOPE_EXIT_END

		if (!CertAddCertificateContextToStore (
			ms_cert_store,
			ms_cert_ctx,
			CERT_STORE_ADD_ALWAYS,
			NULL))
			STCRYPT_UNEXPECTED1("CertAddCertificateContextToStore have failed");



}

void import_into_ms_store(std::string const& file_name, PCCERT_CONTEXT ms_cert_ctx){


	
		HCERTSTORE const ms_cert_store = CertOpenStore (
		CERT_STORE_PROV_MEMORY,
		0,
		0,
		0,
		0);
		if(ms_cert_store==0) {
			DWORD const errcode = GetLastError();
			std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 

			STCRYPT_UNEXPECTED1("CertOpenStore have failed");
		}

	BOOST_SCOPE_EXIT( (ms_cert_store) ){
		BOOL const r = CertCloseStore (ms_cert_store,0);
		assert(r!=0);
	} BOOST_SCOPE_EXIT_END

		if (!CertAddCertificateContextToStore (
			ms_cert_store,
			ms_cert_ctx,
			CERT_STORE_ADD_ALWAYS,
			NULL)){
				DWORD const errcode = GetLastError();
				std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 
				STCRYPT_UNEXPECTED1("CertAddCertificateContextToStore have failed");

		}

		HANDLE hFile;
		if (hFile = CreateFile(
			L"test-cert.cer", // The file name
			GENERIC_WRITE, // Access mode: write to this file
			0, // Share mode
			NULL, // Uses the DACL created previously
			CREATE_ALWAYS, // How to create
			FILE_ATTRIBUTE_NORMAL, // File attributes
			NULL)) // Template
		{
			printf("The file was created successfully.\n");
		}
		else
		{
			printf("An error occurred during creating of the file!\n");
			return;
		}

		//-------------------------------------------------------------------
		// Save the memory store and its certificates to the output file.
		if(CertSaveStore(
			ms_cert_store, // Store handle
			X509_ASN_ENCODING,
			CERT_STORE_SAVE_AS_PKCS7,
			CERT_STORE_SAVE_TO_FILE,
			hFile, // The handle of an open disk file
			0)) // dwFlags: No flags are needed here.
		{
			printf("Saved the memory store to disk. \n");
		}
		else
		{
			printf("Could not save the memory store to disk.\n");
			DWORD const errcode = GetLastError();
			std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 
		}
		CloseHandle(hFile);

} 

void cert_test(){

	char const * const p1 = CertAlgIdToOID(CALG_ID_G28147_89_GAMMA_CBC);
	char const * const p2 = CertAlgIdToOID(CALG_G34311_DSTU4145);
	char const * const p3 = CertAlgIdToOID(CALG_DSTU4145_SIGN);

	DWORD const pp1 = CertOIDToAlgId (p1);
	DWORD const pp2 = CertOIDToAlgId (p2);
	DWORD const pp3 = CertOIDToAlgId (p3);

    DWORD errcode =0;

    stcrypt::cryptprov_ptr_t hProv;
    hProv = stcrypt::create_cryptprov_ptr(TEXT("cert test container"),	STCRYPT_PROVIDER_NAME_W , STCRYPT_PROVIDER_TYPE, CRYPT_NEWKEYSET );
    //hProv = stcrypt::create_cryptprov_ptr(TEXT("cert test container1"),	MS_ENHANCED_PROV, PROV_RSA_FULL, 0 );

    stcrypt::cryptkey_ptr_t sign_key = stcrypt::generate_cryptkey_ptr(*hProv, AT_SIGNATURE, CRYPT_EXPORTABLE);

    //CertOpenStore

	stcrypt::mspki::cert_name_blob_t cert_name_blob;

	cert_str_to_name(
		L"CN=\"Common Name\";"
		L"L=\"Locality\";"
		L"O=\"Organization\";"
		L"OU=\"Organizational Unit\";"
		L"E=\"mail@mail.com\";"
		L"C=\"UA\";"
		L"S=\"State or Province\";"
		L"STREET=\"Street adress\";"
		L"T=\"Title\";"
		L"G=\"Give Name\";"
		L"I=\"Initials\";"
		L"S=\"Sur name\";"
		L"DC=\"Comain Component\""
		, cert_name_blob);

	 
     SYSTEMTIME cs;
     GetSystemTime(&cs);
     cs.wYear += 1; 

     CRYPT_KEY_PROV_INFO pnfo = {
         TEXT("cert test container"),
         TEXT("STCRYPT"),
         STCRYPT_PROVIDER_TYPE,
         0,
         0, 
         0, 
         AT_SIGNATURE
     };

    CRYPT_ALGORITHM_IDENTIFIER alg={OID_G34311_DSTU4145,0};
    PCCERT_CONTEXT cert = CertCreateSelfSignCertificate( 
        *hProv, 
        &cert_name_blob.m_blob,
        0 ,
        0,//&pnfo, // pKeyProvInfo 
        &alg, //pSignatureAlgorithm 
        0, //start time
        &cs, //end time
        0 //extensions
        );

    if(!cert){ 
        errcode = GetLastError();
        std::wcerr << format_sys_message<TCHAR>(errcode) << TEXT("\n"); 
        throw std::exception("failed to create certificate");
    }


    BOOST_SCOPE_EXIT( (cert) ) {
        BOOL const r = CertFreeCertificateContext(cert); assert(r);
    }  BOOST_SCOPE_EXIT_END

		if (!CertAddEnhancedKeyUsageIdentifier (cert, szOID_PKIX_KP_EMAIL_PROTECTION)){
			assert(false);
		}

		import_into_ms_store2(cert, L"ROOT");
		import_into_ms_store2(cert, L"MY");
		import_into_ms_store2(cert, L"ADDRESSBOOK");


		HCERTSTORE const ms_cert_store = CertOpenStore (
			CERT_STORE_PROV_SYSTEM,
			0,
			0,
			/* CERT_STORE_OPEN_EXISTING_FLAG | */
			CERT_SYSTEM_STORE_CURRENT_USER, //CERT_SYSTEM_STORE_LOCAL_MACHINE,
			L"MY");
		if(ms_cert_store==0) STCRYPT_UNEXPECTED1("CertOpenStore have failed");


		BOOL const r55 = CryptVerifyCertificateSignatureEx (0, X509_ASN_ENCODING, CRYPT_VERIFY_CERT_SIGN_SUBJECT_CERT, (void*) cert, CRYPT_VERIFY_CERT_SIGN_ISSUER_CERT, (void*)cert, 0,0);

		CERT_CHAIN_ENGINE_CONFIG config ={0};
		config.cbSize=sizeof(config);
		HCERTCHAINENGINE engine =0;
		BOOL r = CertCreateCertificateChainEngine(&config, &engine);
		assert(r);

		PCCERT_CHAIN_CONTEXT ctx = CertFindChainInStore(ms_cert_store, X509_ASN_ENCODING, 0, CERT_CHAIN_FIND_BY_ISSUER,0 ,0 );




    std::cout << 
        "***************************************************\n"
        "CERT OK \n" 
        "***************************************************"
        << std::endl;

}

//================================================================================================================================================
