//================================================================================================================================================
// FILE: ca_generate_root_ca_cert.cpp
// (c) GIE 2011-02-04  02:01
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "ca_generate_root_ca_cert.hpp"
//================================================================================================================================================
#include "ca_accept_requests_if.hpp"

#include "cert_name.hpp"

#include "qt/qt_def_exception_stubs.hpp"
#include "../../stcrypt-cng/stcrypt-exceptions.hpp"
#include "../../stcrypt-cng/stcrypt-crypto-alg-ids.h"

#include "ms/ms_cert_sign.hpp"

#include <boost/scope_exit.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/make_shared.hpp>

#include <Cryptuiapi.h>
//================================================================================================================================================
namespace toy_ca{

		void initialize_generate_ca_cert( QMainWindow* const main_window ){
			STCRYPT_CHECK(main_window);

			main_window->setCentralWidget( new ca_generate_root_ca_cert_t() );
		}

}


ca_generate_root_ca_cert_t::ca_generate_root_ca_cert_t(QWidget *parent, Qt::WFlags flags)
	: QWidget(parent, flags)
{
	ui.setupUi(this);
}

ca_generate_root_ca_cert_t::~ca_generate_root_ca_cert_t(){
}


void ca_generate_root_ca_cert_t::generate_ca_cert_clicked(){
	GIE_QT_DEF_EXCEPTION_GUARD_BEGIN

		stcrypt::cert_name_t cert_subject_name;


		#define STCRYPT_TOYCA_CP_NAME(x) { auto str = ui.x##_edit->text().toStdWString(); cert_subject_name.set_##x( std::move(str) ); }

		STCRYPT_TOYCA_CP_NAME(common_name);
 		STCRYPT_TOYCA_CP_NAME(country_name);
 		STCRYPT_TOYCA_CP_NAME(locality_name);
 		STCRYPT_TOYCA_CP_NAME(organization_name);
 		STCRYPT_TOYCA_CP_NAME(organization_unit_name);
		STCRYPT_TOYCA_CP_NAME(state_or_province_name);
		STCRYPT_TOYCA_CP_NAME(email_name);

		#undef STCRYPT_TOYCA_CP_NAME

		// generate key pair
		NCRYPT_PROV_HANDLE cng_provider=0;
		NCRYPT_KEY_HANDLE  cng_n_key_pair=0;
		
		auto status = NCryptOpenStorageProvider(&cng_provider, CNG_STCRYPT_KEYSTORAGE, 0);
		STCRYPT_CHECK(!FAILED(status));
		BOOST_SCOPE_EXIT((&cng_provider)) { auto const status = NCryptFreeObject (cng_provider);  assert( !FAILED(status) ); } BOOST_SCOPE_EXIT_END

		boost::uuids::uuid const key_container_id( (boost::uuids::random_generator()()) );
		auto const& key_pair_container_name = boost::lexical_cast<std::wstring>( key_container_id );

		status = NCryptCreatePersistedKey(cng_provider, &cng_n_key_pair, NCNG_DSTU4145, key_pair_container_name.c_str(), AT_KEYEXCHANGE, 0/*NCRYPT_OVERWRITE_KEY_FLAG*/);
		STCRYPT_CHECK(!FAILED(status));
		BOOST_SCOPE_EXIT((&cng_n_key_pair)) { auto const status = NCryptFreeObject (cng_n_key_pair);  assert( !FAILED(status) ); } BOOST_SCOPE_EXIT_END

		status = NCryptFinalizeKey(cng_n_key_pair, 0);
		STCRYPT_CHECK(!FAILED(status));

		auto const& to_be_signed_cert_blob = ms_cert::create_req_blob(cert_subject_name, cng_n_key_pair, cert_subject_name);

		DWORD size;
		STCRYPT_CHECK( CryptDecodeObjectEx(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, reinterpret_cast<BYTE const*> (to_be_signed_cert_blob.data()), to_be_signed_cert_blob.size(), CRYPT_DECODE_TO_BE_SIGNED_FLAG, 0, 0, &size) );
		STCRYPT_CHECK(size!=0);

		std::vector<unsigned char> to_be_signed_cert_blob_combined(size);
		STCRYPT_CHECK( CryptDecodeObjectEx(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, reinterpret_cast<BYTE const*> (to_be_signed_cert_blob.data()), to_be_signed_cert_blob.size(), CRYPT_DECODE_TO_BE_SIGNED_FLAG, 0, to_be_signed_cert_blob_combined.data(), &size) );
		to_be_signed_cert_blob_combined.resize(size);

		CERT_INFO* const cert_to_be_signed = static_cast<CERT_INFO*>( static_cast<void*>( to_be_signed_cert_blob_combined.data() ) );

		// do sign
		CRYPT_ALGORITHM_IDENTIFIER signature_alg={OID_G34311_DSTU4145_SIGN,0};

		DWORD encoded_cert_size = 0;
 		if( !CryptSignAndEncodeCertificate(cng_n_key_pair, 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, cert_to_be_signed, &signature_alg, 0, 0, &encoded_cert_size) ){ //TODO: this CryptSignAndEncodeCertificate leaks memory
 			STCRYPT_UNEXPECTED();
 		}
 		STCRYPT_CHECK(encoded_cert_size!=0);
 
 		std::vector<BYTE> signed_certificate(encoded_cert_size);
 		if( !CryptSignAndEncodeCertificate(cng_n_key_pair, 0, X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, cert_to_be_signed, &signature_alg, 0, signed_certificate.data(), &encoded_cert_size) ){
 			STCRYPT_UNEXPECTED();
 		}
 		signed_certificate.resize(encoded_cert_size);

		// context from signed blob
		ms_cert::pccert_context_t signed_cert_context( CertCreateCertificateContext (X509_ASN_ENCODING, reinterpret_cast<BYTE const*>( signed_certificate.data() ), signed_certificate.size() ) );
		STCRYPT_CHECK( signed_cert_context );

		// assign private key container name
		CRYPT_KEY_PROV_INFO key_prov_info = {0};
		key_prov_info.pwszContainerName = const_cast<wchar_t*>( key_pair_container_name.c_str() );
		key_prov_info.pwszProvName = CNG_STCRYPT_KEYSTORAGE;
		key_prov_info.dwProvType = 0;
		key_prov_info.dwFlags = 0;
		key_prov_info.cProvParam = 0;
		key_prov_info.rgProvParam = 0;
		key_prov_info.dwKeySpec = 0;

		STCRYPT_CHECK( CertSetCertificateContextProperty(signed_cert_context.handle(), CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info) );
		STCRYPT_CHECK( CryptUIDlgViewContext (CERT_STORE_CERTIFICATE_CONTEXT, signed_cert_context.handle(), this->winId(), L"Generated CA certificate [NOT YET INSTALLED]", 0, 0) );

		ms_cert::import_into_ms_store2(signed_cert_context.handle(), L"ROOT");

		STCRYPT_CHECK( CryptUIDlgViewContext (CERT_STORE_CERTIFICATE_CONTEXT, signed_cert_context.handle(), this->winId(), L"Generated CA certificate", 0, 0) );

		toy_ca::initialize_accept_requests_mode( dynamic_cast<QMainWindow*>( this->parent() ), std::move(signed_cert_context) );

	GIE_QT_DEF_EXCEPTION_GUARD_END
}


//================================================================================================================================================
