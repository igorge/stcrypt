//================================================================================================================================================
// FILE: ca_select_or_create_root_cert.cpp
// (c) GIE 2011-02-02  23:12
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "ca_select_or_create_root_cert.hpp"
#include "ca_accept_requests_if.hpp"
#include "ca_generate_root_ca_cert_if.hpp"

#include "../../stcrypt-cng/stcrypt-exceptions.hpp"
#include "ms/ms_cert_store_utils.hpp"

#include <QMessageBox>

#include <boost/scope_exit.hpp>

#include <Cryptuiapi.h>
//================================================================================================================================================
//namespace {

namespace {

	void verify_selected_cert_revocation(ms_cert::pccert_context_t const& cert){
		CERT_CHAIN_PARA cert_chain_para = {0};
		cert_chain_para.cbSize=sizeof(CERT_CHAIN_PARA);

		cert_chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
		cert_chain_para.RequestedUsage.Usage.cUsageIdentifier = 0;

		CERT_CHAIN_CONTEXT const* cert_chain_context=0;
		BOOST_SCOPE_EXIT((&cert_chain_context)) { if(cert_chain_context) CertFreeCertificateChain(cert_chain_context);  }  BOOST_SCOPE_EXIT_END

		STCRYPT_CHECK( CertGetCertificateChain(0, cert.handle(), 0, 0, &cert_chain_para, CERT_CHAIN_REVOCATION_CHECK_END_CERT, 0, &cert_chain_context) );

		CERT_CHAIN_POLICY_PARA cert_chain_policy_para = {0};
		cert_chain_policy_para.cbSize = sizeof(cert_chain_policy_para);
		cert_chain_policy_para.dwFlags = 0;
		
		CERT_CHAIN_POLICY_STATUS pol_status = {0};
		pol_status.cbSize = sizeof(pol_status);

		STCRYPT_CHECK( CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_BASE, cert_chain_context, &cert_chain_policy_para, &pol_status) );
	}
}
	
	void ca_select_or_create_root_cert_t::select_root_ca_from_store(){
		GIE_QT_DEF_EXCEPTION_GUARD_BEGIN

			auto const w_handle = this->winId();
			STCRYPT_CHECK( w_handle );

			ms_cert::store_handle_t const ms_cert_store ( CertOpenStore (
				CERT_STORE_PROV_SYSTEM,
				0,
				0,
				CERT_SYSTEM_STORE_CURRENT_USER, 
				L"ROOT" ) );

			STCRYPT_CHECK(ms_cert_store);

			ms_cert::pccert_context_t cert ( CryptUIDlgSelectCertificateFromStore (ms_cert_store.handle(), w_handle, L"Root CA certificate select", L"Select a certificate for which one you do have a private key", 0, 0, 0) );

			if( cert ){
				verify_selected_cert_revocation(cert);
				toy_ca::initialize_accept_requests_mode( dynamic_cast<QMainWindow*>( this->parent() ), std::move(cert) );
			} else {
				QMessageBox::information(this, "Info", "No certificate selected." );
			}


		GIE_QT_DEF_EXCEPTION_GUARD_END
	}

	void ca_select_or_create_root_cert_t::generate_root_ca_cert(){
		GIE_QT_DEF_EXCEPTION_GUARD_BEGIN

			toy_ca::initialize_generate_ca_cert(  dynamic_cast<QMainWindow*>( this->parent() ) );

		GIE_QT_DEF_EXCEPTION_GUARD_END
	}


//}
//================================================================================================================================================
