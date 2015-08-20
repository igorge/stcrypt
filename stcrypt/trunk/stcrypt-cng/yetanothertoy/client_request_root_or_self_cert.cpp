//================================================================================================================================================
// FILE: client_request_root_or_self_cert.cpp
// (c) GIE 2011-02-03  13:24
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "client_request_root_or_self_cert.hpp"
//================================================================================================================================================
#include "toy_cmds.hpp"
#include "../../stcrypt-cng/stcrypt-exceptions.hpp"

#include <boost/make_shared.hpp>

#include <Cryptuiapi.h>
//================================================================================================================================================

#define STCRYPT_ASYNC_GUARD_BEGIN if( error ) {STCRYPT_ASYNC_ERROR(error);} else { try {
#define STCRYPT_ASYNC_GUARD_END }catch(...) { this->post_show_fatal_exception_( boost::current_exception() ); } } 
#define STCRYPT_ASYNC_ERROR(x) try { STCRYPT_THROW_EXCEPTION( boost::system::system_error(error) ); } catch(...){ this->post_show_fatal_exception_( boost::current_exception() ); }

namespace toy_client {

	void initialize_request_root_or_self_cert(QMainWindow * const main_window){

		STCRYPT_CHECK(main_window);

		main_window->setCentralWidget( new client_request_root_or_selft_cert_t() );

	}

}


void client_request_root_or_selft_cert_t::request_ca_root_certificate(){
	GIE_QT_DEF_EXCEPTION_GUARD_BEGIN

	boost::asio::ip::tcp::endpoint ca_endpoint (boost::asio::ip::address::from_string( ui.ca_ip_edit->text().toStdString() ), 9090);

	auto stream = boost::make_shared<boost::asio::ip::tcp::iostream>();

	stream->rdbuf()->async_connect(ca_endpoint, [this, stream](boost::system::error_code const& error){
		STCRYPT_ASYNC_GUARD_BEGIN
			this->worker_func_request_cert_sign_(stream);
		STCRYPT_ASYNC_GUARD_END
	});

	m_worker_thread = boost::thread( [this, stream](){ 
		stream->rdbuf()->get_io_service().run();
	} ).move();

	GIE_QT_DEF_EXCEPTION_GUARD_END
}

void client_request_root_or_selft_cert_t::worker_func_request_cert_sign_(boost::shared_ptr<boost::asio::ip::tcp::iostream> const& stream){

	STCRYPT_CHECK( stream );
	STCRYPT_CHECK(stream->good());

	toy::cmd_id_t cmd = toy::cmd_get_ca_root_cert;
	stream->write(reinterpret_cast<char const*>( &cmd ), sizeof(cmd));
	stream->flush();
	STCRYPT_CHECK(stream->good());

	unsigned int packet_size = 0;
	stream->read(reinterpret_cast<char*>( &packet_size ), sizeof(packet_size));
	STCRYPT_CHECK( stream->good() );

	STCRYPT_CHECK(packet_size<=4*1024*1024);
	std::vector<char> ca_cert(packet_size);
	stream->read(ca_cert.data(), ca_cert.size());

	STCRYPT_CHECK( !stream->fail() );

	auto signed_cert_context_ptr = boost::make_shared<ms_cert::pccert_context_t>();
	*signed_cert_context_ptr = CertCreateCertificateContext (X509_ASN_ENCODING, reinterpret_cast<BYTE const*>( ca_cert.data() ), ca_cert.size() );
	STCRYPT_CHECK( *signed_cert_context_ptr );

	std::auto_ptr<function_event_t> async_event( new function_event_t( [this, signed_cert_context_ptr](){ this->complete_ca_root_cert_local_registration_(signed_cert_context_ptr); } ) );
	QApplication::postEvent( this, async_event.release() );
}

void client_request_root_or_selft_cert_t::complete_ca_root_cert_local_registration_( boost::shared_ptr<ms_cert::pccert_context_t> const& signed_cert_context ){
	GIE_QT_DEF_EXCEPTION_GUARD_BEGIN

		STCRYPT_CHECK( signed_cert_context );

		STCRYPT_CHECK( CryptUIDlgViewContext (CERT_STORE_CERTIFICATE_CONTEXT, signed_cert_context->handle(), this->winId(), L"Root CA certificate", 0, 0) );

		ms_cert::import_into_ms_store2(signed_cert_context->handle(), L"ROOT");

		ui.requiest_ca_cert_btn->setDisabled(true);

 	GIE_QT_DEF_EXCEPTION_GUARD_END
}


//================================================================================================================================================
