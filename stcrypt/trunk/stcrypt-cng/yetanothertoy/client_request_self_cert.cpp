//================================================================================================================================================
// FILE: client_request_self_cert.cpp
// (c) GIE 2011-02-03  13:39
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "client_request_self_cert.hpp"
//================================================================================================================================================
#include "toy_cmds.hpp"

#include "../../stcrypt-cng/stcrypt-exceptions.hpp"
#include "../../stcrypt-cng/stcrypt-crypto-alg-ids.h"

#include "cert_name.hpp"

#include "ms/ms_cert_sign.hpp"

#include "qt/qt_fun2runnable.hpp"

#include <boost/scope_exit.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/make_shared.hpp>
#include <boost/exception/current_exception_cast.hpp>

#include <Cryptuiapi.h>
//================================================================================================================================================
#define STCRYPT_ASYNC_GUARD_BEGIN if( error ) {STCRYPT_ASYNC_ERROR(error);} else { try {
#define STCRYPT_ASYNC_GUARD_END }catch(...) { this->post_show_fatal_exception_( boost::current_exception() ); } } 
#define STCRYPT_ASYNC_ERROR(x) try { STCRYPT_THROW_EXCEPTION( boost::system::system_error(error) ); } catch(...){ this->post_show_fatal_exception_( boost::current_exception() ); }

namespace toy_client {

	void initialize_request_self_cert(QMainWindow * const main_window){

		STCRYPT_CHECK(main_window);

		main_window->setCentralWidget( new client_request_self_cert_t() );

	}

}

void client_request_self_cert_t::request_cert_clicked() {
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
		m_key_pair_container_name = boost::lexical_cast<std::wstring>( key_container_id );

		status = NCryptCreatePersistedKey(cng_provider, &cng_n_key_pair, NCNG_DSTU4145, m_key_pair_container_name->c_str(), AT_KEYEXCHANGE, 0/*NCRYPT_OVERWRITE_KEY_FLAG*/);
		STCRYPT_CHECK(!FAILED(status));
		BOOST_SCOPE_EXIT((&cng_n_key_pair)) { auto const status = NCryptFreeObject (cng_n_key_pair);  assert( !FAILED(status) ); } BOOST_SCOPE_EXIT_END

		status = NCryptFinalizeKey(cng_n_key_pair, 0);
		STCRYPT_CHECK(!FAILED(status));


		auto cert_to_be_signed_blob = boost::make_shared<  std::vector<unsigned char> >( );
		cert_to_be_signed_blob->swap( ms_cert::create_req_blob(cert_subject_name, cng_n_key_pair) );

		this->request_cert_sign_( cert_to_be_signed_blob );


	GIE_QT_DEF_EXCEPTION_GUARD_END
}


void client_request_self_cert_t::worker_func_request_cert_sign_( boost::shared_ptr<boost::asio::ip::tcp::iostream> const& stream, boost::shared_ptr< std::vector<unsigned char> > const& cert_to_be_signed_blob){
	STCRYPT_CHECK(cert_to_be_signed_blob);
	STCRYPT_CHECK(cert_to_be_signed_blob->size()!=0);

	STCRYPT_CHECK( stream->good() );

	toy::cmd_id_t cmd = toy::cmd_sign_cert;
	stream->write(reinterpret_cast<char const*>( &cmd ), sizeof(cmd));

	unsigned int const size = cert_to_be_signed_blob->size();
	stream->write(reinterpret_cast<char const*>( &size ), sizeof(size) );


	stream->write(reinterpret_cast<char const*>( cert_to_be_signed_blob->data() ), cert_to_be_signed_blob->size() );

	stream->flush();
	STCRYPT_CHECK( stream->good() );

	unsigned int packet_size = 0;
	stream->read(reinterpret_cast<char*>( &packet_size ), sizeof(packet_size));
	STCRYPT_CHECK( stream->good() );

	STCRYPT_CHECK(packet_size<=4*1024*1024);
	std::vector<char> signed_cert(packet_size);
	stream->read(signed_cert.data(), signed_cert.size());
	STCRYPT_CHECK( stream->good() );

	auto signed_cert_context_ptr = boost::make_shared<ms_cert::pccert_context_t>();
	*signed_cert_context_ptr = CertCreateCertificateContext (X509_ASN_ENCODING, reinterpret_cast<BYTE const*>( signed_cert.data() ), signed_cert.size() );
	STCRYPT_CHECK( *signed_cert_context_ptr );

	std::auto_ptr<function_event_t> async_event( new function_event_t( [this, signed_cert_context_ptr](){ this->complete_signed_cert_local_registration_(signed_cert_context_ptr); } ) );
	QApplication::postEvent( this, async_event.release() );

}


void client_request_self_cert_t::complete_signed_cert_local_registration_( boost::shared_ptr<ms_cert::pccert_context_t> const& signed_cert_context ){
	GIE_QT_DEF_EXCEPTION_GUARD_BEGIN

		STCRYPT_CHECK( signed_cert_context );
		STCRYPT_CHECK( m_key_pair_container_name );


		CRYPT_KEY_PROV_INFO key_prov_info = {0};
		key_prov_info.pwszContainerName = const_cast<wchar_t*>( m_key_pair_container_name->c_str() );
		key_prov_info.pwszProvName = CNG_STCRYPT_KEYSTORAGE;
		key_prov_info.dwProvType = 0;
		key_prov_info.dwFlags = 0;
		key_prov_info.cProvParam = 0;
		key_prov_info.rgProvParam = 0;
		key_prov_info.dwKeySpec = 0;

		STCRYPT_CHECK( CertSetCertificateContextProperty(signed_cert_context->handle(), CERT_KEY_PROV_INFO_PROP_ID, 0, &key_prov_info) );

		ms_cert::import_into_ms_store2(signed_cert_context->handle(), L"ADDRESSBOOK");
		ms_cert::import_into_ms_store2(signed_cert_context->handle(), L"MY");

		STCRYPT_CHECK( CryptUIDlgViewContext (CERT_STORE_CERTIFICATE_CONTEXT, signed_cert_context->handle(), this->winId(), L"Signed certificate from CA", 0, 0) );

		auto main_window = dynamic_cast<QMainWindow*>( this->parent() );
		STCRYPT_CHECK(main_window);

		main_window->setCentralWidget( new QLabel("Signed certificate have been imported into store.") );

	GIE_QT_DEF_EXCEPTION_GUARD_END
}


void client_request_self_cert_t::request_cert_sign_( boost::shared_ptr< std::vector<unsigned char> > const& cert_to_be_signed_blob){

	boost::asio::ip::tcp::endpoint ca_endpoint (boost::asio::ip::address::from_string( ui.ca_ip_edit->text().toStdString() ), 9090);

	auto stream = boost::make_shared<boost::asio::ip::tcp::iostream>();


	stream->rdbuf()->async_connect(ca_endpoint, [this, stream, cert_to_be_signed_blob](boost::system::error_code const& error){
		STCRYPT_ASYNC_GUARD_BEGIN
			this->worker_func_request_cert_sign_(stream, cert_to_be_signed_blob);
		STCRYPT_ASYNC_GUARD_END
	});

	m_workers.start( gie::wrap_to_runnable( [this, stream](){ 
 		stream->rdbuf()->get_io_service().run();
 	} ).release() );

// 	m_worker_thread = boost::thread( [this, stream](){ 
// 		stream->rdbuf()->get_io_service().run();
// 	} ).move();

// 	m_workers.schedule( [this, stream ](){ 
// 		stream->rdbuf()->get_io_service().run();
// 	} );

}


void client_request_self_cert_t::post_show_fatal_exception_(boost::exception_ptr const& e){

	std::auto_ptr<function_event_t> async_event( new function_event_t( [this, e](){ this->show_async_exception_(e); } ) );
	QApplication::postEvent( this, async_event.release() );

}

void client_request_self_cert_t::show_async_exception_(boost::exception_ptr const& e){
	GIE_QT_DEF_EXCEPTION_GUARD_BEGIN
		boost::rethrow_exception( e );
	GIE_QT_DEF_EXCEPTION_GUARD_END
}


client_request_self_cert_t::client_request_self_cert_t(QWidget *parent, Qt::WFlags flags)
	: QWidget(parent, flags)
	//, m_workers(6)
{
	auto const tp_thread_count = m_workers.maxThreadCount();
	m_workers.setMaxThreadCount( tp_thread_count<=1?2:tp_thread_count );

	ui.setupUi(this);
}

client_request_self_cert_t::~client_request_self_cert_t(){
	m_workers.waitForDone();
//  	m_worker_thread.interrupt();
//  	m_worker_thread.join();
}


//================================================================================================================================================
