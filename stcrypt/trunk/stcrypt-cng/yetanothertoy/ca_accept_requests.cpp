//================================================================================================================================================
// FILE: ca_accept_requests.cpp
// (c) GIE 2011-02-03  00:39
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "toy_cmds.hpp"
#include "ca_accept_requests_if.hpp"
#include "ca_accept_requests.hpp"

#include "gie/gie_auto_vector.hpp"

#include "../../stcrypt-cng/stcrypt-crypto-alg-ids.h"
#include "../../stcrypt-cng/stcrypt-exceptions.hpp"
#include "../../stcrypt-csp/stcrypt-mspki-helpers.hpp"

#include <boost/make_shared.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/exception_ptr.hpp>
#include <boost/scope_exit.hpp>
#include <boost/format.hpp>
//================================================================================================================================================

#define STCRYPT_ASYNC_GUARD_BEGIN(name) if( error ) {STCRYPT_ASYNC_ERROR(error, name);} else { try {
#define STCRYPT_ASYNC_GUARD_END(name) }catch(...) { if(name->m_show_fatal_exception){ name->m_show_fatal_exception( boost::current_exception() ); } } }
#define STCRYPT_ASYNC_ERROR(x, name) try { STCRYPT_THROW_EXCEPTION( boost::system::system_error(error) ); } catch(...){  name->m_show_fatal_exception( boost::current_exception() ); }

namespace toy_ca {

	struct sesion_t : boost::enable_shared_from_this<struct sesion_t>
	{
		boost::function<void(boost::exception_ptr const& e)>	m_show_fatal_exception;
		boost::function<void(boost::shared_ptr<ms_cert::pccert_context_t> const& ctx)>	m_process_signed_cert;
		boost::shared_ptr<toy_ca::cert_info_t>					m_root_ca_certificate;

		boost::asio::ip::tcp::socket	m_socket;

		std::vector<char>				m_buffer;
		unsigned int					m_tmp_size;

		sesion_t(boost::asio::io_service& io_service) : m_socket( io_service ){}

		template <class HandlerType>
		void async_read_buffer(HandlerType const & handler){
			boost::asio::async_read(m_socket, boost::asio::buffer(m_buffer), handler);
		}
		template <class HandlerType>
		void async_write_buffer(HandlerType const & handler){
			boost::asio::async_write(m_socket, boost::asio::buffer(m_buffer), handler);
		}
		template <class HandlerType>
		void async_read_size(HandlerType const & handler){
			auto session = this->shared_from_this();

			boost::asio::async_read(m_socket, boost::asio::buffer( reinterpret_cast<char*>( &m_tmp_size ), sizeof(m_tmp_size)), 
				[session, handler](boost::system::error_code const& error, std::size_t const bytes_transferred){STCRYPT_ASYNC_GUARD_BEGIN(session) handler(session->m_tmp_size); STCRYPT_ASYNC_GUARD_END(session)} );
		}

		void dispatch_cmd(){
			auto session = this->shared_from_this();

			toy::cmd_id_t cmd;
			STCRYPT_CHECK(sizeof(cmd)==m_buffer.size());
			memcpy(&cmd, m_buffer.data(), sizeof(cmd));

			switch(cmd){
			case toy::cmd_sign_cert: 
				this->async_read_size( [session](unsigned int const size){
					STCRYPT_CHECK(size<=4*1024*1024);

					session->m_buffer.resize(size);
					auto & session1 = session; // cannot pass capture from another capture
					session->async_read_buffer([session1](boost::system::error_code const& error, std::size_t const bytes_transferred){STCRYPT_ASYNC_GUARD_BEGIN(session1) session1->process_certificate_request(); STCRYPT_ASYNC_GUARD_END(session1) } );
				}); 
				break;

			case toy::cmd_get_ca_root_cert: 
				process_root_ca_certificate_request();
				break;

			default: 
				STCRYPT_UNEXPECTED();
			}

		}

		void accept(){
			auto session = this->shared_from_this();

			m_buffer.resize( sizeof(unsigned int) );
			async_read_buffer([session](boost::system::error_code const& error, std::size_t const bytes_transferred){STCRYPT_ASYNC_GUARD_BEGIN(session) session->dispatch_cmd(); STCRYPT_ASYNC_GUARD_END(session)} );
		}

		void process_root_ca_certificate_request(){
			auto session = this->shared_from_this();

			STCRYPT_CHECK(session->m_root_ca_certificate);
			
			auto const pcert_context = session->m_root_ca_certificate->m_cert_ctx.handle();
			STCRYPT_CHECK(pcert_context);
			STCRYPT_CHECK(pcert_context->pbCertEncoded);

			m_buffer.reserve(sizeof(unsigned int)+pcert_context->cbCertEncoded);
			m_buffer.clear();
			unsigned int packet_size = pcert_context->cbCertEncoded;
			std::copy(reinterpret_cast<BYTE const*>(&packet_size), reinterpret_cast<BYTE const*>(&packet_size)+sizeof(packet_size), std::back_inserter(m_buffer) );
			std::copy(pcert_context->pbCertEncoded, pcert_context->pbCertEncoded+pcert_context->cbCertEncoded, std::back_inserter(m_buffer)  );

			this->async_write_buffer([session](boost::system::error_code const& error, std::size_t const bytes_transferred){
				STCRYPT_ASYNC_GUARD_BEGIN(session) session->m_socket.close();  STCRYPT_ASYNC_GUARD_END(session)
			} );
		}

		void process_certificate_request(){
			auto session = this->shared_from_this();

			DWORD size;
			STCRYPT_CHECK( CryptDecodeObjectEx(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, reinterpret_cast<BYTE const*> (m_buffer.data()), m_buffer.size(), CRYPT_DECODE_TO_BE_SIGNED_FLAG, 0, 0, &size) );
			STCRYPT_CHECK(size!=0);

			std::vector<unsigned char> decoded_cert_to_be_signed(size);
			STCRYPT_CHECK( CryptDecodeObjectEx(X509_ASN_ENCODING, X509_CERT_TO_BE_SIGNED, reinterpret_cast<BYTE const*> (m_buffer.data()), m_buffer.size(), CRYPT_DECODE_TO_BE_SIGNED_FLAG, 0, decoded_cert_to_be_signed.data(), &size) );
			decoded_cert_to_be_signed.resize(size);

			CERT_INFO* const cert_to_be_signed = static_cast<CERT_INFO*>( static_cast<void*>( decoded_cert_to_be_signed.data() ) );

			// signing cert
			STCRYPT_CHECK(session->m_root_ca_certificate);
			
			CRYPT_ALGORITHM_IDENTIFIER signature_alg={OID_G34311_DSTU4145_SIGN,0};

			cert_to_be_signed->Issuer = session->m_root_ca_certificate->m_cert_ctx.handle()->pCertInfo->Issuer;
			cert_to_be_signed->SignatureAlgorithm = signature_alg;

			auto const& prov_info = ms_cert::cert_get_private_key_storage_name( *(session->m_root_ca_certificate->m_cert_ctx.handle()) );
			STCRYPT_CHECK( prov_info );

			NCRYPT_PROV_HANDLE cng_provider=0;
			NCRYPT_KEY_HANDLE  cng_n_key_pair=0;

			auto status = NCryptOpenStorageProvider(&cng_provider, boost::get<0>(*prov_info).c_str(), 0);
			STCRYPT_CHECK(!FAILED(status));
			BOOST_SCOPE_EXIT((&cng_provider)) { auto const status = NCryptFreeObject (cng_provider);  assert( !FAILED(status) ); } BOOST_SCOPE_EXIT_END

			status = NCryptOpenKey(cng_provider, &cng_n_key_pair, boost::get<1>(*prov_info).c_str(), AT_KEYEXCHANGE, 0);
			STCRYPT_CHECK(!FAILED(status));
			BOOST_SCOPE_EXIT((&cng_n_key_pair)) { auto const status = NCryptFreeObject (cng_n_key_pair);  assert( !FAILED(status) ); } BOOST_SCOPE_EXIT_END

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

			// send signed cert back
			m_buffer.reserve(sizeof(unsigned int)+signed_certificate.size());
			m_buffer.clear();
			unsigned int packet_size = signed_certificate.size();
			std::copy(reinterpret_cast<BYTE const*>(&packet_size), reinterpret_cast<BYTE const*>(&packet_size)+sizeof(packet_size), std::back_inserter(m_buffer) );
			std::copy(signed_certificate.begin(), signed_certificate.end(), std::back_inserter(m_buffer)  );

			//prepare cert context for main form list
			auto client_cert_ctx_ptr = boost::make_shared<ms_cert::pccert_context_t>();
			*client_cert_ctx_ptr = CertCreateCertificateContext (X509_ASN_ENCODING, reinterpret_cast<BYTE const*>( signed_certificate.data() ), signed_certificate.size() );
			STCRYPT_CHECK(*client_cert_ctx_ptr);

			//do send
			this->async_write_buffer([session, client_cert_ctx_ptr](boost::system::error_code const& error, std::size_t const bytes_transferred){
				STCRYPT_ASYNC_GUARD_BEGIN(session) 

					STCRYPT_CHECK(client_cert_ctx_ptr);

					if(session->m_process_signed_cert){
						session->m_process_signed_cert( client_cert_ctx_ptr );
					}
					session->m_socket.close();  

				STCRYPT_ASYNC_GUARD_END(session)
			} );
		}

		
	};

	typedef boost::shared_ptr<sesion_t> sesion_ptr_t;

}

ca_accept_requests_t::~ca_accept_requests_t(){
	m_listen_thread.interrupt();
	m_io_service.stop();
	m_listen_thread.join();
}

ca_accept_requests_t::ca_accept_requests_t(ms_cert::pccert_context_t && root_cert, QWidget *parent, Qt::WFlags flags)
	: QWidget(parent, flags)
{
	ui.setupUi(this);
	auto r = toy_ca::cook_cert( std::move(root_cert) );
	this->ui.certificates_list->addItem( new toy_ca::proxy_list_item_t<toy_ca::cert_info_t>( r, ms_cert::cert_get_name_string(r->m_cert_ctx)  ) );

	m_root_ca_certificate = r;

	m_listen_thread = boost::thread( [this](){ 
		this->background_thread_func_();
	} ).move();

}

void ca_accept_requests_t::add_signed_cert( boost::shared_ptr<ms_cert::pccert_context_t> const& cert_ctx){
	GIE_QT_DEF_EXCEPTION_GUARD_BEGIN

		STCRYPT_CHECK(cert_ctx);

		auto r = toy_ca::cook_cert( std::move(*cert_ctx) );
		this->ui.certificates_list->addItem( new toy_ca::proxy_list_item_t<toy_ca::cert_info_t>( r, ms_cert::cert_get_name_string(r->m_cert_ctx)  ) );

		ui.log_window->appendPlainText( QString::fromStdWString( (boost::wformat(L"Auto signed request, subject name: %1%") % r->subject_name).str() ) );

	GIE_QT_DEF_EXCEPTION_GUARD_END
}


void ca_accept_requests_t::show_async_exception_(boost::exception_ptr const& e){
	GIE_QT_DEF_EXCEPTION_GUARD_BEGIN
		boost::rethrow_exception( e );
	GIE_QT_DEF_EXCEPTION_GUARD_END
}


void ca_accept_requests_t::start_async_accept_(boost::asio::ip::tcp::acceptor& acceptor){

	auto session = boost::make_shared<toy_ca::sesion_t>( boost::ref(m_io_service) );

	session->m_root_ca_certificate = this->m_root_ca_certificate;

	session->m_show_fatal_exception = [this](boost::exception_ptr const& e){
		auto that = this;
		std::auto_ptr<function_event_t> async_event( new function_event_t( [that, e](){ that->show_async_exception_(e); } ) );
		QApplication::postEvent( this, async_event.release() );
	};

	session->m_process_signed_cert = [this](boost::shared_ptr<ms_cert::pccert_context_t> const& cert_ctx){
		auto that = this;
		std::auto_ptr<function_event_t> async_event( new function_event_t( [that, cert_ctx](){ that->add_signed_cert(cert_ctx); } ) );
		QApplication::postEvent( this, async_event.release() );
	};

	acceptor.async_accept(session->m_socket, [session](const boost::system::error_code& error){ STCRYPT_ASYNC_GUARD_BEGIN(session) session->accept(); STCRYPT_ASYNC_GUARD_END(session) });
}

void ca_accept_requests_t::background_thread_func_(){
	try {

		boost::asio::ip::tcp::acceptor acceptor(m_io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 9090));

		while( !m_listen_thread.interruption_requested() ) {
			start_async_accept_(acceptor);
			std::size_t const num_of_handlres = m_io_service.run();
			m_io_service.reset();
		}


	}catch(...){
		assert(false);
	}
}

namespace toy_ca {

	boost::shared_ptr<cert_info_t>	cook_cert(ms_cert::pccert_context_t&& cert_ctx){

		STCRYPT_CHECK(cert_ctx);

		auto cert_info = boost::make_shared<cert_info_t>();

		cert_info->subject_name = ms_cert::cert_name_to_str(cert_ctx.handle()->pCertInfo->Subject);
		cert_info->issuer_name = ms_cert::cert_name_to_str(cert_ctx.handle()->pCertInfo->Issuer);

		cert_info->m_cert_ctx = std::move(cert_ctx);

		return cert_info;
	}


	void initialize_accept_requests_mode(QMainWindow * const main_window, ms_cert::pccert_context_t&& cert_ctx){

		STCRYPT_CHECK(main_window);
		STCRYPT_CHECK(cert_ctx);

		main_window->setCentralWidget( new ca_accept_requests_t( std::move(cert_ctx) ) );

	}

}
//================================================================================================================================================
