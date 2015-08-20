//================================================================================================================================================
// FILE: toyca-client-worker.cpp
// (c) GIE 2010-04-01  13:50
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "toyca-client-get-ca-root-cert.hpp"
#include "toyca-client-request-cert-sign.hpp"
#include "toyca-client-worker.hpp"
#include "toyca-client-p2p.hpp"
#include "../common/misc/stcrypt-qt-exception-guards.hpp"
#include "../common/toycert/stcrypt-toycert-signature-verifier.hpp"
#include "../toyCA/toycert-cmds.hpp"

#include "boost/date_time/posix_time/ptime.hpp"
#include "boost/enable_shared_from_this.hpp"
//================================================================================================================================================
namespace stcrypt { namespace  caclient {
	
	void worker_t::async_get_ca_root_certificate(boost::asio::ip::tcp::endpoint const& endpoint, event__get_ca_root_certificate_type const& callback, event__error_type const& error_callback){
		//impl::get_ca_root_certificate_state_ptr_t session(  new impl::get_ca_root_certificate_state_t(*this) );

		client_session_ptr const& session = create_session__get_ca_root_certificate(*this, endpoint, callback, error_callback);

		m_io_service.post( boost::bind(&client_session_i::initialize_run, session) );
	}

	void worker_t::async_request_sign_certificate(		
		caclient::db_t& db,
		boost::shared_ptr< stcrypt::toycert_t> ca_cert,
		boost::shared_ptr< stcrypt::toycert_t> certificate_to_sign,
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		worker_t::event__got_self_cert const & callback, 
		worker_t::event__error_type const& error_callback){

			client_session_ptr const& session = create_session__request_sign_certificate(db, *this, ca_cert, certificate_to_sign,  ca_endpoint, callback, error_callback);

			m_io_service.post( boost::bind(&client_session_i::initialize_run, session) );

	}

	void worker_t::async_resume_request_sign_certificate(
		ca::cert_store_t::certificate_id_t const cert_request_id,
		std::vector<char> const& session_key_blob,
		std::wstring const& csp_container_name,

		caclient::db_t& db, 
		boost::shared_ptr< stcrypt::toycert_t> ca_cert, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		worker_t::event__got_self_cert const & callback, 
		worker_t::event__error_type const& error_callback){

			client_session_ptr const& session = create_session__resume_request_sign_certificate(cert_request_id, session_key_blob, csp_container_name, db, *this, ca_cert,  ca_endpoint, callback, error_callback);

			m_io_service.post( boost::bind(&client_session_i::initialize_run, session) );

	}




	void worker_t::run(){
		m_worker_thread = boost::thread( boost::bind( &worker_t::do_run_, this) ).move();

	}

	worker_t::worker_t()
		: m_idle_timer(m_io_service)
	{
	
	}
	worker_t::~worker_t(){
		m_worker_thread.interrupt();
		m_io_service.stop();
		m_worker_thread.join();
	}

	void worker_t::idle_timer_func_(){
		m_idle_timer.expires_from_now(boost::posix_time::seconds(10) );
		m_idle_timer.async_wait( boost::bind(&worker_t::idle_timer_func_, this));

	}

	void worker_t::do_run_(){
		try {

			//boost::asio::ip::tcp::acceptor acceptor(m_io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), 9090));

			m_idle_timer.expires_from_now(boost::posix_time::seconds(10) );
			m_idle_timer.async_wait( boost::bind(&worker_t::idle_timer_func_, this));
			

			//start_async_accept_(acceptor);
			std::size_t const num_of_handlres = m_io_service.run();


		}catch(...){
			assert(false);
		}

	}

	void worker_t::on_accept_(
		boost::shared_ptr<boost::asio::ip::tcp::socket> const & socket, 
		boost::system::error_code const & error, 
		boost::shared_ptr<boost::asio::ip::tcp::acceptor> const& acceptor,

		boost::shared_ptr<stcrypt::toycert_t> const& self_certificate ,
		std::wstring const& csp_container_name,
		boost::shared_ptr<stcrypt::toycert_t> ca_certificate, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint,
		boost::function<void(std::string const&)> const& print_msg
	)
	{
		
		boost::shared_ptr<client_session_i> const listen_session = caclient::new_listen_session(*this, socket, self_certificate, csp_container_name, ca_certificate, ca_endpoint, print_msg);
		m_io_service.post( boost::bind(&client_session_i::initialize_run, listen_session) );

	}


	void worker_t::start_accept(
		boost::shared_ptr<stcrypt::toycert_t> self_certificate, 
		std::wstring const& csp_container_name,
		boost::shared_ptr<stcrypt::toycert_t> ca_certificate, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		unsigned int const listen_port, 
		boost::function<void(std::string const&)> const& print_msg){

			boost::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor( new boost::asio::ip::tcp::acceptor(m_io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), listen_port)) );
			boost::shared_ptr<boost::asio::ip::tcp::socket> socket( new boost::asio::ip::tcp::socket( m_io_service ) );
			acceptor->async_accept(*socket, 
				boost::bind(&worker_t::on_accept_, this, 
					socket, 
					boost::asio::placeholders::error, 
					acceptor,

					self_certificate,
					csp_container_name,
					ca_certificate,
					ca_endpoint,
					print_msg
					)
					);
		

	}

	void worker_t::send_text_to_peer(
		std::string const& message,
		boost::asio::ip::tcp::endpoint const& peer_endpoint,
		boost::shared_ptr<toycert_t> const& self_cert,
		std::wstring const& self_keyset_container_name,
		boost::shared_ptr<toycert_t> const& ca_cert, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		boost::function<void(std::string const&)> const& print_msg){

			boost::shared_ptr<client_session_i> const listen_session = caclient::new_send_text_session(*this, message, peer_endpoint, self_cert, self_keyset_container_name, ca_cert, ca_endpoint, print_msg);
			listen_session->initialize_run();

	}




} }
//================================================================================================================================================
