//================================================================================================================================================
// FILE: toyca-client-worker.h
// (c) GIE 2010-04-01  13:50
//
//================================================================================================================================================
#ifndef H_GUARD_TOYCA_CLIENT_WORKER_2010_04_01_13_50
#define H_GUARD_TOYCA_CLIENT_WORKER_2010_04_01_13_50
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "../common/toycert/stcrypt-toycert.hpp"
#include "toycert-client-db.hpp"

#include "boost/asio.hpp"
#include "boost/function.hpp"
#include "boost/thread.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/optional.hpp"
//================================================================================================================================================
namespace stcrypt { namespace  caclient {

#define STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_BEGIN	\
	STCRYPT_VOID_ASYNC_HANDLER_EGUARD_BEGIN		\
	try{	\
	/**/

#define STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_END	\
		} catch(stcrypt::exception::root const& e){						\
		invoke_error_handler( boost::diagnostic_information(e) );	\
		}																\
		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_END							\
		/**/


	struct client_session_i {

		virtual void initialize_run()=0;
		virtual ~client_session_i (){};
	};

	typedef boost::shared_ptr<client_session_i> client_session_ptr;

	namespace impl {
		struct get_ca_root_certificate_state_t;
		typedef boost::shared_ptr<get_ca_root_certificate_state_t> get_ca_root_certificate_state_ptr_t;
	}


	struct worker_t 
		: boost::noncopyable
	{

		typedef boost::function<void( boost::shared_ptr< stcrypt::toycert_t> const& ca_root_cert, std::vector<char> const& cert_blob, bool signaure_status ) > event__get_ca_root_certificate_type;
		typedef boost::function<void(boost::optional<boost::system::error_code const&> const& error, boost::optional<std::string const&> const& msg)>	event__error_type;

		typedef boost::function<void(boost::shared_ptr<stcrypt::toycert_t> const& self_cert) > event__got_self_cert;


		worker_t();
		~worker_t();
		void run();
		void async_get_ca_root_certificate(
			boost::asio::ip::tcp::endpoint const& endpoint, 
			event__get_ca_root_certificate_type const& callback, 
			event__error_type const& error_callback);

		void async_request_sign_certificate(
			caclient::db_t& db,
			boost::shared_ptr< stcrypt::toycert_t> ca_cert,
			boost::shared_ptr< stcrypt::toycert_t> certificate_to_sign,
			boost::asio::ip::tcp::endpoint const& ca_endpoint, 
			event__got_self_cert const & callback, 
			worker_t::event__error_type const& error_callback);

		void async_resume_request_sign_certificate(
			ca::cert_store_t::certificate_id_t const cert_request_id,
			std::vector<char> const& session_key_blob,
			std::wstring const& csp_container_name,

			caclient::db_t& db, 
			boost::shared_ptr< stcrypt::toycert_t> ca_certificate, 
			boost::asio::ip::tcp::endpoint const& ca_endpoint, 
			worker_t::event__got_self_cert const & callback, 
			worker_t::event__error_type const& error_callback);

		void start_accept(
				boost::shared_ptr<stcrypt::toycert_t> self_certificate, 
				std::wstring const& csp_container_name,
				boost::shared_ptr<stcrypt::toycert_t> ca_certificate, 
				boost::asio::ip::tcp::endpoint const& ca_endpoint, 
				unsigned int const listen_port,
				boost::function<void(std::string const&)> const& print_msg
			);

		
		void send_text_to_peer(
			std::string const& message,
			boost::asio::ip::tcp::endpoint const& peer_endpoint,
			boost::shared_ptr<toycert_t> const& self_cert,
			std::wstring const& self_keyset_container_name,
			boost::shared_ptr<toycert_t> const& ca_cert, 
			boost::asio::ip::tcp::endpoint const& ca_endpoint, 
			boost::function<void(std::string const&)> const& print_msg);



		boost::asio::io_service& io_service(){ return m_io_service; }

		private:
		void do_run_();

		void idle_timer_func_();
		void worker_t::on_accept_(
			boost::shared_ptr<boost::asio::ip::tcp::socket> const & socket, 
			boost::system::error_code const & error, 
			boost::shared_ptr<boost::asio::ip::tcp::acceptor> const& acceptor,
			boost::shared_ptr<stcrypt::toycert_t> const& self_certificate,
			std::wstring const& csp_container_name,
			boost::shared_ptr<stcrypt::toycert_t> ca_certificate, 
			boost::asio::ip::tcp::endpoint const& ca_endpoint,
			boost::function<void(std::string const&)> const& print_msg
			);


		private:

		boost::thread			m_worker_thread;
		boost::asio::io_service m_io_service;
		boost::asio::deadline_timer	m_idle_timer;
	};

} }
//================================================================================================================================================
#endif
//================================================================================================================================================
