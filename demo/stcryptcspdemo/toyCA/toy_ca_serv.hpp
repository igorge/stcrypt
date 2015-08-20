//================================================================================================================================================
// FILE: toy_ca_serv.h
// (c) GIE 2010-03-29  18:03
//
//================================================================================================================================================
#ifndef H_GUARD_TOY_CA_SERV_2010_03_29_18_03
#define H_GUARD_TOY_CA_SERV_2010_03_29_18_03
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "toy-cert-store-db.hpp"

#include "boost/noncopyable.hpp"
#include "boost/optional.hpp"
#include "boost/thread.hpp"
#include "boost/asio.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/function.hpp"
//================================================================================================================================================
namespace stcrypt {

	typedef boost::shared_ptr<boost::asio::ip::tcp::socket> socket_ptr;


	struct  toy_ca_serv_session_t;

	struct toy_ca_serv_t
		: boost::noncopyable
	{
		friend toy_ca_serv_session_t;

		typedef boost::function<void(boost::optional<boost::system::error_code const&> const&, boost::optional<std::string const&> const&)> error_fun_type;
		typedef boost::function<void(ca::cert_store_t::certificate_id_t)> event_certificate_request_type;

		toy_ca_serv_t(ca::db_serv_ptr_t	const& db, error_fun_type const& error_fun, event_certificate_request_type	const & on_cert_request_complete);
		~toy_ca_serv_t();

		void run();

	private:
		void do_run_();
		void start_async_accept_(boost::asio::ip::tcp::acceptor& acceptor);
		void do_accept_client_(socket_ptr const socket, const boost::system::error_code& error, boost::asio::ip::tcp::acceptor& acceptor);

		void invoke_error_handler(boost::system::error_code const& error);
		void invoke_error_handler(std::string const& msg);

	private:
		boost::thread m_listen_thread;
		boost::asio::io_service m_io_service;

		error_fun_type	m_error_fun;
		event_certificate_request_type	const m_on_cert_request_complete;
		ca::db_serv_ptr_t	m_db;
	};
}
//================================================================================================================================================
#endif
//================================================================================================================================================
