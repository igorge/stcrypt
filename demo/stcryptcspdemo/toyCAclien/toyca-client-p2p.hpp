//================================================================================================================================================
// FILE: toyca-client-p2p.h
// (c) GIE 2010-04-18  14:29
//
//================================================================================================================================================
#ifndef H_GUARD_TOYCA_CLIENT_P2P_2010_04_18_14_29
#define H_GUARD_TOYCA_CLIENT_P2P_2010_04_18_14_29
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "toyca-client-worker.hpp"
//================================================================================================================================================
namespace stcrypt { namespace  caclient {
	boost::shared_ptr<client_session_i> new_listen_session(
		worker_t& parent, 
		boost::shared_ptr<boost::asio::ip::tcp::socket> const & socket,
		boost::shared_ptr<toycert_t> const& self_cert,
		std::wstring const& self_keyset_container_name,
		boost::shared_ptr<toycert_t> const& ca_cert, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		boost::function<void(std::string const&)> const& print_msg);

	boost::shared_ptr<client_session_i> new_send_text_session(
		worker_t& parent, 
		std::string const& message,
		boost::asio::ip::tcp::endpoint const& peer_endpoint,
		boost::shared_ptr<toycert_t> const& self_cert,
		std::wstring const& self_keyset_container_name,
		boost::shared_ptr<toycert_t> const& ca_cert, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		boost::function<void(std::string const&)> const& print_msg);


} }

//================================================================================================================================================
#endif
//================================================================================================================================================
