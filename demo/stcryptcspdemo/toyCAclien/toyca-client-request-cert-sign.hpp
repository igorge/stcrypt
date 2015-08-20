//================================================================================================================================================
// FILE: toyca-client-request-cert-sign.h
// (c) GIE 2010-04-03  22:42
//
//================================================================================================================================================
#ifndef H_GUARD_TOYCA_CLIENT_REQUEST_CERT_SIGN_2010_04_03_22_42
#define H_GUARD_TOYCA_CLIENT_REQUEST_CERT_SIGN_2010_04_03_22_42
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "toyca-client-worker.hpp"
#include "toycert-client-db.hpp"
//================================================================================================================================================
namespace stcrypt { namespace  caclient {

	client_session_ptr create_session__request_sign_certificate(
		caclient::db_t& db, 
		worker_t& parent, 
		boost::shared_ptr< stcrypt::toycert_t> ca_certificate, 
		boost::shared_ptr< stcrypt::toycert_t> m_certificate_to_sign, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		worker_t::event__got_self_cert const & callback, 
		worker_t::event__error_type const& error_callback);

	client_session_ptr create_session__resume_request_sign_certificate(
		ca::cert_store_t::certificate_id_t const cert_request_id,
		std::vector<char> const& session_key_blob,
		std::wstring const& csp_container_name,

		caclient::db_t& db, 
		worker_t& parent, 
		boost::shared_ptr< stcrypt::toycert_t> ca_certificate, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		worker_t::event__got_self_cert const & callback, 
		worker_t::event__error_type const& error_callback);

} }

//================================================================================================================================================
#endif
//================================================================================================================================================
