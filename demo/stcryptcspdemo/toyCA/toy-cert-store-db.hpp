//================================================================================================================================================
// FILE: toy-cert-store-db.h
// (c) GIE 2010-03-30  15:36
//
//================================================================================================================================================
#ifndef H_GUARD_TOY_CERT_STORE_DB_2010_03_30_15_36
#define H_GUARD_TOY_CERT_STORE_DB_2010_03_30_15_36
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "../common/toycert/toycert-logger.hpp"
#include "../common/toycert/stcrypt-toycert.hpp"
#include "../toyCAclien/toycert-db.hpp"

#include "boost/thread.hpp"
#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/tuple/tuple.hpp"
//================================================================================================================================================
namespace stcrypt { namespace ca {

	namespace exception {
		struct cert_not_fount_e : stcrypt::exception::not_found {};
	}

	struct db_serv_impl_t;

	struct db_serv_t 
		: boost::noncopyable
	{
		typedef boost::tuple< boost::shared_ptr<toycert_t>, cert_status_t > certificate_info_type;
		typedef boost::tuple< boost::shared_ptr<toycert_t>, cert_request_store_t::cert_request_status_t, boost::shared_ptr< std::vector<char> > > request_info_type;

		friend db_serv_impl_t;

		db_serv_t(log_message_callback_t const& log_func);
		void get_root_cert_blob(std::vector<char>& blob);
		cert_store_t::certificate_id_t store_new_request_blob(std::vector<char> const& blob, std::vector<char> const &session_key);
		void store_new_certifictae_blob(cert_store_t::certificate_id_t const serial, std::vector<char> const& blob);

		cert_store_t::certificate_id_t alloc_new_serial();

		void enumerate_certificates( cert_store_t::enumerate_certificate_callback_t  const& enum_callback );
		void enumerate_requests( cert_store_t::enumerate_certificate_callback_t  const& enum_callback );

		certificate_info_type load_certificate_by_serial(cert_store_t::certificate_id_t const id, toycert_t& verify_with_cert);
		std::vector<char>     load_certificate_blob_by_serial(cert_store_t::certificate_id_t const serial);
		request_info_type load_request_by_serial(cert_store_t::certificate_id_t const id);
		void change_request_state(ca::cert_store_t::certificate_id_t const serial, cert_request_store_t::request_status_t const status);

		void store_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial, ca::cert_store_t::certificate_id_t const serial);
		ca::cert_store_t::certificate_id_t load_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial);

		stcrypt::toycert_t& get_ca_cert();
		std::wstring const& get_ca_private_key_container_name()const;

		void set_revoked_status( cert_store_t::certificate_id_t const serial, bool const is_revoked);
		bool get_revoked_status( cert_store_t::certificate_id_t const serial);

	private:
		boost::recursive_mutex	m_this_lock;
		logger_t m_logger;
		boost::shared_ptr<db_serv_impl_t>	m_impl;
	};

	typedef boost::shared_ptr<db_serv_t> db_serv_ptr_t;

} }
//================================================================================================================================================
#endif
//================================================================================================================================================
