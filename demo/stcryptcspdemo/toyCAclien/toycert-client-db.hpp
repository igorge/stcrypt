//================================================================================================================================================
// FILE: toycert-db.h
// (c) GIE 2010-03-31  17:58
//
//================================================================================================================================================
#ifndef H_GUARD_TOYCERT_DB_2010_03_31_17_58
#define H_GUARD_TOYCERT_DB_2010_03_31_17_58
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "../common/toycert/toycert-logger.hpp"
#include "../common/toycert/stcrypt-toycert.hpp"
#include "toycert-db.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-exceptions.hpp"

#include "boost/thread/mutex.hpp"
#include "boost/shared_ptr.hpp"
//================================================================================================================================================
namespace stcrypt { namespace caclient {

	namespace exception {
		struct certificate_request_not_found : stcrypt::exception::not_found {};
		struct self_certificate_not_found : virtual stcrypt::exception::not_found {};
	}

	struct db_impl_t;

	struct db_t {
		friend db_impl_t;

		db_t(ca::log_message_callback_t const log_func);
		~db_t();

		void store_ca_root_certificate_blob(std::vector<char> const cert_blob);
		void store_self_certificate_blob(std::vector<char> const cert_blob);
		std::vector<char> load_self_certificate_blob();

		void store_keyset_name(std::wstring const& name);
		std::wstring get_keyset_name();

		boost::shared_ptr<stcrypt::toycert_t> load_ca_root_certificate();

		void store_certificate_request(ca::cert_store_t::certificate_id_t const cert_request_id, std::vector<char> const& session_key_blob, std::wstring const& csp_container_name);
		void load_certificate_request(ca::cert_store_t::certificate_id_t& cert_request_id, std::vector<char>& session_key_blob, std::wstring& csp_container_name);
		void delete_certificate_request();

		
		private:
		boost::mutex	m_this_lock;
		boost::shared_ptr<db_impl_t> m_impl;
	};

} }
//================================================================================================================================================
#endif
//================================================================================================================================================ 