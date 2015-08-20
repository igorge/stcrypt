//================================================================================================================================================
// FILE: toycert-client-db.h
// (c) GIE 2010-03-31  16:40
//
//================================================================================================================================================
#ifndef H_GUARD_TOYCERT_CLIENT_DB_2010_03_31_16_40
#define H_GUARD_TOYCERT_CLIENT_DB_2010_03_31_16_40
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-exceptions.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-key-storage-prop.hpp"


#include "boost/thread.hpp"
#include "boost/function.hpp"
#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.hpp"
#include "boost/optional.hpp"
#include "boost/filesystem/path.hpp"
//================================================================================================================================================
namespace stcrypt { namespace ca {

	struct cert_status_t {
		enum signature_check_status_t{ sc_unknown, sc_ok, sc_failed };

		boost::optional<std::wstring> m_csp_container_name;
		signature_check_status_t	  m_signature_check_status;
		bool						  m_signature_trusted;


		std::string signature_check_as_string(){
			if( m_signature_check_status == sc_unknown ) {
				return "unknown";
			} else if(m_signature_check_status == sc_ok ) {
				return "signature_ok";
			} else if( m_signature_check_status ==sc_failed ){ 
				return "signature_failed";
			} else STCRYPT_UNEXPECTED();
		}

		cert_status_t()
			: m_signature_check_status(sc_unknown)
			, m_signature_trusted( false )
		{}

	};



	struct cert_store_t
		: boost::noncopyable
	{

		typedef long certificate_id_t;

		typedef boost::function<void(cert_store_t::certificate_id_t const)> enumerate_certificate_callback_t;

		cert_store_t(boost::filesystem::wpath const& cert_store_root);
		~cert_store_t();

		static
		std::wstring const cert_store_t::serial_to_string(long const serial);

		bool load_cert_blob_by_serial(long const serial, std::vector<char>& cert_blob, cert_status_t& status);
		void enumerate_certificates( enumerate_certificate_callback_t const& enum_callback );

		void store_cert_blob(std::vector<char> const& cert_blob, cert_store_t::certificate_id_t const serial, boost::optional<std::wstring> const& csp_container_name = boost::none);

		void set_revoked_status( cert_store_t::certificate_id_t const serial, bool const is_revoked);
		bool get_revoked_status( cert_store_t::certificate_id_t const serial);
	protected:
		void store_cert_blob_(stcrypt::keyset_props_t& props, std::vector<char> const& cert_blob, cert_store_t::certificate_id_t const serial, boost::optional<std::wstring> const& csp_container_name = boost::none);
		bool load_cert_blob_by_serial_(stcrypt::keyset_props_t& props,long const serial, std::vector<char>& cert_blob, cert_status_t& status);
		boost::filesystem::wpath const m_cert_store_root;

	};

	struct cert_request_store_t : cert_store_t {
		typedef unsigned int request_status_t;

		static request_status_t const reques_status_pending = 1;
		static request_status_t const reques_status_rejected = 2;
		static request_status_t const reques_status_approved = 3;

		struct cert_request_status_t : cert_status_t {
			request_status_t	m_request_status;
			boost::optional<cert_store_t::certificate_id_t> m_certificate_id; //if signed, certificate id in db
			//std::vector<char>	m_session_key;

			std::string request_status_as_string(){
				switch( m_request_status ) {
					case reques_status_pending: return "pending";
					case reques_status_rejected: return "rejected";
					case reques_status_approved: return "approved";
					default: STCRYPT_UNEXPECTED();
				}
			}

		};


		cert_request_store_t(boost::filesystem::wpath const& cert_store_root)
			: cert_store_t( cert_store_root )
		{}

		bool load_cert_request_blob_by_serial(long const serial, std::vector<char>& cert_blob, cert_request_status_t& status, boost::shared_ptr< std::vector<char> >& session_key);
		void store_cert_request_blob(std::vector<char> const& cert_blob, cert_store_t::certificate_id_t const serial, std::vector<char> const& session_key);
		void change_request_state(ca::cert_store_t::certificate_id_t const serial, cert_request_store_t::request_status_t const status);
		void store_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial, ca::cert_store_t::certificate_id_t const serial);
		ca::cert_store_t::certificate_id_t load_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial);

	};

} }
//================================================================================================================================================
#endif
//================================================================================================================================================ 