//================================================================================================================================================
// FILE: toycert-client-db.cpp
// (c) GIE 2010-03-31  16:40
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "toycert-db.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-exceptions.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-key-storage-prop.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-crypto-alg-ids.h"

#include "boost/filesystem.hpp"
#include "boost/lexical_cast.hpp"
//================================================================================================================================================
namespace stcrypt { namespace ca {


	cert_store_t::cert_store_t(boost::filesystem::wpath const& cert_store_root)
		: m_cert_store_root( cert_store_root )
	{
		boost::filesystem::create_directories(cert_store_root);
	}
	
	cert_store_t::~cert_store_t(){

	}

	void cert_store_t::enumerate_certificates( cert_store_t::enumerate_certificate_callback_t  const& enum_callback ){
		if(!boost::filesystem::exists(m_cert_store_root)) STCRYPT_UNEXPECTED();

		boost::filesystem::wdirectory_iterator const end_itr;
		for (boost::filesystem::wdirectory_iterator itr(m_cert_store_root); itr != end_itr; ++itr)
		{
			stcrypt::keyset_props_t cert_store( *itr );
			long serial = 0;
			cert_store.read("serial", serial);
			enum_callback(serial);
		}


	}


	std::wstring const cert_store_t::serial_to_string(long const serial){
		return boost::lexical_cast<std::wstring>(serial);
	}

	void cert_store_t::store_cert_blob( std::vector<char> const& cert_blob, cert_store_t::certificate_id_t const serial, boost::optional<std::wstring> const& csp_container_name /*= boost::none*/ ){
		stcrypt::keyset_props_t cert_store(m_cert_store_root / serial_to_string(serial) );

		return store_cert_blob_(cert_store, cert_blob, serial, csp_container_name);
	}

	std::string ugly_wide2narrow2(std::wstring const& wstr){ //TODO: merge
		std::vector<char> buf(wstr.size());
		std:copy(wstr.begin(), wstr.end(), buf.begin() );

		return std::string(&buf[0], buf.size());
	}

	void cert_store_t::store_cert_blob_(stcrypt::keyset_props_t& props, std::vector<char> const& cert_blob, cert_store_t::certificate_id_t const serial, boost::optional<std::wstring> const& csp_container_name /*= boost::none*/ )
	{
		stcrypt::keyset_props_t& cert_store = props;

		if( !boost::filesystem::create_directory(cert_store.keyset_root()) ){
			STCRYPT_UNEXPECTED1( ugly_wide2narrow2(cert_store.keyset_root().directory_string()) );
		}

		cert_store.store("serial", serial);

		if(csp_container_name)
			cert_store.store("private-key-id", *csp_container_name);

		cert_store.store("blob", cert_blob);
	}

	bool cert_store_t::load_cert_blob_by_serial(long const serial, std::vector<char>& cert_blob, cert_status_t& status){
		stcrypt::keyset_props_t cert_store(m_cert_store_root / serial_to_string(serial) );

		return  load_cert_blob_by_serial_(cert_store, serial, cert_blob, status);
	}

	bool cert_store_t::load_cert_blob_by_serial_(stcrypt::keyset_props_t& props, long const serial, std::vector<char>& cert_blob, cert_status_t& status){

		stcrypt::keyset_props_t& cert_store = props;

		try {
			cert_store.read("blob", cert_blob);
			try {
				std::wstring csp_container;
				cert_store.read("private-key-id", csp_container);
				status.m_csp_container_name = csp_container;
			} catch(stcrypt::exception::io const&){
				status.m_csp_container_name == boost::none;
			}
		} catch(stcrypt::exception::io const&){
			return false;
		}
		return true;
	}

	void cert_store_t::set_revoked_status( cert_store_t::certificate_id_t const serial, bool const is_revoked){
		stcrypt::keyset_props_t cert_store(m_cert_store_root / serial_to_string(serial) );

		unsigned int const status = is_revoked?1:0;
		
		cert_store.store("is-revoked", status);

	}

	bool cert_store_t::get_revoked_status( cert_store_t::certificate_id_t const serial){
		stcrypt::keyset_props_t cert_store(m_cert_store_root / serial_to_string(serial) );

		unsigned int status;

		try{
			cert_store.read("is-revoked", status);

		}catch(exception::prop_not_found const&){
			return false;
		}
		
		switch(status){
			case 0: return false;
			case 1: return true;
			default: STCRYPT_UNEXPECTED1("invalid revocation status");
		}
	}


	bool cert_request_store_t::load_cert_request_blob_by_serial( long const serial, std::vector<char>& cert_blob, cert_request_status_t& status, boost::shared_ptr< std::vector<char> >& session_key )
	{
		stcrypt::keyset_props_t cert_store(m_cert_store_root / serial_to_string(serial) );

		load_cert_blob_by_serial_(cert_store, serial, cert_blob, status);
		session_key.reset( new std::vector<char>() );
		cert_store.read("session-key", *session_key);
		cert_store.read("status", status.m_request_status);

		return true;
	}

	void cert_request_store_t::store_cert_request_blob(std::vector<char> const& cert_blob, cert_store_t::certificate_id_t const serial, std::vector<char> const& session_key){
		stcrypt::keyset_props_t cert_store(m_cert_store_root / serial_to_string(serial) );

		this->store_cert_blob_(cert_store, cert_blob, serial, boost::none);

		cert_store.store("session-key", session_key);

		request_status_t const req_status = reques_status_pending;
		cert_store.store("status", req_status);
	}

	void cert_request_store_t::change_request_state( ca::cert_store_t::certificate_id_t const serial, cert_request_store_t::request_status_t const status )
	{
		stcrypt::keyset_props_t cert_store(m_cert_store_root / serial_to_string(serial) );

		if( !cert_store.is_prop_exists("status") ) STCRYPT_UNEXPECTED();

		cert_store.store("status", status);
	}

	void cert_request_store_t::store_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial, ca::cert_store_t::certificate_id_t const serial){
		stcrypt::keyset_props_t cert_store(m_cert_store_root / serial_to_string(request_serial) );

		cert_store.store("approved-serial", serial);
	}

	ca::cert_store_t::certificate_id_t cert_request_store_t::load_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial){
		stcrypt::keyset_props_t cert_store(m_cert_store_root / serial_to_string(request_serial) );

		ca::cert_store_t::certificate_id_t tmp;

		cert_store.read("approved-serial", tmp);

		return tmp;
	}





} }
//================================================================================================================================================ 