//================================================================================================================================================
// FILE: toycert-db.cpp
// (c) GIE 2010-03-31  17:58
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "toycert-client-db.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-key-storage-prop.hpp"
#include "../common/misc/stcrypt-mscertstore-import.hpp"

#include "boost/filesystem.hpp"
#include "boost/utility/in_place_factory.hpp"
#include "boost/iostreams/stream.hpp"
//================================================================================================================================================
namespace stcrypt { namespace caclient {


	struct db_impl_t {
		db_impl_t(ca::log_message_callback_t const log_func)
			: m_logger("client db", log_func)
			, m_db_root(L"./client-cert-db")
			, m_certs_db_root(L"./client-cert-db/certs")
		{
			boost::filesystem::create_directories(m_db_root);
			boost::filesystem::create_directories(m_certs_db_root);

			m_meta_info =  boost::in_place( m_db_root / L"metainfo" );
			boost::filesystem::create_directories(m_meta_info->keyset_root());

		}

		void store_ca_root_certificate_blob(std::vector<char> const& cert_blob);

		void store_self_certificate_blob(std::vector<char> const cert_blob);
		std::vector<char> load_self_certificate_blob();

		boost::shared_ptr<stcrypt::toycert_t> load_ca_root_certificate();

		void store_certificate_request(ca::cert_store_t::certificate_id_t const cert_request_id, std::vector<char> const& session_key_blob, std::wstring const& csp_container_name);
		void load_certificate_request(ca::cert_store_t::certificate_id_t& cert_request_id, std::vector<char>& session_key_blob, std::wstring& csp_container_name);
		void delete_certificate_request();


		void store_keyset_name(std::wstring const& name);
		std::wstring get_keyset_name();

		ca::logger_t	m_logger;
		boost::filesystem::wpath	m_db_root;
		boost::filesystem::wpath	m_certs_db_root;
		boost::optional<stcrypt::keyset_props_t>     m_meta_info;
	};

	void db_impl_t::store_keyset_name(std::wstring const& name){
		m_meta_info->store("csp-container", name);
	}
	std::wstring db_impl_t::get_keyset_name(){
		std::wstring name;
		m_meta_info->read("csp-container", name);
		return name;
	}

	void db_impl_t::delete_certificate_request(){
		m_meta_info->remove("req-id");
		m_meta_info->remove("req-session-key");
		m_meta_info->remove("req-csp-container");
	}


	void db_impl_t::store_certificate_request(ca::cert_store_t::certificate_id_t const cert_request_id, std::vector<char> const& session_key_blob, std::wstring const& csp_container_name){
		m_meta_info->store("req-id", cert_request_id);
		m_meta_info->store("req-session-key", session_key_blob);
		m_meta_info->store("req-csp-container", csp_container_name);

	}

	void db_impl_t::load_certificate_request(ca::cert_store_t::certificate_id_t& cert_request_id, std::vector<char>& session_key_blob, std::wstring& csp_container_name){
		try{
			m_meta_info->read("req-id", cert_request_id);
			m_meta_info->read("req-session-key", session_key_blob);
			m_meta_info->read("req-csp-container", csp_container_name);
		} catch (stcrypt::exception::prop_not_found const&) {
			STCRYPT_THROW_EXCEPTION( exception::certificate_request_not_found() );
		}
	}

	void db_impl_t::store_ca_root_certificate_blob( std::vector<char> const& cert_blob )
	{
		m_meta_info->store("ca-root-certificate", cert_blob);
	}

	void db_impl_t::store_self_certificate_blob(std::vector<char> const cert_blob){
		m_meta_info->store("self-certificate", cert_blob);
	}

	 std::vector<char> db_impl_t::load_self_certificate_blob(){
		std::vector<char> cert_blob;

		m_meta_info->read("self-certificate", cert_blob);

		return cert_blob;
	}

	boost::shared_ptr<stcrypt::toycert_t> db_impl_t::load_ca_root_certificate(){
		boost::shared_ptr<stcrypt::toycert_t> cert;
		std::vector<char> cert_blob;
		try{
			m_meta_info->read("ca-root-certificate", cert_blob);
		}catch(stcrypt::exception::io const&){
			return cert;
		}

		cert.reset( new stcrypt::toycert_t() );

		boost::iostreams::basic_array_source<char> source(&cert_blob[0],cert_blob.size());
		boost::iostreams::stream<boost::iostreams::basic_array_source <char> > input_stream(source);

		cert->x509_load(input_stream, 0);

		return cert;
	}


	db_t::db_t(ca::log_message_callback_t const log_func)
		: m_impl( new db_impl_t(log_func) )
	{

	}
	db_t::~db_t(){

	}

	void db_t::store_ca_root_certificate_blob(std::vector<char> const cert_blob){
		boost::mutex::scoped_lock scoped_lock(m_this_lock);

		m_impl->store_ca_root_certificate_blob(cert_blob);
		import_into_ms_store(cert_blob);
	}

	void db_t::store_self_certificate_blob(std::vector<char> const cert_blob){
		boost::mutex::scoped_lock scoped_lock(m_this_lock);

		m_impl->store_self_certificate_blob(cert_blob);
		import_into_ms_store(cert_blob);
	}

	void db_t::store_keyset_name(std::wstring const& name){
		boost::mutex::scoped_lock scoped_lock(m_this_lock);

		m_impl->store_keyset_name(name);

	}

	std::wstring db_t::get_keyset_name(){
		boost::mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->get_keyset_name();
	}




	boost::shared_ptr<stcrypt::toycert_t> db_t::load_ca_root_certificate(){
		boost::mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->load_ca_root_certificate();
	}

	void db_t::store_certificate_request(ca::cert_store_t::certificate_id_t const cert_request_id, std::vector<char> const& session_key_blob, std::wstring const& csp_container_name){
		boost::mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->store_certificate_request(cert_request_id, session_key_blob, csp_container_name);
	}

	void db_t::load_certificate_request(ca::cert_store_t::certificate_id_t& cert_request_id, std::vector<char>& session_key_blob, std::wstring& csp_container_name){
		boost::mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->load_certificate_request(cert_request_id, session_key_blob, csp_container_name);
	}

	void db_t::delete_certificate_request(){
		boost::mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->delete_certificate_request();
	}

	std::vector<char> db_t::load_self_certificate_blob(){
		boost::mutex::scoped_lock scoped_lock(m_this_lock);

		try{
			return m_impl->load_self_certificate_blob();
		} catch(stcrypt::exception::prop_not_found const&){
			throw exception::self_certificate_not_found();
		}
	}


} }
//================================================================================================================================================ 