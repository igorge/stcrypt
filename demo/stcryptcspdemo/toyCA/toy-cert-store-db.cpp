//================================================================================================================================================
// FILE: toy-cert-store-db.cpp
// (c) GIE 2010-03-30  15:36
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "../toyCAclien/toycert-db.hpp"
#include "toy-cert-store-db.hpp"

#include "../common/toycert/stcrypt-toycert.hpp"
#include "../common/toycert/stcrypt-toycert-signature-verifier.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-exceptions.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-key-storage-prop.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-crypto-alg-ids.h"
#include "../common/misc/stcrypt-mscertstore-import.hpp"

#include "boost/format.hpp"
#include "boost/filesystem.hpp"
#include "boost/lexical_cast.hpp"
#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"
#include "boost/random.hpp"
#include "boost/assign.hpp"
#include "boost/iostreams/stream.hpp"
#include "boost/iostreams/device/back_inserter.hpp"

#include <sstream>
//================================================================================================================================================
namespace stcrypt { namespace ca {


	std::string ugly_wide2narrow(std::wstring const& wstr){
		std::vector<char> buf(wstr.size());
		std:copy(wstr.begin(), wstr.end(), buf.begin() );

		return std::string(&buf[0], buf.size());
	}

	struct db_serv_impl_t
	{

		db_serv_impl_t(db_serv_t&parent,  boost::filesystem::wpath const& db_root)
			: m_db_root( db_root )
			, m_db_metainfo( db_root / L"metainfo")
			, m_parent(parent)
		{

			std::string const& db_root_narrow = ugly_wide2narrow( m_db_root.string() );
			m_parent.m_logger.log_message("db path", db_root_narrow );

			boost::filesystem::create_directory(m_db_root);
			boost::filesystem::create_directory(m_db_metainfo.keyset_root());

			m_cert_store.reset( new cert_store_t(m_db_root / L"certs") );
			m_cert_request_store.reset(new cert_request_store_t(m_db_root / L"certs-req") );


			{
				try{
					m_db_metainfo.read("serial", m_cert_curr_serial);
				} catch(stcrypt::exception::io const& e){

					m_parent.m_logger.log_message("'serial' not found, creating.");

					m_cert_curr_serial = 0;
					m_db_metainfo.store("serial", m_cert_curr_serial);
				}

				m_parent.m_logger.log_message("serial",m_cert_curr_serial);


			}

			{
				try{
					m_db_metainfo.read("req-serial", m_cert_request_curr_serial);
				} catch(stcrypt::exception::io const& e){

					m_parent.m_logger.log_message("'req-serial' not found, creating.");

					m_cert_request_curr_serial = 0;
					m_db_metainfo.store("req-serial", m_cert_request_curr_serial);
				}

				m_parent.m_logger.log_message("req-serial",m_cert_request_curr_serial);


			}

			load_or_create_ca_cert_();

		}

		long get_free_serial_(){
			return m_cert_curr_serial++;
		}

		static
		std::wstring const serial_to_string_(long const serial){
			return cert_store_t::serial_to_string(serial);
		}

		void load_or_create_ca_cert_();
		void create_ca_cert_(long const serial);
		bool load_cert_blob_by_serial_(long const serial, std::vector<char>& cert_blob, cert_status_t& status);
		void db_update_serial_();
		void db_update_req_serial_();
		cert_store_t::certificate_id_t store_new_request_blob(std::vector<char> const& blob, std::vector<char> const &session_key);

		std::pair<stcrypt::cryptprov_ptr_t, stcrypt::cryptkey_ptr_t> generate_keypair_(std::vector<char>& public_key_blob, std::wstring const & csp_container_name);


		boost::filesystem::wpath  m_db_root;
		stcrypt::keyset_props_t	  m_db_metainfo;

		long					  m_cert_curr_serial;
		long					  m_cert_request_curr_serial;
		stcrypt::toycert_t		  m_ca_cert;
		std::wstring			  m_ca_private_key_container_name;

		db_serv_t	&m_parent;

		boost::shared_ptr<cert_store_t>	m_cert_store;
		boost::shared_ptr<cert_request_store_t>	m_cert_request_store;

		void get_root_cert_blob(std::vector<char>& blob);
		db_serv_t::certificate_info_type load_certificate_by_serial(cert_store_t::certificate_id_t const id, toycert_t& verify_with_cert);
		db_serv_t::request_info_type load_request_by_serial(cert_store_t::certificate_id_t const id);
		void enumerate_certificates( cert_store_t::enumerate_certificate_callback_t const& enum_callback );
		void enumerate_requests( cert_store_t::enumerate_certificate_callback_t const& enum_callback );

		void change_request_state(ca::cert_store_t::certificate_id_t const serial, cert_request_store_t::request_status_t const status);


		cert_store_t::certificate_id_t alloc_new_serial();

		stcrypt::toycert_t& get_ca_cert(){
			return m_ca_cert;
		}

		std::wstring const& get_ca_private_key_container_name()const{
			return m_ca_private_key_container_name;
		}
		
		void store_new_certifictae_blob(cert_store_t::certificate_id_t const serial, std::vector<char> const& blob);
		void store_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial, ca::cert_store_t::certificate_id_t const serial);
		ca::cert_store_t::certificate_id_t load_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial);

		void set_revoked_status( cert_store_t::certificate_id_t const serial, bool const is_revoked){
			return m_cert_store->set_revoked_status(serial, is_revoked);
		}
		bool get_revoked_status( cert_store_t::certificate_id_t const serial){
			return m_cert_store->get_revoked_status(serial);
		}


	};

	void db_serv_impl_t::store_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial, ca::cert_store_t::certificate_id_t const serial){
		m_cert_request_store->store_approved_request_cert_serial(request_serial, serial);
	}

	ca::cert_store_t::certificate_id_t db_serv_impl_t::load_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial){
		return m_cert_request_store->load_approved_request_cert_serial(request_serial);
	}

	void db_serv_impl_t::change_request_state( ca::cert_store_t::certificate_id_t const serial, cert_request_store_t::request_status_t const status )
	{
		m_cert_request_store->change_request_state( serial, status );
	}

	db_serv_t::certificate_info_type db_serv_impl_t::load_certificate_by_serial(cert_store_t::certificate_id_t const id, toycert_t& verify_with_cert){
		std::vector<char> cert_blob; 
		cert_status_t	  status;
		load_cert_blob_by_serial_(id, cert_blob, status);

		boost::shared_ptr<toycert_t> cert ( new toycert_t() );
		boost::iostreams::basic_array_source<char> source(&cert_blob[0],cert_blob.size());
		boost::iostreams::stream<boost::iostreams::basic_array_source <char> > input_stream(source);

		struct load_certificate_by_serial__verify_signature { static bool run(toycert_t& verify_with_cert, char const * const data, size_t const size, oid::oid_type const& sign_alg_oid,  toycert_t::signature_blob_t const& signature){
			return verify_signature_via_csp(data, size, signature, verify_with_cert);
		} };
		
		if( cert->x509_load(input_stream, boost::bind(&load_certificate_by_serial__verify_signature::run, boost::ref(verify_with_cert), _1, _2, _3, _4) ) ) {
			status.m_signature_check_status = cert_status_t::sc_ok;
		} else {
			status.m_signature_check_status = cert_status_t::sc_failed;
		}

		return db_serv_t::certificate_info_type(cert, status);
	}

	void db_serv_impl_t::store_new_certifictae_blob( cert_store_t::certificate_id_t const serial, std::vector<char> const& blob )
	{
		m_cert_store->store_cert_blob(blob, serial);
		import_into_ms_store(blob);
	}


	cert_store_t::certificate_id_t db_serv_impl_t::alloc_new_serial(){
		cert_store_t::certificate_id_t const allocated_serial = m_cert_curr_serial++;

		this->db_update_serial_();

		return allocated_serial ;
	}

	db_serv_t::request_info_type db_serv_impl_t::load_request_by_serial( cert_store_t::certificate_id_t const id )
	{
		std::vector<char> cert_blob; 
		cert_request_store_t::cert_request_status_t	status;
		boost::shared_ptr<std::vector<char> > session_key;
		if( !m_cert_request_store->load_cert_request_blob_by_serial(id, cert_blob, status, session_key) ) STCRYPT_UNEXPECTED();

		boost::shared_ptr<toycert_t> cert ( new toycert_t() );
		boost::iostreams::basic_array_source<char> source(&cert_blob[0],cert_blob.size());
		boost::iostreams::stream<boost::iostreams::basic_array_source <char> > input_stream(source);

		struct load_request_by_serial__verify_signature { static bool run(char const * const data, size_t const size, oid::oid_type const& sign_alg_oid,  toycert_t::signature_blob_t const& signature){
			return true; // requests have not been signed yet
		} };

		if( cert->x509_load(input_stream, boost::bind(&load_request_by_serial__verify_signature::run,  _1, _2, _3, _4) ) ) {
			status.m_signature_check_status = cert_status_t::sc_ok;
		} else {
			status.m_signature_check_status = cert_status_t::sc_failed;
		}

		return db_serv_t::request_info_type(cert, status, session_key);
	}


	void db_serv_impl_t::enumerate_certificates(cert_store_t::enumerate_certificate_callback_t const& enum_callback ){
		return m_cert_store->enumerate_certificates( enum_callback );
	}

	void db_serv_impl_t::enumerate_requests(cert_store_t::enumerate_certificate_callback_t const& enum_callback ){
		return m_cert_request_store->enumerate_certificates( enum_callback );
	}

	void db_serv_impl_t::db_update_serial_(){
		m_db_metainfo.store("serial", m_cert_curr_serial);
	}

	void db_serv_impl_t::db_update_req_serial_(){
		m_db_metainfo.store("req-serial", m_cert_request_curr_serial);
	}


	db_serv_t::db_serv_t(log_message_callback_t const& log_func)
		: m_logger("cert-db", log_func )
	{
		m_impl.reset( new db_serv_impl_t( *this, L"./cert-db" ) );
	}

	std::pair<stcrypt::cryptprov_ptr_t, stcrypt::cryptkey_ptr_t> db_serv_impl_t::generate_keypair_(std::vector<char>& public_key_blob, std::wstring const & csp_container_name){
		BOOST_STATIC_ASSERT(sizeof(BYTE)==sizeof(char));

		stcrypt::cryptprov_ptr_t cprov = create_cryptprov_ptr(csp_container_name.c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, CRYPT_NEWKEYSET);
		stcrypt::cryptkey_ptr_t keypair = generate_cryptkey_ptr(*cprov, AT_SIGNATURE /*CALG_DSTU4145_SIGN*/, 0);
		DWORD blob_size = 0;
		STCRYPT_CHECK_MSCRYPTO( CryptExportKey(*keypair, 0, PUBLICKEYBLOB, 0,0, &blob_size) );
		public_key_blob.resize(blob_size);
		STCRYPT_CHECK_MSCRYPTO( CryptExportKey(*keypair, 0, PUBLICKEYBLOB, 0,reinterpret_cast<BYTE*>( &public_key_blob[0] ), &blob_size) );

		return std::make_pair(cprov, keypair);
	}

	cert_store_t::certificate_id_t db_serv_impl_t::store_new_request_blob(std::vector<char> const& blob, std::vector<char> const &session_key){
		cert_store_t::certificate_id_t req_serial = m_cert_request_curr_serial++;
		db_update_req_serial_();

		m_cert_request_store->store_cert_request_blob(blob, req_serial, session_key);

		return req_serial;
	}


	void db_serv_impl_t::create_ca_cert_(long const serial){
		using boost::assign::operator+=;

		struct name_initer { static void run(stcrypt::toycert_t::issuer_t & n) {
			n.set_common_name("STCRYPT");
			n.set_country_name("UA");
			n.set_locality_name("Ukraine");
			n.set_organization_name("STCRYPT.ORG");
			n.set_organization_unit_name("STCRYPTCA");
			n.set_state_or_province_name("Kiev");
		}};

		m_ca_cert.set_serial(serial);
		name_initer::run( m_ca_cert.issuer() );
		name_initer::run( m_ca_cert.subject() );

		boost::posix_time::ptime const not_before_time = boost::posix_time::second_clock::universal_time();
		boost::posix_time::ptime const not_after_time = ( not_before_time + boost::gregorian::days(7) ); 
		m_ca_cert.validity().set(not_before_time, not_after_time);


		boost::uuids::basic_random_generator<boost::mt19937> gen;
		boost::uuids::uuid crypto_container_id = gen();
		std::wostringstream crypto_container_id_as_string_sonverter;
		crypto_container_id_as_string_sonverter << crypto_container_id;
		std::wstring const& crypto_container_id_as_string = crypto_container_id_as_string_sonverter.str();

		std::vector<char> public_key_blob;
		std::pair<stcrypt::cryptprov_ptr_t, stcrypt::cryptkey_ptr_t> const& csp_key = generate_keypair_(public_key_blob, crypto_container_id_as_string);

		stcrypt::oid::oid_type oid;
		oid+=SCTRYPT_ALG_OID;

		m_ca_cert.set_public_key_blob(public_key_blob, oid);

		struct blob_signer { static void run(std::pair<stcrypt::cryptprov_ptr_t, stcrypt::cryptkey_ptr_t> const& csp_key, char const * const data, size_t const size, toycert_t::signature_blob_t& signature){
			BOOST_STATIC_ASSERT(sizeof(char)==sizeof(BYTE));

			stcrypt::crypthash_ptr_t hash = create_crypthash_ptr(*csp_key.first, CALG_ID_HASH_G34311, 0/* *csp_key.second */, 0);
			STCRYPT_CHECK_MSCRYPTO( CryptHashData(*hash, reinterpret_cast<BYTE const*>(data), size, 0) );

			DWORD signature_size=0;
			STCRYPT_CHECK_MSCRYPTO( CryptSignHash(*hash, AT_SIGNATURE, 0, 0, 0, &signature_size) );
			signature.resize(signature_size);
			STCRYPT_CHECK_MSCRYPTO( CryptSignHash(*hash, AT_SIGNATURE, 0, 0, reinterpret_cast<BYTE*>( &signature[0] ), &signature_size) );
			
		}};

		typedef std::vector<char> buffer_type;
		buffer_type cert_blob;
		cert_blob.reserve(4*1024);

		{
			boost::iostreams::stream<boost::iostreams::back_insert_device<buffer_type> > cert_blob_stream(cert_blob);

			m_ca_cert.x509_save(cert_blob_stream, oid, boost::bind(&blob_signer::run, boost::ref(csp_key), _1, _2, _3) );

			cert_blob_stream.flush();
		}
		m_cert_store->store_cert_blob(cert_blob, serial, crypto_container_id_as_string);
		import_into_ms_store(cert_blob);

		m_ca_private_key_container_name = crypto_container_id_as_string;

/*		stcrypt::keyset_props_t cert_store(m_db_root / L"certs" / serial_to_string_(serial) );
		if( !boost::filesystem::create_directory(cert_store.keyset_root()) ){
			STCRYPT_UNEXPECTED();
		}
		cert_store.store("serial", serial);
		cert_store.store("private-key-id", crypto_container_id_as_string);
		cert_store.store("blob", cert_blob);*/
	

	}

	void db_serv_impl_t::load_or_create_ca_cert_(){

		long ca_cert_serial;
		try{
			m_db_metainfo.read("ca-cert-serial", ca_cert_serial);
		} catch(stcrypt::exception::io const&) {
			ca_cert_serial = get_free_serial_();
			create_ca_cert_(ca_cert_serial);
			m_parent.m_logger.log_message("created root certificate", ca_cert_serial);

			m_db_metainfo.store("ca-cert-serial", ca_cert_serial);
			db_update_serial_();

			return;
		}

		std::vector<char> cert_blob; cert_status_t cert_status;
		if( load_cert_blob_by_serial_(ca_cert_serial, cert_blob, cert_status) ){

			struct blob_verifyer {  static bool run(boost::optional<std::wstring> const& csp_container_name, char const * const data, size_t const size, oid::oid_type const& sign_alg_oid,  toycert_t::signature_blob_t const& signature){
				BOOST_STATIC_ASSERT(sizeof(char)==sizeof(BYTE));

				//TODO:: check oid
				if( !csp_container_name )
					return false;

				stcrypt::cryptprov_ptr_t cprov = create_cryptprov_ptr(csp_container_name->c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, 0);

				stcrypt::crypthash_ptr_t hash = create_crypthash_ptr(*cprov, CALG_ID_HASH_G34311, 0, 0);
				STCRYPT_CHECK_MSCRYPTO( CryptHashData(*hash, reinterpret_cast<BYTE const*>(data), size, 0) );

				stcrypt::cryptkey_ptr_t const v_key = get_user_cryptkey_ptr(*cprov, AT_SIGNATURE);

				//DWORD signature_size=0;
				try {
					STCRYPT_CHECK_MSCRYPTO( CryptVerifySignature(*hash, reinterpret_cast<BYTE const*>( &signature[0] ), signature.size(), *v_key, 0,0 ) );
				} catch ( stcrypt::exception::cryptoapi_error const&e ) {
					return false;
				}

				return true;
			}};

			boost::iostreams::basic_array_source<char> source(&cert_blob[0],cert_blob.size());
			boost::iostreams::stream<boost::iostreams::basic_array_source <char> > input_stream(source);

			if(!cert_status.m_csp_container_name) STCRYPT_UNEXPECTED();
			m_ca_private_key_container_name =  *cert_status.m_csp_container_name;

			if( m_ca_cert.x509_load(input_stream, boost::bind(&blob_verifyer::run, boost::ref(cert_status.m_csp_container_name), _1, _2, _3, _4 )) ){
				m_parent.m_logger.log_message("loaded root certificate");
			} else {
				m_parent.m_logger.log_message("failed to loaded root certificate", "signature failure");
			}

		} else {
			STCRYPT_UNEXPECTED(); //db is broken 
		}

	}

	bool db_serv_impl_t::load_cert_blob_by_serial_(long const serial, std::vector<char>& cert_blob, cert_status_t& status){
		return m_cert_store->load_cert_blob_by_serial(serial, cert_blob, status);

	}

	void db_serv_impl_t::get_root_cert_blob(std::vector<char>& blob){
		long ca_cert_serial;
		cert_status_t status;
		m_db_metainfo.read("ca-cert-serial", ca_cert_serial);
		if( !load_cert_blob_by_serial_(ca_cert_serial, blob, status) ){
			STCRYPT_UNEXPECTED();
		}


	}

	void db_serv_t::get_root_cert_blob(std::vector<char>& blob){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->get_root_cert_blob(blob);
	}


	void db_serv_t::enumerate_certificates( cert_store_t::enumerate_certificate_callback_t const& enum_callback ){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->enumerate_certificates(enum_callback );
	}

	void db_serv_t::enumerate_requests( cert_store_t::enumerate_certificate_callback_t const& enum_callback ){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->enumerate_requests(enum_callback );
	}

	db_serv_t::certificate_info_type db_serv_t::load_certificate_by_serial(cert_store_t::certificate_id_t const id, toycert_t& verify_with_cert){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->load_certificate_by_serial(id, verify_with_cert);
	}

	std::vector<char>     db_serv_t::load_certificate_blob_by_serial(cert_store_t::certificate_id_t const serial){
		std::vector<char> cert_blob;
		cert_status_t status;
		if( !m_impl->load_cert_blob_by_serial_(serial, cert_blob, status) )
			STCRYPT_THROW_EXCEPTION( ca::exception::cert_not_fount_e() );

		return cert_blob;
	}


	db_serv_t::request_info_type db_serv_t::load_request_by_serial( cert_store_t::certificate_id_t const id )
	{
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->load_request_by_serial(id);
	}


	stcrypt::toycert_t& db_serv_t::get_ca_cert(){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->get_ca_cert();

	}

	std::wstring const& db_serv_t::get_ca_private_key_container_name()const{
		//boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->get_ca_private_key_container_name();
	}

	cert_store_t::certificate_id_t db_serv_t::store_new_request_blob(std::vector<char> const& blob, std::vector<char> const &session_key){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->store_new_request_blob(blob, session_key);

	}

	void db_serv_t::change_request_state( ca::cert_store_t::certificate_id_t const serial, cert_request_store_t::request_status_t const status )
	{
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->change_request_state(serial, status);
	}

	void db_serv_t::store_new_certifictae_blob( cert_store_t::certificate_id_t const serial, std::vector<char> const& blob )
	{
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->store_new_certifictae_blob(serial, blob);

	}

	ca::cert_store_t::certificate_id_t db_serv_t::load_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->load_approved_request_cert_serial(request_serial);
	}

	void db_serv_t::store_approved_request_cert_serial(ca::cert_store_t::certificate_id_t const request_serial, ca::cert_store_t::certificate_id_t const serial){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->store_approved_request_cert_serial(request_serial, serial);
	}


	cert_store_t::certificate_id_t db_serv_t::alloc_new_serial(){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->alloc_new_serial();
	}

	void db_serv_t::set_revoked_status( cert_store_t::certificate_id_t const serial, bool const is_revoked){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->set_revoked_status(serial, is_revoked);

	}

	bool db_serv_t::get_revoked_status( cert_store_t::certificate_id_t const serial){
		boost::recursive_mutex::scoped_lock scoped_lock(m_this_lock);

		return m_impl->get_revoked_status(serial);

	}


} }
//================================================================================================================================================
