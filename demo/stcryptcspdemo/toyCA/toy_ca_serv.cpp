//================================================================================================================================================
// FILE: toy_ca_serv.cpp
// (c) GIE 2010-03-29  18:03
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "toy_ca_serv.hpp"
#include "toycert-cmds.hpp"
#include "../common/misc/stcrypt-qt-exception-guards.hpp"
#include "../common/toycert/stcrypt-toycert-signature-verifier.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-crypto-alg-ids.h"

#include "boost/shared_ptr.hpp"
#include "boost/enable_shared_from_this.hpp"
#include "boost/iostreams/stream.hpp"
#include "boost/iostreams/device/back_inserter.hpp"
#include "boost/scope_exit.hpp"
//================================================================================================================================================
namespace stcrypt{

	namespace asio = boost::asio;

	typedef ca::cmd::packet_size_t packet_size_t;
	size_t const max_packet_size=64*1024;

	toy_ca_serv_t::toy_ca_serv_t(ca::db_serv_ptr_t	const& db, error_fun_type const& error_fun, event_certificate_request_type	const & on_cert_request_complete)
		: m_error_fun( error_fun )
		, m_db( db )
		, m_on_cert_request_complete( on_cert_request_complete )
	{
		run();
	}

	toy_ca_serv_t::~toy_ca_serv_t(){
		m_listen_thread.interrupt();
		m_io_service.stop();
		m_listen_thread.join();

	}


	void toy_ca_serv_t::run(){
		m_listen_thread = boost::thread( boost::bind( &toy_ca_serv_t::do_run_, this) ).move();

	}

	void toy_ca_serv_t::invoke_error_handler(boost::system::error_code const& error){
		if(m_error_fun)
			m_error_fun(error, boost::none);

	}
	void toy_ca_serv_t::invoke_error_handler(std::string const& msg){
		if(m_error_fun)
			m_error_fun(boost::none, msg);

	}


	struct toy_ca_serv_session_t 
		: boost::enable_shared_from_this<toy_ca_serv_session_t>
	{
		toy_ca_serv_session_t(toy_ca_serv_t& parent)
			: m_parent( parent )
		{}

		void read_packet_stage_2(const boost::system::error_code& error, std::size_t bytes_transferred  );
		void read_packet_stage_1(const boost::system::error_code& error, std::size_t bytes_transferred  );

		void invoke_error_handler(boost::system::error_code const& error);
		void invoke_error_handler(std::string const& msg);

		void handle_ca_request_();

		struct req_cert_sign_state_t {
			enum state_t {rcs_init, rcs_got_key_sizem, rcs_got_key, rcs_got_cert_request_size, rcs_got_cert_request, s_sent_reply, s_done};
			std::vector<char>	m_enc_session_key;
			std::vector<char>	m_enc_cert_request;
			
			ca::cert_store_t::certificate_id_t	m_req_serial;


			state_t m_state;
		};
		typedef boost::shared_ptr<req_cert_sign_state_t> req_cert_sign_state_ptr;

		struct cert_sign_polling_state_t {
			enum state_t {s_init, s_got_session_key_size, s_got_session_key, s_got_packet_size, s_got_request_packet, s_sent_reply, s_done};
			
			stcrypt::cryptprov_ptr_t m_cprov;
			stcrypt::cryptkey_ptr_t m_temp_session_key;
			stcrypt::cryptkey_ptr_t m_session_key;

			
			ca::cert_store_t::certificate_id_t	m_req_serial;
			state_t	m_state;

		};
		typedef boost::shared_ptr<cert_sign_polling_state_t> cert_sign_polling_state_ptr_t;

		struct request_cert_and_status_state_t {
			enum state_t {s_init, s_got_session_key_size, s_got_session_key, s_got_cert_serial, s_sent_reply, s_done};

			stcrypt::cryptprov_ptr_t m_cprov;
			stcrypt::cryptkey_ptr_t  m_temp_session_key;
			stcrypt::cryptkey_ptr_t  m_session_key;


			ca::cert_store_t::certificate_id_t	m_req_serial;
			state_t	m_state;
		};
		typedef boost::shared_ptr<request_cert_and_status_state_t> request_cert_and_status_state_ptr_t;


		void process_certificate_request_(req_cert_sign_state_ptr const & state);
		void process_certificate_request_polling_(cert_sign_polling_state_ptr_t const & state);

		void handle_certificate_request_polling_(cert_sign_polling_state_ptr_t const& state,  boost::system::error_code const& error);
		void handle_request_certificate_signing_(req_cert_sign_state_ptr const state, boost::system::error_code const& error);
		void handle_request_cert_and_status_state_(request_cert_and_status_state_ptr_t const& state, boost::system::error_code const& error);

		void sent_ca_root_cert_(const boost::system::error_code& error);

		socket_ptr		  m_socket;
		std::vector<char> m_buffer;

		toy_ca_serv_t&	  m_parent;
	};

	typedef boost::shared_ptr<toy_ca_serv_session_t> toy_ca_serv_session_ptr;

	void toy_ca_serv_session_t::invoke_error_handler(boost::system::error_code const& error){
		return m_parent.invoke_error_handler(error);
	}
	void toy_ca_serv_session_t::invoke_error_handler(std::string const& msg){
		return m_parent.invoke_error_handler(msg);
	}

	void toy_ca_serv_session_t::sent_ca_root_cert_(const boost::system::error_code& error){
		if(error){
			return invoke_error_handler(error);
		}

		invoke_error_handler("successfully sent ca root certificate");
	}

	void toy_ca_serv_session_t::process_certificate_request_polling_(cert_sign_polling_state_ptr_t const & state){
		state->m_req_serial = ca::decrypt_final_pod<ca::cert_store_t::certificate_id_t>( *(state->m_temp_session_key), m_buffer );

		ca::db_serv_t::request_info_type const& request_info = m_parent.m_db->load_request_by_serial(state->m_req_serial);

		ca::cert_request_store_t::cert_request_status_t const& status = request_info.get<1>();
		std::vector<char> const& session_key_blob =  *request_info.get<2>();

		if( !state->m_session_key ){
			state->m_session_key = stcrypt::wrap_cryptkey_ptr( ca::import_key(*(state->m_cprov), session_key_blob) );
		}

		if(status.m_request_status==ca::cert_request_store_t::reques_status_pending){

			m_buffer = ca::encrypt_final_pod<ca::cmd::type>(*(state->m_session_key), ca::cmd::response_certificate_signing_status_pending);
			
			state->m_state = cert_sign_polling_state_t::s_done;
			m_socket->async_send( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_certificate_request_polling_, this->shared_from_this(), state, boost::asio::placeholders::error));

		} else if(status.m_request_status==ca::cert_request_store_t::reques_status_rejected){

			m_buffer = ca::encrypt_final_pod<ca::cmd::type>(*(state->m_session_key), ca::cmd::response_certificate_signing_status_rejected);

			state->m_state = cert_sign_polling_state_t::s_done;
			m_socket->async_send( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_certificate_request_polling_, this->shared_from_this(), state, boost::asio::placeholders::error));
		} else if(status.m_request_status==ca::cert_request_store_t::reques_status_approved){
			m_buffer = ca::encrypt_final_pod<ca::cmd::type>(*(state->m_session_key), ca::cmd::response_certificate_signing_status_signed_data_follows);

			ca::cert_store_t::certificate_id_t const approved_cert_serial = m_parent.m_db->load_approved_request_cert_serial( state->m_req_serial );
			std::vector<char> cert_blob = m_parent.m_db->load_certificate_blob_by_serial(approved_cert_serial);

			ca::append_buffer( m_buffer, ca::encrypt_final_pod<ca::cmd::packet_size_t>(*(state->m_session_key), cert_blob.size()) );
			ca::inplace_encrypt_buffer_final( *(state->m_session_key), cert_blob );
			ca::append_buffer(m_buffer, cert_blob);

			state->m_state = cert_sign_polling_state_t::s_done;
			m_socket->async_send( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_certificate_request_polling_, this->shared_from_this(), state, boost::asio::placeholders::error));


		} else STCRYPT_UNEXPECTED();
	}

	void toy_ca_serv_session_t::handle_request_cert_and_status_state_(request_cert_and_status_state_ptr_t const& state, boost::system::error_code const& error){
		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_BEGIN

		assert(state);
		switch(state->m_state){
			case request_cert_and_status_state_t::s_init: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					m_buffer.resize( sizeof(ca::cmd::packet_size_t));
					state->m_state = request_cert_and_status_state_t::s_got_session_key_size;
					m_socket->async_receive( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_request_cert_and_status_state_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case request_cert_and_status_state_t::s_got_session_key_size: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					m_buffer.resize( ca::to_pod<ca::cmd::packet_size_t>(m_buffer) );
					state->m_state = request_cert_and_status_state_t::s_got_session_key;
					m_socket->async_receive( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_request_cert_and_status_state_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case request_cert_and_status_state_t::s_got_session_key: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					state->m_cprov = create_cryptprov_ptr(m_parent.m_db->get_ca_private_key_container_name().c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, 0);
					state->m_session_key = stcrypt::wrap_cryptkey_ptr( ca::import_key(*(state->m_cprov), m_buffer) );
					
					m_buffer.resize( sizeof(stcrypt::toycert_t::serial_number_type));
					state->m_state = request_cert_and_status_state_t::s_got_cert_serial;
					m_socket->async_receive( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_request_cert_and_status_state_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case request_cert_and_status_state_t::s_got_cert_serial: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					stcrypt::toycert_t::serial_number_type const cert_serial = ca::decrypt_final_pod<stcrypt::toycert_t::serial_number_type>(state->m_session_key,m_buffer);

					try{
						std::vector<char> const& cert_blob = m_parent.m_db->load_certificate_blob_by_serial(cert_serial);
						ca::cmd::type const response_cmd = m_parent.m_db->get_revoked_status(cert_serial) ? ca::cmd::response_cert_and_status_revoked : ca::cmd::response_cert_and_status_valid;
						std::vector<char> response_buff  ;//= ca::encrypt_final_pod<ca::cmd::type>( state->m_session_key, response_cmd );
						ca::append_pod<ca::cmd::type>(response_buff,  response_cmd );
						ca::append_pod<ca::cmd::packet_size_t>(response_buff, cert_blob.size());
						ca::append_buffer(response_buff, cert_blob);
						ca::inplace_encrypt_buffer_final(state->m_session_key, response_buff);

						//m_buffer.clear();
						m_buffer = ca::encrypt_final_pod<ca::cmd::packet_size_t>(state->m_session_key, response_buff.size());
						//ca::append_pod<ca::cmd::packet_size_t>(m_buffer, response_buff.size());
						ca::append_buffer(m_buffer, response_buff);

						state->m_state = request_cert_and_status_state_t::s_done;
						m_socket->async_send( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_request_cert_and_status_state_, this->shared_from_this(), state, boost::asio::placeholders::error));

					} catch (ca::exception::cert_not_fount_e const&){
						m_buffer = ca::encrypt_final_pod<ca::cmd::type>(state->m_session_key, ca::cmd::response_cert_and_status_not_found );
						state->m_state = request_cert_and_status_state_t::s_done;
						m_socket->async_send( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_request_cert_and_status_state_, this->shared_from_this(), state, boost::asio::placeholders::error));
						break;
					}

				} break;
			} case request_cert_and_status_state_t::s_done: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
				} break;
			} default: {
				STCRYPT_UNEXPECTED();
			}
		}



		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_END
	}


	void toy_ca_serv_session_t::handle_certificate_request_polling_(cert_sign_polling_state_ptr_t const& state,  boost::system::error_code const& error){
		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_BEGIN

		assert(state);
		switch(state->m_state){
			case cert_sign_polling_state_t::s_init: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					m_buffer.resize( sizeof(ca::cmd::packet_size_t));
					state->m_state = cert_sign_polling_state_t::s_got_session_key_size;
					m_socket->async_receive( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_certificate_request_polling_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case cert_sign_polling_state_t::s_got_packet_size: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					ca::cmd::packet_size_t const size = ca::to_pod<ca::cmd::packet_size_t>(m_buffer);
					m_buffer.resize(size);
					state->m_state = cert_sign_polling_state_t::s_got_request_packet;
					m_socket->async_receive( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_certificate_request_polling_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case cert_sign_polling_state_t::s_got_session_key_size: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					m_buffer.resize( ca::to_pod<ca::cmd::packet_size_t>(m_buffer) );
					state->m_state = cert_sign_polling_state_t::s_got_session_key;
					m_socket->async_receive( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_certificate_request_polling_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case cert_sign_polling_state_t::s_got_session_key: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					state->m_cprov = create_cryptprov_ptr(m_parent.m_db->get_ca_private_key_container_name().c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, 0);
					state->m_temp_session_key = stcrypt::wrap_cryptkey_ptr( ca::import_key(*(state->m_cprov), m_buffer) );
					
					m_buffer.resize( sizeof(ca::cmd::packet_size_t));
					state->m_state = cert_sign_polling_state_t::s_got_packet_size;
					m_socket->async_receive( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_certificate_request_polling_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case cert_sign_polling_state_t::s_got_request_packet: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					//state->m_req_serial = ca::to_pod<ca::cert_store_t::certificate_id_t>(m_buffer);
					process_certificate_request_polling_(state);
				} break;
			} case cert_sign_polling_state_t::s_done: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
				} break;
			} default: {
				STCRYPT_UNEXPECTED();
			}
		}

		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_END

	}

	void toy_ca_serv_session_t::process_certificate_request_( req_cert_sign_state_ptr const & state )
	{

		std::vector<char> const& enc_request_blob = state->m_enc_cert_request;
		std::vector<char> const& session_key_blob = state->m_enc_session_key;

		stcrypt::cryptprov_ptr_t cprov = create_cryptprov_ptr(m_parent.m_db->get_ca_private_key_container_name().c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, 0);

		HCRYPTKEY const session_key = ca::import_key(*cprov, session_key_blob);
		BOOST_SCOPE_EXIT( (session_key) ){
			if( CryptDestroyKey(session_key)==0 ){ assert(false); };
		}BOOST_SCOPE_EXIT_END

		std::vector<char> cert_requst_blob(enc_request_blob);

		DWORD cert_requst_blob_size = cert_requst_blob.size();
		STCRYPT_CHECK_MSCRYPTO( CryptDecrypt(session_key, 0, TRUE, 0, reinterpret_cast<BYTE*>( &cert_requst_blob[0] ), &cert_requst_blob_size) );

		state->m_req_serial = m_parent.m_db->store_new_request_blob( cert_requst_blob, session_key_blob );


		{
			ca::cert_store_t::certificate_id_t & req_serial = state->m_req_serial;

			std::vector<char>& response = m_buffer;

			std::vector<char> encrypted_response;
			encrypted_response.resize(sizeof(req_serial));

			memcpy(&encrypted_response[0], &req_serial, sizeof(req_serial));
			DWORD data_len = encrypted_response.size();
			STCRYPT_CHECK_MSCRYPTO( CryptEncrypt(session_key, 0, TRUE, 0, reinterpret_cast<BYTE*>( &encrypted_response[0] ), &data_len, encrypted_response.size()) );
			if(data_len!=encrypted_response.size()) STCRYPT_UNEXPECTED();

			ca::cmd::packet_size_t const response_size = encrypted_response.size();
			response.reserve(encrypted_response.size() + sizeof(response_size));
			response.resize(sizeof(response_size));
			memcpy(&response[0], &response_size, sizeof(response_size));
			response.insert(response.end(), encrypted_response.begin(), encrypted_response.end());

			state->m_state = req_cert_sign_state_t::s_sent_reply;
			m_socket->async_send( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_request_certificate_signing_, this->shared_from_this(), state, boost::asio::placeholders::error));
		}

	}

	void toy_ca_serv_session_t::handle_request_certificate_signing_(req_cert_sign_state_ptr const state, boost::system::error_code const& error){
		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_BEGIN

		assert(state);
		switch(state->m_state){
			case req_cert_sign_state_t::rcs_init: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					m_buffer.resize( sizeof(ca::cmd::packet_size_t));
					state->m_state = req_cert_sign_state_t::rcs_got_key_sizem;
					m_socket->async_receive( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_request_certificate_signing_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case req_cert_sign_state_t::rcs_got_key_sizem: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					ca::cmd::packet_size_t encrypted_session_key_size;
					if(sizeof(encrypted_session_key_size)!=m_buffer.size()) STCRYPT_UNEXPECTED();
					memcpy(&encrypted_session_key_size, &m_buffer[0],  sizeof(encrypted_session_key_size) );

					if(encrypted_session_key_size==0)STCRYPT_UNEXPECTED();
					state->m_enc_session_key.resize(encrypted_session_key_size);

					state->m_state = req_cert_sign_state_t::rcs_got_key;
					m_socket->async_receive( boost::asio::buffer(state->m_enc_session_key, state->m_enc_session_key.size()), boost::bind(&toy_ca_serv_session_t::handle_request_certificate_signing_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case req_cert_sign_state_t::rcs_got_key: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					m_buffer.resize( sizeof(ca::cmd::packet_size_t));
					state->m_state = req_cert_sign_state_t::rcs_got_cert_request_size;
					m_socket->async_receive( boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::handle_request_certificate_signing_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case req_cert_sign_state_t::rcs_got_cert_request_size: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					ca::cmd::packet_size_t encrypted_request_size;
					if(sizeof(encrypted_request_size)!=m_buffer.size()) STCRYPT_UNEXPECTED();
					memcpy(&encrypted_request_size, &m_buffer[0],  sizeof(encrypted_request_size) );

					if(encrypted_request_size==0)STCRYPT_UNEXPECTED();
					state->m_enc_cert_request.resize(encrypted_request_size);

					state->m_state = req_cert_sign_state_t::rcs_got_cert_request;
					m_socket->async_receive( boost::asio::buffer(state->m_enc_cert_request, state->m_enc_cert_request.size()), boost::bind(&toy_ca_serv_session_t::handle_request_certificate_signing_, this->shared_from_this(), state, boost::asio::placeholders::error));
				} break;
			} case req_cert_sign_state_t::rcs_got_cert_request: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					process_certificate_request_(state);
				} break;
			} case req_cert_sign_state_t::s_sent_reply: {
				if(error){
					STCRYPT_UNEXPECTED();
				} else {
					state->m_state = req_cert_sign_state_t::s_done;
					m_parent.m_on_cert_request_complete(state->m_req_serial);
				} break;
			}  default: {
				STCRYPT_UNEXPECTED();
			}
		}

		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_END
	}

	void toy_ca_serv_session_t::handle_ca_request_(){
		m_buffer.clear();
		std::vector<char> cert_blob;
		m_parent.m_db->get_root_cert_blob(cert_blob);
		if(cert_blob.size()==0) STCRYPT_UNEXPECTED();
		{
			boost::iostreams::stream<boost::iostreams::back_insert_device<std::vector<char> > > cmd_blob_stream(m_buffer);
			ca::cmd::packet_size_t packet_size = cert_blob.size();
			cmd_blob_stream.write(reinterpret_cast<char const*>(&packet_size), sizeof(packet_size) );
			cmd_blob_stream.write(&cert_blob[0],cert_blob.size() );
			cmd_blob_stream.flush();
			if(cmd_blob_stream.bad()) STCRYPT_UNEXPECTED();
		}

		m_socket->async_send(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toy_ca_serv_session_t::sent_ca_root_cert_, this->shared_from_this(),  boost::asio::placeholders::error));
		
	}

	void toy_ca_serv_session_t::read_packet_stage_2(const boost::system::error_code& error, std::size_t bytes_transferred  ){
		if(error){
			assert(false);
			return;
		}


	}

	void toy_ca_serv_session_t::read_packet_stage_1(const boost::system::error_code& error, std::size_t bytes_transferred  ){
		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_BEGIN

			if(!error){
			ca::cmd::type cmd;
			if(sizeof(cmd)!=this->m_buffer.size()){
				assert(false);
				return;
			}

			memcpy(&cmd, &this->m_buffer[0], sizeof(cmd));

			switch(cmd){
				case ca::cmd::request_ca_root_certificate:{
					return handle_ca_request_();
				} case ca::cmd::request_certificate_signing:{
					req_cert_sign_state_ptr state(new req_cert_sign_state_t );
					state->m_state = req_cert_sign_state_t::rcs_init;
					return handle_request_certificate_signing_( state, boost::system::error_code() );
				} case ca::cmd::certificate_signing_status:{
					cert_sign_polling_state_ptr_t state ( new cert_sign_polling_state_t );
					state->m_state = cert_sign_polling_state_t::s_init;
					return handle_certificate_request_polling_( state, boost::system::error_code() );
				} case ca::cmd::request_cert_and_status:{
					request_cert_and_status_state_ptr_t state ( new request_cert_and_status_state_t );
					state->m_state = request_cert_and_status_state_t::s_init;
					return handle_request_cert_and_status_state_( state, boost::system::error_code() );
				} default: {
					assert(false);
				}
			}

			boost::asio::async_read(*(this->m_socket), boost::asio::buffer(this->m_buffer), boost::bind(&toy_ca_serv_session_t::read_packet_stage_2, this->shared_from_this(), _1, _2));

		} else {
			invoke_error_handler( error );
		}

		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_END
	}


	void toy_ca_serv_t::do_accept_client_(socket_ptr const socket, const boost::system::error_code& error, asio::ip::tcp::acceptor& acceptor){
		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_BEGIN
			try{

		if( !error ) {

			toy_ca_serv_session_ptr session( new toy_ca_serv_session_ptr::value_type(*this) );
			session->m_socket = socket;
			session->m_buffer.resize(sizeof(ca::cmd::type));

			boost::asio::async_read(*(session->m_socket), boost::asio::buffer(session->m_buffer), boost::bind(&toy_ca_serv_session_t::read_packet_stage_1, session, _1, _2));


			start_async_accept_(acceptor);
		} else {
			invoke_error_handler( error );
		}
			} catch(stcrypt::exception::root const& e){
				invoke_error_handler( boost::diagnostic_information(e) );
			}

		STCRYPT_VOID_ASYNC_HANDLER_EGUARD_END

	}

	void toy_ca_serv_t::start_async_accept_(asio::ip::tcp::acceptor& acceptor){

		socket_ptr socket( new socket_ptr::value_type( m_io_service ) );
		acceptor.async_accept(*socket, boost::bind(&toy_ca_serv_t::do_accept_client_, this, socket, boost::asio::placeholders::error, boost::ref(acceptor)) );

	}

	void toy_ca_serv_t::do_run_(){
		try {

				asio::ip::tcp::acceptor acceptor(m_io_service, asio::ip::tcp::endpoint(asio::ip::tcp::v4(), 9090));

				start_async_accept_(acceptor);
				std::size_t const num_of_handlres = m_io_service.run();


		}catch(...){
			assert(false);
		}

	}



}
//================================================================================================================================================
