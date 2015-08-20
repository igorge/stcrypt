//================================================================================================================================================
// FILE: toyca-client-p2p.cpp
// (c) GIE 2010-04-18  14:29
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "toyca-client-p2p.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-crypto-alg-ids.h"

#include "../common/misc/stcrypt-qt-exception-guards.hpp"
#include "../common/toycert/stcrypt-toycert-signature-verifier.hpp"
#include "../toyCA/toycert-cmds.hpp"
#include "toycert-db.hpp"

#include "boost/iostreams/stream.hpp"
#include "boost/make_shared.hpp"
#include "boost/date_time/posix_time/ptime.hpp"
#include "boost/enable_shared_from_this.hpp"
#include "boost/iostreams/stream.hpp"
#include "boost/iostreams/device/back_inserter.hpp"
//================================================================================================================================================
namespace stcrypt { namespace  caclient {

	namespace impl {

		struct request_certificate_state_t 
			: client_session_i
			, boost::enable_shared_from_this<request_certificate_state_t>
		{
			typedef std::vector<char> buffer_type;
			typedef boost::function<void( boost::shared_ptr<toycert_t> const& cert, ca::cmd::type const cert_state)> event_peer_cert_loaded_t;

			enum state_t {s_init, s_connected, s_requested_cert, s_sent_serial, s_sent_session_key, s_got_enc_packet_size,  s_got_enc_packet, s_done};


			

			boost::asio::ip::tcp::endpoint	m_ca_endpoint;
			boost::asio::ip::tcp::socket	m_ca_socket;

			state_t		m_state;
			std::vector<char>	m_buffer;

			event_peer_cert_loaded_t	m_done_callback;

			stcrypt::cryptprov_ptr_t	m_cprov;
			stcrypt::cryptkey_ptr_t		m_session_key;

			worker_t&	m_parent;
			toycert_t::serial_number_type const m_cert_serial_to_fetch;
			boost::shared_ptr<toycert_t> const m_ca_cert;

			request_certificate_state_t(worker_t& parent, boost::shared_ptr<toycert_t> const ca_cert, boost::asio::ip::tcp::endpoint const& ca_endpoint, toycert_t::serial_number_type const cert_serial_to_fetch, event_peer_cert_loaded_t const& done_event)
				: m_cert_serial_to_fetch( cert_serial_to_fetch )
				, m_parent( parent )
				, m_done_callback( done_event )
				, m_ca_socket( parent.io_service() )
				, m_ca_endpoint( ca_endpoint )
				, m_ca_cert( ca_cert )
				, m_state(s_init)
			{}
			

			virtual void initialize_run(){
				m_parent.io_service().post( boost::bind(&request_certificate_state_t::run, this->shared_from_this(), boost::system::error_code() ) );
			}
			void run(boost::system::error_code const& error);
			void invoke_error_handler(std::string const& error){
				STCRYPT_UNIMPLEMENTED();
			}
			void invoke_error_handler(boost::system::error_code const& error){
				STCRYPT_UNIMPLEMENTED();
			}
		};



		void request_certificate_state_t::run(boost::system::error_code const& error){
			STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_BEGIN			
				if(error) return invoke_error_handler(error);

			switch(m_state){
				case s_init: {
					if(error) return invoke_error_handler(error);

					m_state=s_connected;
					m_ca_socket.async_connect(m_ca_endpoint, boost::bind(&request_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error));
					break;
				} case s_connected: {
					if(error) return invoke_error_handler(error);

					m_cprov = create_cryptprov_ptr(NULL, STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, CRYPT_VERIFYCONTEXT);
					m_session_key = generate_cryptkey_ptr(*m_cprov,CALG_ID_G28147_89_GAMMA_CBC,CRYPT_EXPORTABLE);


					m_buffer.clear();
					ca::append_pod<ca::cmd::type>(m_buffer, ca::cmd::request_cert_and_status);
					std::vector<char> session_key_blob;
					ca::export_key(m_cprov, m_session_key, *m_ca_cert, session_key_blob);
					ca::append_pod<ca::cmd::packet_size_t>(m_buffer, session_key_blob.size());
					ca::append_buffer(m_buffer, session_key_blob);

					m_state = s_sent_session_key;
					m_ca_socket.async_send(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					break;
				} case s_sent_session_key: {
					m_buffer = ca::encrypt_final_pod<toycert_t::serial_number_type>(m_session_key, m_cert_serial_to_fetch);

					m_state = s_sent_serial;
					m_ca_socket.async_send(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					break;
				} case s_sent_serial: {
					if(error) return invoke_error_handler(error);

					m_buffer.resize( sizeof(ca::cmd::packet_size_t) );

					m_state = s_got_enc_packet_size;
					m_ca_socket.async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					break;
				} case s_got_enc_packet_size: {
					ca::cmd::packet_size_t const enc_packet_size = ca::decrypt_final_pod<ca::cmd::packet_size_t>(m_session_key, m_buffer);
					m_buffer.resize( enc_packet_size  );

					m_state = s_got_enc_packet;
					m_ca_socket.async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					break;
				} case s_got_enc_packet: {
					ca::inplace_decrypt_buffer_final(m_session_key, m_buffer);

					boost::iostreams::basic_array_source<char> source(&m_buffer[0],m_buffer.size());
					boost::iostreams::stream<boost::iostreams::basic_array_source <char> > input_stream(source);


					ca::cmd::type response;
					input_stream.read(reinterpret_cast<char*>(&response), sizeof(response));
					if( input_stream.bad() )
						STCRYPT_UNEXPECTED1("bad CA response");

					boost::shared_ptr<toycert_t> cert;

					switch(response){
						  case ca::cmd::response_cert_and_status_not_found_pending: {
							m_done_callback(cert, ca::cmd::response_cert_and_status_not_found_pending);
							break;
						} case ca::cmd::response_cert_and_status_revoked: {
							m_done_callback(cert, ca::cmd::response_cert_and_status_revoked);
							break;
						} case ca::cmd::response_cert_and_status_not_found: {
							m_done_callback(cert, ca::cmd::response_cert_and_status_not_found);
							break;
						} case ca::cmd::response_cert_and_status_valid: {

							ca::cmd::packet_size_t cert_blob_size;
							input_stream.read(reinterpret_cast<char*>(&cert_blob_size), sizeof(cert_blob_size));
							if( input_stream.bad() )
								STCRYPT_UNEXPECTED1("bad CA response");

							cert = boost::make_shared<toycert_t>();
							bool const is_valid = cert->x509_load(input_stream, boost::bind(&ca::verify_signature_via_csp, _1, _2, _4, boost::ref(*m_ca_cert)));
							if(!is_valid) STCRYPT_UNEXPECTED1("session with valid CA key, but cert signed with other");

							m_done_callback(cert, ca::cmd::response_cert_and_status_valid);
							break;
						} default : {
							STCRYPT_UNEXPECTED1("invalid CA response");
						}
					} // end switch
					
					m_state = s_done;
					break;
				} default: {
					STCRYPT_UNEXPECTED1("unknown FSM state");
				}
			} // end switch

			STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_END
		}

	} // ns impl








	namespace impl {

		struct term_session_e{};

		struct toyca_client_client_server_t 
			: client_session_i
			, boost::enable_shared_from_this<toyca_client_client_server_t >
		{
			typedef std::vector<char> buffer_type;
			typedef boost::function<void( boost::shared_ptr<toycert_t> const& cert, ca::cmd::type const cert_state)> event_peer_cert_loaded_t;

			enum state_t {
				s_c_init, s_c_connected, s_c_got_peer_serial, s_c_got_peer_cert, s_c_sent_message,
				s_s_init, s_s_connected, s_s_sent_self_serial, s_s_got_session_key_size, s_s_got_session_key, s_s_got_got_enc_message_size, s_s_got_enc_message,
				s_done, s_external};


			std::string m_message_to_send;

			boost::asio::ip::tcp::acceptor	 m_acceptor;

			boost::asio::ip::tcp::endpoint	   m_ca_endpoint;
			boost::shared_ptr<toycert_t> const m_ca_cert;
			boost::asio::ip::tcp::socket 	   m_ca_socket;

			boost::asio::ip::tcp::endpoint	   m_peer_endpoint;
			boost::shared_ptr<boost::asio::ip::tcp::socket>	   m_peer_socket;

			boost::shared_ptr<toycert_t> const m_self_cert;
			std::wstring				 const m_self_keyset_container_name;

			ca::cmd::type					m_peer_state;
			boost::shared_ptr<toycert_t>	m_peer_cert;

			state_t		m_state;
			std::vector<char>	m_buffer;

			event_peer_cert_loaded_t	m_done_callback;

			stcrypt::cryptprov_ptr_t	m_cprov;
			stcrypt::cryptkey_ptr_t		m_session_key;

			boost::function<void(std::string const&)> const m_print_msg;

			worker_t&	m_parent;

			void run(boost::system::error_code const& error);

			toyca_client_client_server_t(
				worker_t& parent, 
				boost::shared_ptr<toycert_t> const& self_cert,
				std::wstring const& self_keyset_container_name,
				boost::shared_ptr<toycert_t> const& ca_cert, 
				boost::asio::ip::tcp::endpoint const& ca_endpoint, 
				boost::asio::ip::tcp::endpoint const& peer_endpoint, 
				boost::function<void(std::string const&)> const& print_msg)

				: m_parent( parent )
				, m_ca_socket( parent.io_service() )
				, m_ca_endpoint( ca_endpoint )
				, m_peer_endpoint( peer_endpoint )
				, m_ca_cert( ca_cert )
				, m_print_msg(print_msg)
				, m_self_cert( self_cert )
				, m_self_keyset_container_name( self_keyset_container_name )
				, m_acceptor( parent.io_service() )
			{}

			void print(std::string const& msg){
				if(!m_print_msg) STCRYPT_UNEXPECTED1("print callbacl not defined");

				m_print_msg(msg);
			}

			void invoke_error_handler(std::string const& error){
				print(error);
				throw term_session_e();
			}
			void invoke_error_handler(boost::system::error_code const& error){
				print(error.message());
				throw term_session_e();
			}

			void got_peer_cert( boost::shared_ptr<toycert_t> const& cert, ca::cmd::type const cert_state){
				if(m_state!=s_external) STCRYPT_UNEXPECTED();

				m_peer_cert = cert;
				m_peer_state = cert_state;

				m_state = s_c_got_peer_cert;

				this->run(boost::system::error_code());
			}

			virtual void initialize_run(){
				m_parent.io_service().post( boost::bind(&toyca_client_client_server_t::run, this->shared_from_this(), boost::system::error_code() ));
			}


		};


		void toyca_client_client_server_t::run(boost::system::error_code const& error){
			STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_BEGIN	
				try {

			if(error) return invoke_error_handler(error);

			switch(m_state){
				case s_s_init: {
					m_state = s_s_connected;
					this->run( error );
					break;

				} case s_s_connected: {
					m_buffer.clear();
					ca::append_pod<toycert_t::serial_number_type>(m_buffer, m_self_cert->get_serial());
					m_state = s_s_sent_self_serial;
					m_peer_socket->async_send(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toyca_client_client_server_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					break;

				} case s_s_sent_self_serial: {
					m_buffer.resize( sizeof(ca::cmd::packet_size_t) );
					m_state = s_s_got_session_key_size;
					m_peer_socket->async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toyca_client_client_server_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					break;

				} case s_s_got_session_key_size: {
					m_buffer.resize( ca::to_pod<ca::cmd::packet_size_t>( m_buffer) );
					m_state = s_s_got_session_key;
					m_peer_socket->async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toyca_client_client_server_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					break;

				} case s_s_got_session_key: {
					m_cprov = create_cryptprov_ptr(m_self_keyset_container_name.c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, 0);
					m_session_key = wrap_cryptkey_ptr( ca::import_key(*m_cprov, m_buffer) );

					m_buffer.resize( sizeof(ca::cmd::packet_size_t) );
					m_state = s_s_got_got_enc_message_size;
					m_peer_socket->async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toyca_client_client_server_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					break;

				} case s_s_got_got_enc_message_size: {
					m_buffer.resize( ca::to_pod<ca::cmd::packet_size_t>( m_buffer) );
					m_state = s_s_got_enc_message;
					m_peer_socket->async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toyca_client_client_server_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					break;

				} case s_s_got_enc_message: {

					ca::inplace_decrypt_buffer_final(m_session_key, m_buffer);
					print("got message:");
					print( std::string(&m_buffer[0], m_buffer.size()) );
					m_state =  s_done;
					break;


				} case s_c_init: {
					if(error) return invoke_error_handler(error);

					m_peer_socket.reset(new boost::asio::ip::tcp::socket(m_parent.io_service() ) );
					m_state=s_c_connected;
					m_peer_socket->async_connect(m_peer_endpoint, boost::bind(&toyca_client_client_server_t::run, this->shared_from_this(),  boost::asio::placeholders::error));
					break;

				} case s_c_connected: {

					m_buffer.resize( sizeof(toycert_t::serial_number_type) );
					m_state = s_c_got_peer_serial;
					m_peer_socket->async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toyca_client_client_server_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					break;
					
				} case s_c_got_peer_serial: {
					toycert_t::serial_number_type const peer_cert_serial = ca::to_pod<toycert_t::serial_number_type>(m_buffer);
					boost::shared_ptr<request_certificate_state_t> peer_cert_requestor(
						new request_certificate_state_t(m_parent, m_ca_cert, m_ca_endpoint, peer_cert_serial, boost::bind(&toyca_client_client_server_t::got_peer_cert, this->shared_from_this(), _1,_2)));

					m_state = s_external;
					m_parent.io_service().post( boost::bind(&request_certificate_state_t::run, peer_cert_requestor, boost::system::error_code()) );
					break;

				} case s_c_got_peer_cert: {
					if(m_peer_state!=ca::cmd::response_cert_and_status_valid){
						print("peer certificate is invalid");
						m_state = s_done;
						break;
					} else {
						print("got peers certificate from CA, status: valid.");
						
						m_buffer.clear();
						
						m_cprov = create_cryptprov_ptr(0, STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, CRYPT_VERIFYCONTEXT);
						cryptkey_ptr_t const session_key = generate_cryptkey_ptr(*m_cprov,CALG_ID_G28147_89_GAMMA_CBC,CRYPT_EXPORTABLE);

						std::vector<char> encrypted_message;
						
						std::vector<char> session_key_blob;
						ca::export_key(m_cprov, session_key, *m_peer_cert, session_key_blob);

						ca::append_pod<ca::cmd::packet_size_t>(m_buffer, session_key_blob.size());
						ca::append_buffer(m_buffer, session_key_blob);

						if(m_message_to_send.empty()) m_message_to_send = "<empty message>";
						std::copy(m_message_to_send.begin(), m_message_to_send.end(), std::back_inserter(encrypted_message));

						ca::inplace_encrypt_buffer_final(session_key, encrypted_message);

						ca::append_pod<ca::cmd::packet_size_t>(m_buffer, encrypted_message.size());
						ca::append_buffer(m_buffer, encrypted_message);

						m_peer_socket->async_send(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&toyca_client_client_server_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

						m_state = s_done;
						break;
					}
				} case s_done : {
					break;

				} default: {
					STCRYPT_UNEXPECTED1("unknown FSM state");
				}
			} // end switch

			} catch(term_session_e const&){
				m_state = s_done;
			}

			STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_END
		}

	} // ns impl


	boost::shared_ptr<client_session_i> new_listen_session(
		worker_t& parent, 
		boost::shared_ptr<boost::asio::ip::tcp::socket> const & socket,
		boost::shared_ptr<toycert_t> const& self_cert,
		std::wstring const& self_keyset_container_name,
		boost::shared_ptr<toycert_t> const& ca_cert, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		boost::function<void(std::string const&)> const& print_msg){

			boost::shared_ptr<impl::toyca_client_client_server_t> tmp (new impl::toyca_client_client_server_t(parent, self_cert, self_keyset_container_name, ca_cert, ca_endpoint, 
				boost::asio::ip::tcp::endpoint(), // do not need peer endpoint for server
				print_msg));

			tmp->m_state =  impl::toyca_client_client_server_t::s_s_init;
			tmp->m_peer_socket =  socket;

			return tmp;
	}


	boost::shared_ptr<client_session_i> new_send_text_session(
		worker_t& parent, 
		std::string const& message,
		boost::asio::ip::tcp::endpoint const& peer_endpoint,
		boost::shared_ptr<toycert_t> const& self_cert,
		std::wstring const& self_keyset_container_name,
		boost::shared_ptr<toycert_t> const& ca_cert, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		boost::function<void(std::string const&)> const& print_msg){

			boost::shared_ptr<impl::toyca_client_client_server_t> tmp (new impl::toyca_client_client_server_t(parent, self_cert, self_keyset_container_name, ca_cert, ca_endpoint, 
				peer_endpoint,
				print_msg));

			tmp->m_state =  impl::toyca_client_client_server_t::s_c_init;
			tmp->m_message_to_send = message;

			return tmp;
	}


} }
//================================================================================================================================================
