//================================================================================================================================================
// FILE: toyca-client-request-cert-sign.cpp
// (c) GIE 2010-04-03  22:42
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "toyca-client-request-cert-sign.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-crypto-alg-ids.h"

#include "../common/misc/stcrypt-qt-exception-guards.hpp"
#include "../common/toycert/stcrypt-toycert-signature-verifier.hpp"
#include "../toyCA/toycert-cmds.hpp"
#include "toycert-db.hpp"

#include "boost/date_time/posix_time/ptime.hpp"
#include "boost/enable_shared_from_this.hpp"
#include "boost/iostreams/stream.hpp"
#include "boost/iostreams/device/back_inserter.hpp"
#include "boost/assign.hpp"
#include "boost/uuid/uuid.hpp"
#include "boost/uuid/uuid_generators.hpp"
#include "boost/uuid/uuid_io.hpp"
#include "boost/random.hpp"
//================================================================================================================================================
namespace stcrypt { namespace  caclient {


	namespace impl {

		struct request_sign_certificate_state_t 
			: client_session_i
			, boost::enable_shared_from_this<request_sign_certificate_state_t>
		{
			typedef std::vector<char> buffer_type;
			enum state_t {s_init, s_connected, s_requested_cert, s_got_response_size, s_got_response, 
				s_cert_polling_init, s_cert_polling_connected, s_cert_polling_sent_request, s_cert_polling_got_response_size, s_cert_polling_got_response, 
				s_resume_cert_polling, 
				s_got_cert_size, s_got_cert, s_done};

			request_sign_certificate_state_t(worker_t& parent, caclient::db_t& db)
				: m_parent( parent )
				, m_state( s_init )
				, m_ca_socket(parent.io_service())
				, m_timer(parent.io_service())
				, m_db( db )
			{}

			~request_sign_certificate_state_t(){}

			void resume_request();


			void run(boost::system::error_code const& error);
			void invoke_error_handler(boost::system::error_code const& error);
			void invoke_error_handler(std::string const& msg);
			void log_message(std::string const& msg);
			//void restart();

			virtual void initialize_run(){
				m_parent.io_service().post( boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(), boost::system::error_code() ) );
			}

			void prepare_cert_to_sign_packet_(std::ostream& out_stream);
			void decrypt_req_cert_response_();
			void handle_request_approved();

			boost::shared_ptr<stcrypt::toycert_t> m_cert_to_sign;
			boost::shared_ptr<stcrypt::toycert_t> m_ca_cert;

			boost::asio::ip::tcp::endpoint	m_ca_endpoint;
			boost::asio::ip::tcp::socket	m_ca_socket;
			buffer_type						m_buffer;
			worker_t&	m_parent;
			state_t		m_state;
			worker_t::event__got_self_cert	m_callback;
			worker_t::event__error_type					    m_error_callback;
			boost::asio::deadline_timer						m_timer;

			ca::cert_store_t::certificate_id_t m_request_id;
			std::wstring					   m_crypto_container_id;
			stcrypt::cryptprov_ptr_t	cprov;
			stcrypt::cryptkey_ptr_t		session_key;
			boost::optional< std::vector<char> > m_session_key_blob;
			stcrypt::cryptkey_ptr_t		m_self_keypair;
			caclient::db_t&			    m_db;

		};



		void request_sign_certificate_state_t::invoke_error_handler(boost::system::error_code const& error){
			assert( error );
			if(m_error_callback)
				m_error_callback(error, boost::none);
		}
		void request_sign_certificate_state_t::invoke_error_handler(std::string const& msg){
			if(m_error_callback)
				m_error_callback(boost::none, msg);
		}

		void request_sign_certificate_state_t::log_message(std::string const& msg){
			invoke_error_handler(msg); //TODO
		}

		void dummy_sign_func(char const * const data, size_t const size, toycert_t::signature_blob_t& signature){
			using boost::assign::operator+=;

			signature.clear();
			signature+=0xB,0xA,0xD,0xF,0,0,0xD;

		}

		void request_sign_certificate_state_t::prepare_cert_to_sign_packet_(std::ostream& out_stream){

			{
				boost::uuids::basic_random_generator<boost::mt19937> gen;
				boost::uuids::uuid crypto_container_id = gen();
				std::wostringstream crypto_container_id_as_string_sonverter;
				crypto_container_id_as_string_sonverter << crypto_container_id;
				m_crypto_container_id = crypto_container_id_as_string_sonverter.str();
			}

			std::vector<char> public_key_blob;
			{
				cprov = create_cryptprov_ptr(m_crypto_container_id.c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, CRYPT_NEWKEYSET);
				m_self_keypair = generate_cryptkey_ptr(*cprov, AT_SIGNATURE /*CALG_DSTU4145_SIGN*/, 0);
				export_key_as_public_blob(*m_self_keypair, public_key_blob);

			}


			buffer_type cert_blob;
			{
				using boost::assign::operator+=;
				boost::iostreams::stream<boost::iostreams::back_insert_device<buffer_type> > cert_blob_stream(cert_blob);

				oid::oid_type sign_oid;				//TODO: any random oid
				sign_oid+=1,2,840,113549,1,1,2;

				m_cert_to_sign->set_public_key_blob(public_key_blob, sign_oid);

				m_cert_to_sign->x509_save(cert_blob_stream, sign_oid, dummy_sign_func);
				cert_blob_stream.flush();
				if(cert_blob_stream.bad()) STCRYPT_UNEXPECTED();
			}

			session_key = generate_cryptkey_ptr(*cprov,CALG_ID_G28147_89_GAMMA_CBC,CRYPT_EXPORTABLE);

			std::vector<char> exported_session_key;
			if(!m_ca_cert ) STCRYPT_UNEXPECTED();
			ca::export_key(*cprov, *session_key, *m_ca_cert, exported_session_key);
			
			ca::cmd::packet_size_t packet_size = exported_session_key.size();

			out_stream.write(reinterpret_cast<char const*>( &packet_size ), sizeof(packet_size));
			out_stream.write(&exported_session_key[0], exported_session_key.size());

			size_t const data_size = cert_blob.size();
			DWORD data_len_and_out_buff_size = data_size;
			STCRYPT_CHECK_MSCRYPTO( CryptEncrypt(*session_key, 0, TRUE, 0, 0, &data_len_and_out_buff_size, cert_blob.size()) );
			if(data_len_and_out_buff_size < cert_blob.size()) STCRYPT_UNEXPECTED();
			cert_blob.resize(data_len_and_out_buff_size);
			data_len_and_out_buff_size = data_size;
			STCRYPT_CHECK_MSCRYPTO( CryptEncrypt(*session_key, 0, TRUE, 0, reinterpret_cast<BYTE*>( &cert_blob[0] ), &data_len_and_out_buff_size, cert_blob.size()) );

			packet_size = cert_blob.size();
			out_stream.write(reinterpret_cast<char const*>( &packet_size ), sizeof(packet_size));
			out_stream.write(&cert_blob[0], cert_blob.size());

		}

		void request_sign_certificate_state_t::decrypt_req_cert_response_(){
			DWORD decrypted_size = m_buffer.size();
			STCRYPT_CHECK_MSCRYPTO( CryptDecrypt(*session_key, 0, TRUE, 0, reinterpret_cast<BYTE*>( &m_buffer[0] ), &decrypted_size ) );
			if(decrypted_size!=m_buffer.size()) STCRYPT_UNEXPECTED();
			
			if(m_buffer.size()!=sizeof(m_request_id)) STCRYPT_UNEXPECTED();

			memcpy(&m_request_id, &m_buffer[0], sizeof(m_request_id));

			std::vector<char> self_encrypted_session_key;
			export_key_as_simple_blob(*session_key, *m_self_keypair, self_encrypted_session_key);

			m_db.store_certificate_request(m_request_id, self_encrypted_session_key, m_crypto_container_id);

		}

		void request_sign_certificate_state_t::handle_request_approved(){
			m_db.store_self_certificate_blob(m_buffer);
			m_db.store_keyset_name(m_crypto_container_id);

			boost::iostreams::basic_array_source<char> source(&m_buffer[0],m_buffer.size());
			boost::iostreams::stream<boost::iostreams::basic_array_source <char> > input_stream(source);

			struct req_sign_cert_state__signature_verifier { static bool run(toycert_t& pub_key_from_cert, char const * const data, size_t const size, oid::oid_type const& sign_alg_oid,  toycert_t::signature_blob_t const& signature) {
				return ca::verify_signature_via_csp(data, size, signature, pub_key_from_cert);
			} };

			boost::shared_ptr<toycert_t> cert( new toycert_t() );
			if( !cert->x509_load(input_stream, boost::bind(&req_sign_cert_state__signature_verifier::run, boost::ref(*m_ca_cert),_1,_2,_3,_4)) ){
				invoke_error_handler("self certificate signature failure.");
				m_state = s_done;
			} else {
				log_message("got self certificate, signature ok.");
				m_callback(cert);
				m_state = s_done;
			}


		}

		void request_sign_certificate_state_t::resume_request(){
			if(!m_session_key_blob) STCRYPT_UNEXPECTED();

			cprov = create_cryptprov_ptr(m_crypto_container_id.c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, 0);

			m_self_keypair = get_user_cryptkey_ptr(*cprov, AT_SIGNATURE);
		
			session_key = import_cryptkey_ptr(*cprov, &(*m_session_key_blob)[0], m_session_key_blob->size(), *m_self_keypair, 0);

			m_parent.io_service().post(	boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::system::error_code()) );

		}

		void request_sign_certificate_state_t::run(boost::system::error_code const& error){
			STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_BEGIN			

			switch(m_state){
				case s_init: {
					if(error) return invoke_error_handler(error);

					m_state=s_connected;
					m_ca_socket.async_connect(m_ca_endpoint, boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error));
					return;
				} case s_connected: {
					if(error) {
						return invoke_error_handler(error);
					} else {
						m_buffer.clear();
						{
							boost::iostreams::stream<boost::iostreams::back_insert_device<buffer_type> > cmd_blob_stream(m_buffer);
							ca::cmd::type const cmd = ca::cmd::request_certificate_signing;

							cmd_blob_stream.write(reinterpret_cast<char const*>(&cmd), sizeof(cmd));
							prepare_cert_to_sign_packet_(cmd_blob_stream);
							cmd_blob_stream.flush();
							if(cmd_blob_stream.bad())
								STCRYPT_UNEXPECTED();
						}
						m_state = s_requested_cert;
						m_ca_socket.async_send(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					} return;
				} case s_requested_cert: {
					if(error) return invoke_error_handler(error);

					m_buffer.resize(sizeof( ca::cmd::packet_size_t) );

					m_state=s_got_response_size;
					m_ca_socket.async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					return;
				} case s_got_response_size: {
					if(error) return invoke_error_handler(error);
					ca::cmd::packet_size_t response_size;
					
					if( m_buffer.size()!=sizeof(response_size) ) STCRYPT_UNEXPECTED();
					memcpy(&response_size, &m_buffer[0], sizeof(response_size));
					if(response_size>ca::cmd::max_packet_size) STCRYPT_UNEXPECTED();

					m_buffer.resize(response_size);
					m_state=s_got_response;
					m_ca_socket.async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					return;
				} case s_got_response: {
					if(error) return invoke_error_handler(error);

					decrypt_req_cert_response_();
					m_timer.expires_from_now( boost::posix_time::seconds(30) );
					m_state = s_cert_polling_init;
					m_ca_socket.close();
					m_timer.async_wait( boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					return;
				} case s_resume_cert_polling: {
					if(error) return invoke_error_handler(error);

					m_state=s_cert_polling_init;
					resume_request();

					return;
				} case s_cert_polling_init: {
					if(error) return invoke_error_handler(error);

					m_state=s_cert_polling_connected;
					m_ca_socket.async_connect(m_ca_endpoint, boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error));

					return;
				} case s_cert_polling_connected: {
					if(error) return invoke_error_handler(error);

					m_buffer.clear();

					//cmd
					ca::append_pod(m_buffer, ca::cmd::certificate_signing_status);
					
					//key
					cryptkey_ptr_t const tmp_session_key = generate_cryptkey_ptr(*cprov,CALG_ID_G28147_89_GAMMA_CBC,CRYPT_EXPORTABLE);
					std::vector<char> tmp_session_key_blob;
					ca::export_key(*cprov, *tmp_session_key, *m_ca_cert,tmp_session_key_blob);
					ca::append_pod<ca::cmd::packet_size_t>(m_buffer, tmp_session_key_blob.size());
					m_buffer.insert(m_buffer.end(), tmp_session_key_blob.begin(), tmp_session_key_blob.end());

					
					//cert id
					std::vector<char> const& enc_message = ca::encrypt_final_pod(*tmp_session_key, m_request_id);;
					ca::append_pod<ca::cmd::packet_size_t>(m_buffer, enc_message.size());
					m_buffer.insert(m_buffer.end(), enc_message.begin(), enc_message.end());

					m_state = s_cert_polling_sent_request;
					m_ca_socket.async_send(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					return;
				} case s_cert_polling_sent_request: {
					if(error) return invoke_error_handler(error);

					m_buffer.resize( sizeof(ca::cmd::type) );
					m_state = s_cert_polling_got_response;
					m_ca_socket.async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					return;
				} case s_cert_polling_got_response: {
					if(error) return invoke_error_handler(error);
					
					ca::cmd::type const response = ca::decrypt_final_pod<ca::cmd::type>(*session_key, m_buffer);
					if(response==ca::cmd::response_certificate_signing_status_pending){

						m_state=s_cert_polling_init;
						m_ca_socket.close();

						invoke_error_handler("certificate status: pending, will check again in 30s.");
						m_timer.expires_from_now(boost::posix_time::seconds(30));
						m_timer.async_wait( boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					} else if(response==ca::cmd::response_certificate_signing_status_rejected){
						m_callback( boost::shared_ptr<toycert_t>());
					} else if(response==ca::cmd::response_certificate_signing_status_signed_data_follows){
						m_buffer.resize(sizeof(ca::cmd::packet_size_t) );

						m_state = s_got_cert_size;
						m_ca_socket.async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					} else 
						STCRYPT_UNEXPECTED1("unknown response cmd");
					return;

				} case s_got_cert_size: {
					if(error) return invoke_error_handler(error);
					
					ca::cmd::packet_size_t const cert_blob_size = ca::decrypt_final_pod<ca::cmd::packet_size_t>(*session_key, m_buffer);
					m_buffer.resize(cert_blob_size);

					m_state = s_got_cert;
					m_ca_socket.async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&request_sign_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					return;
				} case s_got_cert: {
					ca::inplace_decrypt_buffer_final(*session_key, m_buffer);

					handle_request_approved();

					return ;
				} default: {
					STCRYPT_UNEXPECTED1("unknown FSM state");
				}
			} // end switch

			STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_END
		}

	} // ns impl


	stcrypt::caclient::client_session_ptr create_session__request_sign_certificate(	caclient::db_t& db, worker_t& parent, boost::shared_ptr< stcrypt::toycert_t> ca_certificate, boost::shared_ptr< stcrypt::toycert_t> certificate_to_sign, boost::asio::ip::tcp::endpoint const& ca_endpoint, worker_t::event__got_self_cert const & callback, worker_t::event__error_type const& error_callback )
	{

			boost::shared_ptr<impl::request_sign_certificate_state_t> session( new impl::request_sign_certificate_state_t(parent, db) );

			session->m_callback = callback;
			session->m_error_callback = error_callback;
			session->m_ca_endpoint = ca_endpoint;
			session->m_cert_to_sign = certificate_to_sign;
			session->m_ca_cert = ca_certificate;

			return session;
	}

	stcrypt::caclient::client_session_ptr create_session__resume_request_sign_certificate(
		ca::cert_store_t::certificate_id_t const cert_request_id,
		std::vector<char> const& session_key_blob,
		std::wstring const& csp_container_name,

		caclient::db_t& db, 
		worker_t& parent, 
		boost::shared_ptr< stcrypt::toycert_t> ca_certificate, 
		boost::asio::ip::tcp::endpoint const& ca_endpoint, 
		worker_t::event__got_self_cert const & callback, 
		worker_t::event__error_type const& error_callback){

			boost::shared_ptr<impl::request_sign_certificate_state_t> session( new impl::request_sign_certificate_state_t(parent, db) );

			session->m_state = impl::request_sign_certificate_state_t::s_resume_cert_polling;

			session->m_request_id = cert_request_id;
			session->m_crypto_container_id = csp_container_name;
			session->m_session_key_blob = session_key_blob;

			session->m_callback = callback;
			session->m_error_callback = error_callback;
			session->m_ca_endpoint = ca_endpoint;
			//session->m_cert_to_sign = certificate_to_sign;
			session->m_ca_cert = ca_certificate;

			return session;
	}



} }
//================================================================================================================================================
