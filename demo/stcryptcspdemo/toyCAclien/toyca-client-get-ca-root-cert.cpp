//================================================================================================================================================
// FILE: toyca-client-get-ca-root-cert.cpp
// (c) GIE 2010-04-03  15:09
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "toyca-client-get-ca-root-cert.hpp"

#include "../common/misc/stcrypt-qt-exception-guards.hpp"
#include "../common/toycert/stcrypt-toycert-signature-verifier.hpp"
#include "../toyCA/toycert-cmds.hpp"

#include "boost/date_time/posix_time/ptime.hpp"
#include "boost/enable_shared_from_this.hpp"
#include "boost/iostreams/stream.hpp"
#include "boost/iostreams/device/back_inserter.hpp"
//================================================================================================================================================
namespace stcrypt { namespace  caclient {


	namespace impl {

		struct get_ca_root_certificate_state_t 
			: client_session_i
			, boost::enable_shared_from_this<get_ca_root_certificate_state_t>
		{
			typedef std::vector<char> buffer_type;
			enum state_t {s_init, s_connected, s_requested_ca, s_got_ca_blob_size, s_got_ca_blob, s_done};

			get_ca_root_certificate_state_t(worker_t& parent)
				: m_parent( parent )
				, m_state( s_init )
				, m_ca_socket(parent.io_service())
				, m_timer(parent.io_service())
			{}

			~get_ca_root_certificate_state_t(){}


			void run(boost::system::error_code const& error);
			void invoke_error_handler(boost::system::error_code const& error);
			void invoke_error_handler(std::string const& msg);
			void restart();

			virtual void initialize_run(){
				m_parent.io_service().post( boost::bind(&get_ca_root_certificate_state_t::run, this->shared_from_this(), boost::system::error_code() ) );
			}

			void handle_ca_root_certificate_blob_();
			
			boost::asio::ip::tcp::endpoint	m_ca_endpoint;
			boost::asio::ip::tcp::socket	m_ca_socket;
			buffer_type						m_buffer;
			worker_t&	m_parent;
			state_t		m_state;
			worker_t::event__get_ca_root_certificate_type	m_callback;
			worker_t::event__error_type					    m_error_callback;
			boost::asio::deadline_timer						m_timer;
		};

		bool ca_cert_verify_proxy(stcrypt::toycert_t& cert, char const * const data, size_t const size, oid::oid_type const& sign_alg_oid,  toycert_t::signature_blob_t const& signature){
			return ca::verify_signature_via_csp(data, size,signature, cert);
		}

		void get_ca_root_certificate_state_t::handle_ca_root_certificate_blob_(){
			boost::shared_ptr<stcrypt::toycert_t> ca_root_cert( new stcrypt::toycert_t() );

			{
				std::vector<char> const& cert_blob = m_buffer;

				boost::iostreams::basic_array_source<char> source(&cert_blob[0],cert_blob.size());
				boost::iostreams::stream<boost::iostreams::basic_array_source <char> > input_stream(source);

				if( ca_root_cert->x509_load(input_stream, boost::bind(&ca_cert_verify_proxy, boost::ref(*ca_root_cert), _1, _2, _3, _4) ) ){
					m_callback(ca_root_cert, cert_blob, true);
				} else {
					m_callback(ca_root_cert, cert_blob, false);
				}
			}

		}


		void get_ca_root_certificate_state_t::invoke_error_handler(boost::system::error_code const& error){
			assert( error );
			if(m_error_callback)
				m_error_callback(error, boost::none);
		}
		void get_ca_root_certificate_state_t::invoke_error_handler(std::string const& msg){
			if(m_error_callback)
				m_error_callback(boost::none, msg);
		}

		void get_ca_root_certificate_state_t::restart(){
			m_ca_socket.close();
			m_timer.expires_from_now(boost::posix_time::seconds(30));
			m_state=s_init;
			m_timer.async_wait( boost::bind(&get_ca_root_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
		}


		void get_ca_root_certificate_state_t::run(boost::system::error_code const& error){
			STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_BEGIN			

			switch(m_state){
				case s_init: {
					if(error) return invoke_error_handler(error);

					m_state=s_connected;
					m_ca_socket.async_connect(m_ca_endpoint, boost::bind(&get_ca_root_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error));
					return;

				} case s_connected: {
					if(error) {
						restart();
						return invoke_error_handler(error);
					} else {
						m_buffer.clear();
						{
							boost::iostreams::stream<boost::iostreams::back_insert_device<buffer_type> > cmd_blob_stream(m_buffer);
							ca::cmd::type const cmd = ca::cmd::request_ca_root_certificate;
							
							cmd_blob_stream.write(reinterpret_cast<char const*>(&cmd), sizeof(cmd));
							cmd_blob_stream.flush();
							if(cmd_blob_stream.bad())
								STCRYPT_UNEXPECTED();
						}
						m_state = s_requested_ca;
						m_ca_socket.async_send(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&get_ca_root_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );

					} return;
				} case s_requested_ca: {
					if(error) {
						restart();
						return invoke_error_handler(error);
					} else {
						m_buffer.resize( sizeof(ca::cmd::packet_size_t) );
						m_state = s_got_ca_blob_size;
						m_ca_socket.async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&get_ca_root_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					} return;
				} case s_got_ca_blob_size: {
					if(error) {
						restart();
						return invoke_error_handler(error);
					} else {
						if(m_buffer.size()!=sizeof(ca::cmd::packet_size_t)) STCRYPT_UNEXPECTED();
						ca::cmd::packet_size_t packet_size;
						memcpy(&packet_size, &m_buffer[0], sizeof(packet_size));
						if(packet_size==0) STCRYPT_UNEXPECTED();
						if(packet_size>ca::cmd::max_packet_size) STCRYPT_UNEXPECTED();
						m_buffer.resize(packet_size);

						m_state = s_got_ca_blob;
						m_ca_socket.async_receive(boost::asio::buffer(m_buffer, m_buffer.size()), boost::bind(&get_ca_root_certificate_state_t::run, this->shared_from_this(),  boost::asio::placeholders::error) );
					} return;
				} case s_got_ca_blob: {
					if(error) {
						restart();
						return invoke_error_handler(error);
					} else {
						m_state = s_done;
						return handle_ca_root_certificate_blob_();
					} return;
				} default: {
					STCRYPT_UNEXPECTED();
				}
			} // end switch

			STCRYPT_CLIEN_STATE_HANDLER_E_GUARD_END
		}

	} // namespace impl

	client_session_ptr create_session__get_ca_root_certificate(worker_t& parent, boost::asio::ip::tcp::endpoint const& ca_endpoint, worker_t::event__get_ca_root_certificate_type	const & callback, worker_t::event__error_type const& error_callback){
		boost::shared_ptr<impl::get_ca_root_certificate_state_t> session( new impl::get_ca_root_certificate_state_t(parent) );
		session->m_ca_endpoint = ca_endpoint;
		session->m_callback = callback;
		session->m_error_callback = error_callback;

		return session;
	}

} }
//================================================================================================================================================
