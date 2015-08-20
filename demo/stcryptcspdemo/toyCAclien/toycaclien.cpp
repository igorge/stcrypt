#include "stdafx.h"

#include "toycaclien.h"

#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-crypto-alg-ids.h"
#include "../../../stcrypt/trunk/stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../common/toycert/stcrypt-toycert-signature-verifier.hpp"

#include "boost/format.hpp"
#include "boost/assign.hpp"
#include "boost/iostreams/stream.hpp"

void toyCAclien::async_on_ca_connect_error(boost::optional<boost::system::error_code const&> const& error, boost::optional<std::string const&> const& msg){
	std::string err_msg("[ca-get-root-cert]");
	if(error){
		err_msg+="[";
		err_msg+=error->message();
		err_msg+="]";
	}
	if(msg){
		err_msg+="[";
		err_msg+=*msg;
		err_msg+="]";
	}

	QApplication::postEvent(this,new function_event_t( boost::bind(&toyCAclien::on_ca_connect_error, this, QString::fromStdString( err_msg ))  ));

}

void toyCAclien::print_log_msg(QString const& msg){
	ui.log_edit->appendPlainText(msg);
}

void toyCAclien::on_ca_connect_error(QString const& msg){
	this->print_log_msg(msg);

}

void toyCAclien::post_log_message(QString const& msg){
	std::auto_ptr<function_event_t> async_event( new function_event_t(boost::bind(&toyCAclien::print_log_msg, this, msg) ) );
	QApplication::postEvent( this, async_event.release());
}

void toyCAclien::post_log_message2(std::string const& msg){
	post_log_message(QString::fromStdString(msg) );

}

void toyCAclien::async_on_error(boost::optional<boost::system::error_code const&> const& error, boost::optional<std::string const&> const& srt_msg){
	std::string msg("[async]");
	if(error){
		msg.append("[").append(error->message()).append("]");
	}
	if(srt_msg){
		msg.append("[").append(*srt_msg).append("]");
	}

	post_log_message(QString::fromStdString(msg));

}


void toyCAclien::async_on_ca_got_root_certificate( boost::shared_ptr< stcrypt::toycert_t> const& ca_root_cert, std::vector<char> const& cert_blob, bool signaure_status){
	m_client_db.store_ca_root_certificate_blob(cert_blob);

	QApplication::postEvent(this,new function_event_t( boost::bind(&toyCAclien::print_log_msg, this, QString( "[saved CA root certificate]" ))  ));
	QApplication::postEvent(this,new function_event_t( boost::bind(&toyCAclien::set_ca_root_certificate, this, ca_root_cert)  ));
	
}

void toyCAclien::cleanup_cert_request(){
	using namespace stcrypt;

	ca::cert_store_t::certificate_id_t cert_request_id;
	std::vector<char> session_key_blob;
	std::wstring csp_container_name;

	m_client_db.load_certificate_request(cert_request_id, session_key_blob, csp_container_name);
	HCRYPTPROV prov = 0;
	STCRYPT_CHECK_MSCRYPTO( CryptAcquireContext(&prov, csp_container_name.c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, CRYPT_DELETEKEYSET) );
	m_client_db.delete_certificate_request();
	ui.request_cert_group->setEnabled(true);

	post_log_message("certificate signing aborted.");
}

void toyCAclien::async_on_cert_request_completition( boost::shared_ptr< stcrypt::toycert_t> const& signed_ca_root_cert ) {
	if( !signed_ca_root_cert ){ // failed or rejected 
		QApplication::postEvent(this,new function_event_t( boost::bind(&toyCAclien::cleanup_cert_request, this)  ));
	} else {
		QApplication::postEvent(this,new function_event_t( boost::bind(&toyCAclien::set_new_self_certificate, this, signed_ca_root_cert)  ));
	}
}

void toyCAclien::set_new_self_certificate(boost::shared_ptr<stcrypt::toycert_t> const& self_cert){
	m_self_certificate = self_cert;
}



void toyCAclien::initiate_ca_root_cert_retrival(){
	try {
		if(m_ca_root_certificate){
			print_log_msg("[already have CA root certificate, aborting]");
		} else {
			m_worker.async_get_ca_root_certificate(
				boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string( ui.ca_ip_edit->text().toStdString() ), 9090), 
				boost::bind(&toyCAclien::async_on_ca_got_root_certificate, this, _1, _2, _3),
				boost::bind(&toyCAclien::async_on_ca_connect_error, this, _1, _2) );

			ui.get_ca_root_cert_button->setEnabled(false);
		}
	} catch(boost::exception const& e){
		print_log_msg( QString::fromStdString( boost::diagnostic_information(e) ) );
	}
}

void toyCAclien::initiate_send(){

	m_worker.send_text_to_peer(
		ui.peer_message_edit->toPlainText().toStdString(),
		boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string( ui.peer_ip_edit->text().toStdString() ), ui.peer_port_edit->text().toUInt()),
		m_self_certificate,
		m_client_db.get_keyset_name(),
		m_ca_root_certificate,
		boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string( ui.ca_ip_edit->text().toStdString() ), 9090),
		boost::bind(&toyCAclien::post_log_message2, this, _1));


}
void toyCAclien::initiate_listen(){
	
	m_worker.start_accept(
		m_self_certificate,
		m_client_db.get_keyset_name(),
		m_ca_root_certificate,
		boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string( ui.ca_ip_edit->text().toStdString() ), 9090),
		ui.listen_port_edit->text().toUInt(),
		boost::bind(&toyCAclien::post_log_message2, this, _1));

}

void toyCAclien::initiate_cert_signing(){
	using boost::assign::operator+=;

	if(!m_ca_root_certificate){
		print_log_msg("No CA certificate found.");
		return;
	}

	#define STCRYPT_TOYCA_CP_NAME(x) cert->subject().set_##x( ui. x##_edit->text().toStdString() ); \
		cert->issuer().set_##x("undefined");

	try {

		ui.request_cert_group->setEnabled(false);

		boost::shared_ptr<stcrypt::toycert_t> cert( new stcrypt::toycert_t() );

		STCRYPT_TOYCA_CP_NAME(common_name);
		STCRYPT_TOYCA_CP_NAME(country_name);
		STCRYPT_TOYCA_CP_NAME(locality_name);
		STCRYPT_TOYCA_CP_NAME(organization_name);
		STCRYPT_TOYCA_CP_NAME(organization_unit_name);
		STCRYPT_TOYCA_CP_NAME(state_or_province_name);

		boost::posix_time::ptime const not_before_time = boost::posix_time::second_clock::universal_time();
		boost::posix_time::ptime const not_after_time = ( not_before_time + boost::gregorian::days(7) ); 
		cert->validity().set(not_before_time, not_after_time);

		stcrypt::oid::oid_type pub_key_oid;				//TODO: any random oid
		pub_key_oid+=1,2,840,113549,1,1,2;
		std::vector<char> pub_key_blob;
		pub_key_blob+=0,0,0;
		cert->set_public_key_blob(pub_key_blob, pub_key_oid);


		m_worker.async_request_sign_certificate(
			boost::ref(m_client_db),
			m_ca_root_certificate,
			cert,
			boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string( ui.ca_ip_edit->text().toStdString() ), 9090),
			boost::bind(&toyCAclien::async_on_cert_request_completition, this, _1),
			boost::bind(&toyCAclien::async_on_error, this, _1, _2) );

	} catch(boost::exception const& e){
		print_log_msg( QString::fromStdString( boost::diagnostic_information(e) ) );
	}

	#undef STCRYPT_TOYCA_CP_NAME
}



toyCAclien::toyCAclien(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
	, m_client_db(0)
{
	ui.setupUi(this);

	{bool const r = connect(ui.get_ca_root_cert_button, SIGNAL(clicked()), this, SLOT(initiate_ca_root_cert_retrival())); assert(r);}
	{bool const r = connect(ui.request_cert_button, SIGNAL(clicked()), this, SLOT(initiate_cert_signing())); assert(r);}
	{bool const r = connect(ui.listen_button, SIGNAL(clicked()), this, SLOT(initiate_listen())); assert(r);}
	{bool const r = connect(ui.send_button, SIGNAL(clicked()), this, SLOT(initiate_send())); assert(r);}

	m_ca_root_certificate = m_client_db.load_ca_root_certificate();
	if(m_ca_root_certificate){
		ui.get_ca_root_cert_button->setEnabled(false);
		print_log_msg("[already have CA root certificate]");
	}

	m_worker.run();

	{
		using namespace stcrypt;

		
		
		try{
			std::vector<char> const& self_cert_blob = m_client_db.load_self_certificate_blob();

			boost::iostreams::basic_array_source<char> source(&self_cert_blob[0],self_cert_blob.size());
			boost::iostreams::stream<boost::iostreams::basic_array_source <char> > input_stream(source);

			struct toyCAclien__signature_verifier { static bool run(toycert_t& pub_key_from_cert, char const * const data, size_t const size, oid::oid_type const& sign_alg_oid,  toycert_t::signature_blob_t const& signature) {
				return stcrypt::ca::verify_signature_via_csp(data, size, signature, pub_key_from_cert);
			} };

			m_self_certificate.reset(new toycert_t() );
			boost::shared_ptr<toycert_t>& cert( m_self_certificate );

			if( !cert->x509_load(input_stream, boost::bind(&toyCAclien__signature_verifier::run, boost::ref(*m_ca_root_certificate),_1,_2,_3,_4)) ){
				print_log_msg("[loaded self certificate, signature failed.]");
			} else {
				print_log_msg("[loaded self certificate, signature ok.]");
			}
			ui.request_cert_group->setEnabled(false);

		}catch(stcrypt::caclient::exception::self_certificate_not_found const&){

			ca::cert_store_t::certificate_id_t cert_request_id;
			std::vector<char> session_key_blob;
			std::wstring csp_container_name;
			do{
				try{ 
					m_client_db.load_certificate_request(cert_request_id, session_key_blob, csp_container_name); }
				catch(caclient::exception::certificate_request_not_found const&){
					break;
				}
				print_log_msg("[already requested CA for certificate, resuming response polling]");
				m_worker.async_resume_request_sign_certificate(
					cert_request_id, 
					session_key_blob, 
					csp_container_name,
					boost::ref(m_client_db),
					m_ca_root_certificate,
					boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string( ui.ca_ip_edit->text().toStdString() ), 9090),
					boost::bind(&toyCAclien::async_on_cert_request_completition, this, _1),
					boost::bind(&toyCAclien::async_on_error, this, _1, _2) );

				ui.request_cert_group->setEnabled(false);

			} while(false);

		}// end catch

	}

}

void toyCAclien::set_ca_root_certificate(boost::shared_ptr< stcrypt::toycert_t> const& cert){
	m_ca_root_certificate = cert;
}

toyCAclien::~toyCAclien()
{

}
