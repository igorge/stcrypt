#include "stdafx.h"
#include "toy_ca_t.h"

#include "boost/function.hpp"
#include "boost/bind.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/util-raii-helpers-crypt.hpp"
#include "../../../stcrypt/trunk/stcrypt-csp/stcrypt-crypto-alg-ids.h"


#include "boost/iostreams/stream.hpp"
#include "boost/iostreams/device/back_inserter.hpp"
#include "boost/assign.hpp"


certificate_list_item_t::certificate_list_item_t(stcrypt::ca::cert_store_t::certificate_id_t const cert_id)
	: QListWidgetItem("serial #" + QString().setNum(cert_id) /*, 0, QListWidgetItem::UserType+100 */)
	, m_serial(cert_id)
{

}

void toy_ca_t::handle_enumerate_certificate(stcrypt::ca::cert_store_t::certificate_id_t const cert_id){
	ui.certificates_list->addItem( new certificate_list_item_t(cert_id) );

}

void toy_ca_t::handle_enumerate_requests(stcrypt::ca::cert_store_t::certificate_id_t const cert_id){
	ui.requests_list->addItem( new certificate_list_item_t(cert_id) );

}

void toy_ca_t::reject_cert(bool){
	certificate_list_item_t* item = dynamic_cast<certificate_list_item_t*>( ui.requests_list->currentItem () );
	if(item) {
		stcrypt::ca::db_serv_t::request_info_type const & request_status = m_ca_db->load_request_by_serial(item->serial());

		if( request_status.get<1>().m_request_status==stcrypt::ca::cert_request_store_t::reques_status_pending){
			m_ca_db->change_request_state(item->serial(), stcrypt::ca::cert_request_store_t::reques_status_rejected);
			this->request_selected(item);
		} else {
			print_log_msg_("unable to change certificate request status");
		}

	}
}


toy_ca_t::toy_ca_t(QWidget *parent, Qt::WFlags flags)
	: QMainWindow(parent, flags)
{
	ui.setupUi(this);

	//QApplication::postEvent(this,new function_event_t());

	{bool const r = connect(ui.sign_button, SIGNAL(clicked(bool)), this, SLOT(sign_cert(bool)));assert(r);}

	{bool const r2 = connect(ui.revoke_button, SIGNAL(clicked(bool)), this, SLOT(revoke_cert(bool)));assert(r2);}
	{bool const r= connect(ui.certificates_list, SIGNAL(itemClicked(QListWidgetItem*)), this, SLOT(cert_selected(QListWidgetItem*)) ); assert(r);	}
	{bool const r= connect(ui.requests_list, SIGNAL(itemClicked(QListWidgetItem*)), this, SLOT(request_selected(QListWidgetItem*)) ); assert(r);	}
	{bool const r= connect(ui.reject_button, SIGNAL(clicked(bool)), this, SLOT(reject_cert(bool)));assert(r);}

	 m_ca_db.reset( new stcrypt::ca::db_serv_t( boost::bind(&toy_ca_t::print_log_msg_, this, _1) ) );
	 m_ca_db->enumerate_certificates( boost::bind(&toy_ca_t::handle_enumerate_certificate, this, _1) );
	 m_ca_db->enumerate_requests( boost::bind(&toy_ca_t::handle_enumerate_requests, this, _1) );

	 m_ca.reset( new stcrypt::toy_ca_serv_t( 
		 m_ca_db, 
		 boost::bind(&toy_ca_t::async_on_serv_error, this, _1, _2) ,
		 boost::bind(&toy_ca_t::asyn_on_ca_request_completition, this, _1 ) ));


}

toy_ca_t::~toy_ca_t()
{

}

void toy_ca_t::asyn_on_ca_request_completition(stcrypt::ca::cert_store_t::certificate_id_t const id){
	std::auto_ptr<function_event_t> async_event( new function_event_t(boost::bind(&toy_ca_t::on_ca_request_completition, this, id) ) );
	QApplication::postEvent( this, async_event.release());
}

void toy_ca_t::on_ca_request_completition(stcrypt::ca::cert_store_t::certificate_id_t const id){
	handle_enumerate_requests(id);
}


void toy_ca_t::cert_selected(QListWidgetItem * elem){

	certificate_list_item_t* item = dynamic_cast<certificate_list_item_t*>(elem);
	if(item){
		boost::shared_ptr<stcrypt::toycert_t> cert;
		stcrypt::ca::cert_status_t cert_status;
		boost::tie(cert, cert_status) =  m_ca_db->load_certificate_by_serial( item->serial(), m_ca_db->get_ca_cert() );
		ui.signature_status_label->setText(QString::fromStdString(
			cert_status.signature_check_as_string()
			+ (m_ca_db->get_revoked_status(item->serial())?",revoked":",trusted by CA" ) ));

		#define STCRYPT_TOYCA_CP_NAME(x)  if(cert->subject().get_##x() ) {ui. x##_edit->setText( QString::fromStdString( * cert->subject().get_##x() ) ); } else {ui. x##_edit->clear();}

		STCRYPT_TOYCA_CP_NAME(common_name);
		STCRYPT_TOYCA_CP_NAME(country_name);
		STCRYPT_TOYCA_CP_NAME(locality_name);
		STCRYPT_TOYCA_CP_NAME(organization_name);
		STCRYPT_TOYCA_CP_NAME(organization_unit_name);
		STCRYPT_TOYCA_CP_NAME(state_or_province_name);

		#undef STCRYPT_TOYCA_CP_NAME

	}
}

void toy_ca_t::request_selected(QListWidgetItem * elem){

	certificate_list_item_t* item = dynamic_cast<certificate_list_item_t*>(elem);
	if(item){
		boost::shared_ptr<stcrypt::toycert_t> cert;
		stcrypt::ca::cert_request_store_t::cert_request_status_t cert_status;
		boost::tie(cert, cert_status, boost::tuples::ignore ) =  m_ca_db->load_request_by_serial( item->serial() );

		ui.signature_status_label->setText(QString::fromStdString(cert_status.request_status_as_string()));

		#define STCRYPT_TOYCA_CP_NAME(x)  if(cert->subject().get_##x() ) {ui. x##_edit->setText( QString::fromStdString( * cert->subject().get_##x() ) ); } else {ui. x##_edit->clear();}

		STCRYPT_TOYCA_CP_NAME(common_name);
		STCRYPT_TOYCA_CP_NAME(country_name);
		STCRYPT_TOYCA_CP_NAME(locality_name);
		STCRYPT_TOYCA_CP_NAME(organization_name);
		STCRYPT_TOYCA_CP_NAME(organization_unit_name);
		STCRYPT_TOYCA_CP_NAME(state_or_province_name);

		#undef STCRYPT_TOYCA_CP_NAME

	}
}


void toy_ca_t::post_log_message_(std::string const& msg){
	std::auto_ptr<function_event_t> async_event( new function_event_t(boost::bind(&toy_ca_t::print_log_msg_, this, msg) ) );
	QApplication::postEvent( this, async_event.release());

}

void toy_ca_t::print_log_msg_(std::string const& msg){
	ui.log_window->appendPlainText( QString::fromStdString(msg) );
}



void toy_ca_t::sign_cert(bool){
	using namespace stcrypt;
	using boost::assign::operator +=;

	try{

	certificate_list_item_t* item = dynamic_cast<certificate_list_item_t*>( ui.requests_list->currentItem () );
	if(item) {
		stcrypt::ca::db_serv_t::request_info_type const & request_status = m_ca_db->load_request_by_serial(item->serial());

		if( request_status.get<1>().m_request_status==stcrypt::ca::cert_request_store_t::reques_status_pending){

			struct name_initer { static void run(stcrypt::toycert_t::issuer_t & n) { //TODO
				n.set_common_name("STCRYPT");
				n.set_country_name("UA");
				n.set_locality_name("Ukraine");
				n.set_organization_name("STCRYPT.ORG");
				n.set_organization_unit_name("STCRYPTCA");
				n.set_state_or_province_name("Kiev");
			}};

			struct blob_signer { static void run(std::pair<stcrypt::cryptprov_ptr_t, stcrypt::cryptkey_ptr_t> const& csp_key, char const * const data, size_t const size, toycert_t::signature_blob_t& signature){
				BOOST_STATIC_ASSERT(sizeof(char)==sizeof(BYTE));

				stcrypt::crypthash_ptr_t hash = create_crypthash_ptr(*csp_key.first, CALG_ID_HASH_G34311, 0/* *csp_key.second */, 0);
				STCRYPT_CHECK_MSCRYPTO( CryptHashData(*hash, reinterpret_cast<BYTE const*>(data), size, 0) );

				DWORD signature_size=0;
				STCRYPT_CHECK_MSCRYPTO( CryptSignHash(*hash, AT_SIGNATURE, 0, 0, 0, &signature_size) );
				signature.resize(signature_size);
				STCRYPT_CHECK_MSCRYPTO( CryptSignHash(*hash, AT_SIGNATURE, 0, 0, reinterpret_cast<BYTE*>( &signature[0] ), &signature_size) );

			}};


			boost::shared_ptr<toycert_t> const& request = request_status.get<0>();
			name_initer::run( request->issuer() );

			ca::cert_store_t::certificate_id_t const cert_serial = m_ca_db->alloc_new_serial();
			request->set_serial( cert_serial );

			std::pair<stcrypt::cryptprov_ptr_t, stcrypt::cryptkey_ptr_t> csp_and_key;
			csp_and_key.first = create_cryptprov_ptr(m_ca_db->get_ca_private_key_container_name().c_str(), STCRYPT_PROVIDER_NAME, STCRYPT_PROVIDER_TYPE, 0);
			csp_and_key.second = get_user_cryptkey_ptr(*(csp_and_key.first), AT_SIGNATURE );


			typedef std::vector<char> buffer_type;
			buffer_type cert_blob;
			cert_blob.reserve(4*1024);

			{
				boost::iostreams::stream<boost::iostreams::back_insert_device<buffer_type> > cert_blob_stream(cert_blob);

				stcrypt::oid::oid_type oid;
				oid+=SCTRYPT_ALG_OID;

				request->x509_save(cert_blob_stream, oid, boost::bind(&blob_signer::run, boost::ref(csp_and_key), _1, _2, _3) );

				cert_blob_stream.flush();
			}

			m_ca_db->store_new_certifictae_blob(cert_serial, cert_blob);
			m_ca_db->store_approved_request_cert_serial( item->serial(), cert_serial);

			m_ca_db->change_request_state(item->serial(), stcrypt::ca::cert_request_store_t::reques_status_approved);
			this->request_selected(item);

			handle_enumerate_certificate(cert_serial);

		} else {
			print_log_msg_("unable to change certificate request status");
		}

	}

	} catch(boost::exception const& e){
		print_log_msg_(  boost::diagnostic_information(e) );
	}


}

void toy_ca_t::async_on_serv_error(boost::optional<boost::system::error_code const&> const& error, boost::optional<std::string const&> const& srt_msg){
	std::string msg("[serv]");
	if(error){
		msg.append("[").append(error->message()).append("]");
	}
	if(srt_msg){
		msg.append("[").append(*srt_msg).append("]");
	}

	post_log_message_(msg);

}

void toy_ca_t::revoke_cert(bool){
	certificate_list_item_t* item = dynamic_cast<certificate_list_item_t*>( ui.certificates_list->currentItem () );
	if(item) {
		m_ca_db->set_revoked_status(item->serial(), true);
		this->cert_selected(item);
	}
}



