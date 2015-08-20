#ifndef TOY_CA_T_H
#define TOY_CA_T_H

#include <QtGui/QMainWindow>
#include <qevent.h>

#include "ui_toy_ca_t.h"

#include "toy_ca_serv.hpp"
#include "toy-cert-store-db.hpp"
#include "../common/misc/stcrypt-qt-async-function.hpp"

#include "boost/function.hpp"
#include "boost/shared_ptr.hpp"

struct certificate_list_item_t : QListWidgetItem {

	certificate_list_item_t(stcrypt::ca::cert_store_t::certificate_id_t const cert_id);
	~certificate_list_item_t(){}

	stcrypt::ca::cert_store_t::certificate_id_t serial()const{ return m_serial;}
private:
	stcrypt::ca::cert_store_t::certificate_id_t m_serial;
};

class toy_ca_t : public QMainWindow
{
	Q_OBJECT

public:
	toy_ca_t(QWidget *parent = 0, Qt::WFlags flags = 0);
	~toy_ca_t();

public slots:
	void sign_cert(bool);
	void reject_cert(bool);
	void revoke_cert(bool);
	void cert_selected(QListWidgetItem *);
	void request_selected(QListWidgetItem *);

protected:
	virtual void closeEvent(QCloseEvent * e){
		e->accept();
	}

	STCRYPT_DEF_EVENT_HANDLE(QMainWindow)


private:
	void post_log_message_(std::string const& msg);
	void print_log_msg_(std::string const& msg);
	void async_on_serv_error(boost::optional<boost::system::error_code const&> const&, boost::optional<std::string const&> const&);
	void asyn_on_ca_request_completition(stcrypt::ca::cert_store_t::certificate_id_t const id);
	void on_ca_request_completition(stcrypt::ca::cert_store_t::certificate_id_t const id);

	void handle_enumerate_certificate(stcrypt::ca::cert_store_t::certificate_id_t const cert_id);
	void handle_enumerate_requests(stcrypt::ca::cert_store_t::certificate_id_t const cert_id);
private:
	Ui::toy_ca_tClass ui;
private:
	boost::scoped_ptr<stcrypt::toy_ca_serv_t>	m_ca;
	boost::shared_ptr<stcrypt::ca::db_serv_t>	m_ca_db;
};


#endif // TOY_CA_T_H
