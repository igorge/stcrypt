#ifndef TOYCACLIEN_H
#define TOYCACLIEN_H

#include <QtGui/QMainWindow>
#include "ui_toycaclien.h"

#include "toycert-client-db.hpp"
#include "toyca-client-worker.hpp"
#include "../common/misc/stcrypt-qt-async-function.hpp"

#include "boost/optional.hpp"

class toyCAclien : public QMainWindow
{
	Q_OBJECT

public:
	toyCAclien(QWidget *parent = 0, Qt::WFlags flags = 0);
	~toyCAclien();
private:

	void print_log_msg(QString const& msg);
	void post_log_message(QString const& msg);
	void post_log_message2(std::string const& msg);

	void set_ca_root_certificate(boost::shared_ptr< stcrypt::toycert_t> const& cert);

	void on_ca_connect_error(QString const& msg);

	void async_on_ca_connect_error(boost::optional<boost::system::error_code const&> const& error, boost::optional<std::string const&> const& msg);
	void async_on_ca_got_root_certificate( boost::shared_ptr< stcrypt::toycert_t> const& ca_root_cert, std::vector<char> const& cert_blob, bool signaure_status);
	void async_on_error(boost::optional<boost::system::error_code const&> const&, boost::optional<std::string const&> const&);
	void async_on_cert_request_completition( boost::shared_ptr< stcrypt::toycert_t> const& signed_ca_root_cert ) ;

	void cleanup_cert_request();
	void set_new_self_certificate(boost::shared_ptr<stcrypt::toycert_t> const& self_cert);


	STCRYPT_DEF_EVENT_HANDLE(QMainWindow)

private slots:
	void initiate_ca_root_cert_retrival();
	void initiate_cert_signing();
	void initiate_listen();
	void initiate_send();

private:
	stcrypt::caclient::db_t m_client_db;
	stcrypt::caclient::worker_t	m_worker;
	boost::shared_ptr< stcrypt::toycert_t> m_ca_root_certificate;
	boost::shared_ptr< stcrypt::toycert_t> m_self_certificate;
private:
	Ui::toyCAclienClass ui;
};

#endif // TOYCACLIEN_H
