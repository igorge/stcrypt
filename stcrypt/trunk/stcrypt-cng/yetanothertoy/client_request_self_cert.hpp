//================================================================================================================================================
// FILE: client_request_self_cert.h
// (c) GIE 2011-02-03  13:39
//
//================================================================================================================================================
#ifndef H_GUARD_CLIENT_REQUEST_SELF_CERT_2011_02_03_13_39
#define H_GUARD_CLIENT_REQUEST_SELF_CERT_2011_02_03_13_39
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include <QtGui/QWidget>

#include "ms/ms_cert_store_utils.hpp"

#include "qt/qt_def_exception_stubs.hpp"
#include "qt/stcrypt-qt-async-function.hpp"

#include "ui_client_request_self_cert.h"

#include <boost/optional.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>

#include <vector>

#include <QThreadPool>

class client_request_self_cert_t : public QWidget
{
	Q_OBJECT

public slots:

public:
	client_request_self_cert_t(QWidget *parent = 0, Qt::WFlags flags = 0);
	~client_request_self_cert_t();

public slots:
	void request_cert_clicked();

private:
	Ui::client_request_self_cert_t ui;
private:
	void request_cert_sign_( boost::shared_ptr< std::vector<unsigned char> > const& cert_to_be_signed_blob);
	void worker_func_request_cert_sign_(boost::shared_ptr<boost::asio::ip::tcp::iostream> const& stream, boost::shared_ptr< std::vector<unsigned char> > const& cert_to_be_signed_blob);
	void show_async_exception_(boost::exception_ptr const& e);
	void post_show_fatal_exception_(boost::exception_ptr const& e);
	void complete_signed_cert_local_registration_( boost::shared_ptr<ms_cert::pccert_context_t> const& signed_cert_context );
private:
	boost::optional<std::wstring>	m_key_pair_container_name;

	//boost::thread			m_worker_thread;
	QThreadPool				m_workers;

	STCRYPT_DEF_EVENT_HANDLE(QWidget)

};


//================================================================================================================================================
#endif
//================================================================================================================================================
