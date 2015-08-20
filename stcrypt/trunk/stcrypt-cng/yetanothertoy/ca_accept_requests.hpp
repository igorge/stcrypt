	//================================================================================================================================================
// FILE: ca_accept_requests.h
// (c) GIE 2011-02-03  00:39
//
//================================================================================================================================================
#ifndef H_GUARD_CA_ACCEPT_REQUESTS_2011_02_03_00_39
#define H_GUARD_CA_ACCEPT_REQUESTS_2011_02_03_00_39
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "ms/ms_cert_store_utils.hpp"

#include "qt/qt_def_exception_stubs.hpp"
#include "qt/stcrypt-qt-async-function.hpp"

#include "ui_ca_accept_requests_form.h"

#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>
#include <boost/thread.hpp>

#include <QtGui/QWidget>
//================================================================================================================================================
class ca_accept_requests_t;
//================================================================================================================================================
namespace toy_ca {

	struct cert_info_t : boost::noncopyable
	{
		std::wstring subject_name;
		std::wstring issuer_name;

		ms_cert::pccert_context_t	m_cert_ctx;
	};

	boost::shared_ptr<cert_info_t>	cook_cert(ms_cert::pccert_context_t&& cert_ctx);

	template <class T> 
	struct proxy_list_item_t : QListWidgetItem
	{
		proxy_list_item_t(boost::shared_ptr<T> const& item, std::wstring const& display_str) : QListWidgetItem(QString::fromStdWString(display_str)) , m_item( item ) {}

		boost::shared_ptr<T>	m_item;
	};

}
//================================================================================================================================================
class ca_accept_requests_t : public QWidget
{
	Q_OBJECT

	public slots:

public:
	ca_accept_requests_t(ms_cert::pccert_context_t && root_cert, QWidget *parent = 0, Qt::WFlags flags = 0);
	~ca_accept_requests_t();

private:
	Ui::ca_accept_requests_form ui;
private:
	void background_thread_func_();
	void start_async_accept_(boost::asio::ip::tcp::acceptor& acceptor);
	void show_async_exception_(boost::exception_ptr const& e);
	void add_signed_cert( boost::shared_ptr<ms_cert::pccert_context_t> const& cert_ctx);
private:
	boost::asio::io_service m_io_service;
	boost::thread			m_listen_thread;

	boost::shared_ptr<toy_ca::cert_info_t>	m_root_ca_certificate;

	STCRYPT_DEF_EVENT_HANDLE(QWidget)
};

//================================================================================================================================================
#endif
//================================================================================================================================================
