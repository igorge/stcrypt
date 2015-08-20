//================================================================================================================================================
// FILE: client_request_root_or_self_cert.h
// (c) GIE 2011-02-03  13:24
//
//================================================================================================================================================
#ifndef H_GUARD_CLIENT_REQUEST_ROOT_OR_SELF_CERT_2011_02_03_13_24
#define H_GUARD_CLIENT_REQUEST_ROOT_OR_SELF_CERT_2011_02_03_13_24
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include <QtGui/QWidget>

#include "ms/ms_cert_store_utils.hpp"

#include "qt/qt_def_exception_stubs.hpp"
#include "qt/stcrypt-qt-async-function.hpp"

#include "client_request_self_cert_if.hpp"

#include "ui_client_request_root_or_self_cert.h"

#include <boost/thread.hpp>
#include <boost/asio.hpp>
//================================================================================================================================================
class client_request_root_or_selft_cert_t : public QWidget
{
	Q_OBJECT

		public slots:

public:
	client_request_root_or_selft_cert_t(QWidget *parent = 0, Qt::WFlags flags = 0)
		: QWidget(parent, flags)
	{
		ui.setupUi(this);
	}

	~client_request_root_or_selft_cert_t(){
		m_worker_thread.interrupt();
		m_worker_thread.join();
	};


	public slots:
		void request_certificate_clicked(){
			GIE_QT_DEF_EXCEPTION_GUARD_BEGIN

				toy_client::initialize_request_self_cert( dynamic_cast<QMainWindow*> ( this->parent() ) );

			GIE_QT_DEF_EXCEPTION_GUARD_END
		}

		void request_ca_root_certificate();

private:
	Ui::client_request_root_or_self_cert_t ui;
private:
	void worker_func_request_cert_sign_(boost::shared_ptr<boost::asio::ip::tcp::iostream> const& stream);
	void complete_ca_root_cert_local_registration_( boost::shared_ptr<ms_cert::pccert_context_t> const& signed_cert_context );
private:
	void show_async_exception_(boost::exception_ptr const& e){
		GIE_QT_DEF_EXCEPTION_GUARD_BEGIN
			boost::rethrow_exception( e );
		GIE_QT_DEF_EXCEPTION_GUARD_END
	}

	void post_show_fatal_exception_(boost::exception_ptr const& e){
		std::auto_ptr<function_event_t> async_event( new function_event_t( [this, e](){ this->show_async_exception_(e); } ) );
		QApplication::postEvent( this, async_event.release() );
	}

private:
	boost::thread			m_worker_thread;

	STCRYPT_DEF_EVENT_HANDLE(QWidget)
};

//================================================================================================================================================
#endif
//================================================================================================================================================
