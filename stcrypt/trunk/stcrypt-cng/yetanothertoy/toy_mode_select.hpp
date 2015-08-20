//================================================================================================================================================
// FILE: toy_mode_select.h
// (c) GIE 2011-02-02  20:54
//
//================================================================================================================================================
#ifndef H_GUARD_TOY_MODE_SELECT_2011_02_02_20_54
#define H_GUARD_TOY_MODE_SELECT_2011_02_02_20_54
//================================================================================================================================================
#pragma once
//================================================================================================================================================

#include <QtGui/QWidget>
#include "ui_toy_mode_select_t.h"

#include "toy_mode_selected_ca_if.hpp"
#include "client_request_root_or_self_cert_if.hpp"

#include "qt/qt_def_exception_stubs.hpp"

class toy_mode_select_t : public QWidget
{
	Q_OBJECT

public slots:

	void ca_mode_selected(){
		GIE_QT_DEF_EXCEPTION_GUARD_BEGIN
			
			toy_ca::initialize_ca_mode( dynamic_cast<QMainWindow*> ( this->parent() ) );

		GIE_QT_DEF_EXCEPTION_GUARD_END
	}

	void client_mode_selected(){
		GIE_QT_DEF_EXCEPTION_GUARD_BEGIN

			toy_client::initialize_request_root_or_self_cert( dynamic_cast<QMainWindow*> ( this->parent() ) );

		GIE_QT_DEF_EXCEPTION_GUARD_END
	}

public:
	toy_mode_select_t(QWidget *parent = 0, Qt::WFlags flags = 0)
		: QWidget(parent, flags)
	{
		ui.setupUi(this);
	}

	~toy_mode_select_t(){};

private:
	Ui::ui_toy_mode_select_t ui;
};

//================================================================================================================================================
#endif
//================================================================================================================================================
