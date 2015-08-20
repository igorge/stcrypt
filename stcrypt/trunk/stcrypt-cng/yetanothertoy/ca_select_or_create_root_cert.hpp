//================================================================================================================================================
// FILE: ca_select_or_create_root_cert.h
// (c) GIE 2011-02-02  23:12
//
//================================================================================================================================================
#ifndef H_GUARD_CA_SELECT_OR_CREATE_ROOT_CERT_2011_02_02_23_12
#define H_GUARD_CA_SELECT_OR_CREATE_ROOT_CERT_2011_02_02_23_12
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include <QtGui/QWidget>

#include "qt/qt_def_exception_stubs.hpp"

#include "ui_ca_select_or_create_root_cert.h"

class ca_select_or_create_root_cert_t : public QWidget
{
	Q_OBJECT

public slots:

	void select_root_ca_from_store();
	void generate_root_ca_cert();

public:
	ca_select_or_create_root_cert_t(QWidget *parent = 0, Qt::WFlags flags = 0)
		: QWidget(parent, flags)
	{
		ui.setupUi(this);
	}

	~ca_select_or_create_root_cert_t(){};

private:
	Ui::ca_select_or_create_root_cert ui;
};

//================================================================================================================================================
#endif
//================================================================================================================================================
