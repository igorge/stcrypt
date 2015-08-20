#ifndef YETANOTHERTOY_T_H
#define YETANOTHERTOY_T_H

#include <QtGui/QMainWindow>
#include "ui_yetanothertoy_t.h"

class yetanothertoy_t : public QMainWindow
{
	Q_OBJECT

public:
	yetanothertoy_t(QWidget *parent = 0, Qt::WFlags flags = 0);
	~yetanothertoy_t();

private:
	Ui::yetanothertoy_tClass ui;
};

#endif // YETANOTHERTOY_T_H
