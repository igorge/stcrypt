#include "stdafx.h"
#include "toy_ca_t.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{

	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF |/* _CRTDBG_CHECK_ALWAYS_DF |*/ _CRTDBG_DELAY_FREE_MEM_DF);

	QApplication a(argc, argv);
	toy_ca_t w;
	w.show();
	return a.exec();
}
