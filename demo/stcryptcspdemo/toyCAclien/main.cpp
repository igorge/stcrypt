#include "stdafx.h"
#include "toycaclien.h"
#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF |/* _CRTDBG_CHECK_ALWAYS_DF |*/ _CRTDBG_DELAY_FREE_MEM_DF);

	QApplication a(argc, argv);
	toyCAclien w;
	w.show();
	return a.exec();
}
