#include "stdafx.h"

#include "toy_mode_select.hpp"
#include "yetanothertoy_t.h"

#include <QtGui/QApplication>

#include <memory>


int main(int argc, char *argv[])
{

	_CrtSetDbgFlag( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | /*_CRTDBG_CHECK_ALWAYS_DF |*/ _CRTDBG_DELAY_FREE_MEM_DF);
	//_CrtSetBreakAlloc(168);

	
	QApplication a(argc, argv);
	yetanothertoy_t w;
	
	std::auto_ptr<QWidget> mode_sel_w( new toy_mode_select_t() );

	w.setCentralWidget( mode_sel_w.release() );

	w.show();
	
	auto const r = a.exec();

	return r;
}
