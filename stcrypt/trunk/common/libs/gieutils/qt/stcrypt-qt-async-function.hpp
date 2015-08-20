//================================================================================================================================================
// FILE: stcrypt-qt-async-function.h
// (c) GIE 2010-04-01  16:26
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_QT_ASYNC_FUNCTION_2010_04_01_16_26
#define H_GUARD_STCRYPT_QT_ASYNC_FUNCTION_2010_04_01_16_26
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include <qevent.h>
#include "boost/function.hpp"
//================================================================================================================================================
int const function_event_t_ID  = QEvent::User+101;

struct function_event_t : QEvent 
{
	function_event_t(boost::function<void()> const& action)
		: QEvent( static_cast<QEvent::Type>(function_event_t_ID) )
		, m_action( action )
	{}

	~function_event_t(){}

	void run(){
		if(m_action)
			m_action();
	}

private:
	boost::function<void()>	m_action;
};

#define STCRYPT_DEF_EVENT_HANDLE(Type)				\
bool event(QEvent *e){								\
	try{											\
		if( e->type() == function_event_t_ID ) {	\
			function_event_t * const my_event = dynamic_cast<function_event_t*>(e);	\
			if(my_event)							\
				my_event->run();					\
			return true;							\
		}											\
	}catch(...){									\
		assert(false);								\
		return false;								\
	}												\
													\
	return Type::event(e);							\
}													\
/**/


//================================================================================================================================================
#endif
//================================================================================================================================================
