//================================================================================================================================================
// FILE: util-raw-buffer-oiter.h
// (c) GIE 2010-09-14  21:48
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_RAW_BUFFER_OITER_2010_09_14_21_48
#define H_GUARD_UTIL_RAW_BUFFER_OITER_2010_09_14_21_48
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "util-sio-exceptions.hpp"

#include <boost/function_output_iterator.hpp>
//================================================================================================================================================
namespace stcrypt {

	namespace sio {

		template <class T>
		struct raw_buffer_appender
		{
			raw_buffer_appender(T*& buffer_start, T const* const buffer_end)
				: m_buffer_curr( buffer_start )
				, m_end( buffer_end )
			{}

			void operator()(T const v) const
			{
				if(m_buffer_curr==m_end) STCRYPT_THROW_EXCEPTION( sio::exception::overflow() );
				*m_buffer_curr = v;
				++m_buffer_curr;
			}

			boost::reference_wrapper<T*> m_buffer_curr;
			T const* m_end;
		};

	}

	template <class T>
	struct raw_buffer_oiter_for{
		typedef boost::function_output_iterator< sio::raw_buffer_appender<T> > type;
		typedef raw_buffer_oiter_for<T> ctor;

		static type construct(T *& v, T const * const end){
			return type( sio::raw_buffer_appender<T>(v, end) );
		}
	};


}
//================================================================================================================================================
#endif
//================================================================================================================================================
