//================================================================================================================================================
// FILE: stcrypt-debug-logger.h
// (c) GIE 2010-09-21  22:10
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_DEBUG_LOGGER_2010_09_21_22_10
#define H_GUARD_STCRYPT_DEBUG_LOGGER_2010_09_21_22_10
//================================================================================================================================================
#pragma once
//================================================================================================================================================
//#include <boost/utility/thread_specific_singleton.hpp>
#include <boost/scoped_ptr.hpp>
//================================================================================================================================================
namespace stcrypt {

	namespace logger {

		struct stcrypt_debug_subsystem_logger_tag {};

		struct logger_impl;

		struct logger
			//: boost::thread_specific_singleton<logger, 1, stcrypt_debug_subsystem_logger_tag>
		{

			logger(/*boost::restricted*/);
			~logger();

			void log(std::wstring const& msg);
			void log(std::string const& msg);
			void inc_level();
			void dec_level();

		private:
			boost::scoped_ptr<logger_impl>	m_impl;
		};

		
	
		logger* get_logger();
		void before_unload();
		void unload_for_thread();

	}

}
//================================================================================================================================================
#endif
//================================================================================================================================================
