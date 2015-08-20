//================================================================================================================================================
// FILE: util-raii-helpers.h
// (c) GIE 2009-11-02  17:08
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_RAII_HELPERS_2009_11_02_17_08
#define H_GUARD_UTIL_RAII_HELPERS_2009_11_02_17_08
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "boost/shared_ptr.hpp"
//================================================================================================================================================
namespace stcrypt {

	inline void delete_HMODULE(HMODULE * const module)
	{
		assert(module);
		if(*module){
			BOOL const r =  FreeLibrary(*module);
			assert( r ); //TODO: can't throw from a destructor
		}
		delete module;
	}

	typedef boost::shared_ptr<HMODULE>	module_ptr_t;

	inline module_ptr_t create_module_ptr(HMODULE const module)
	{
		std::auto_ptr<HMODULE> hmodule_mem;
		try{
			hmodule_mem.reset( new HMODULE(module) );
		}catch(...) {
			if(module) {BOOL const r =  FreeLibrary(module); assert( r );}
			throw;
		}
		return module_ptr_t( hmodule_mem.release() , delete_HMODULE ); // will cleanup on exceptions
	}
}
//================================================================================================================================================
#endif
//================================================================================================================================================
