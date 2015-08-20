//================================================================================================================================================
// FILE: util-scope-exit.h
// (c) GIE 2011-02-20  02:05
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_SCOPE_EXIT_2011_02_20_02_05
#define H_GUARD_UTIL_SCOPE_EXIT_2011_02_20_02_05
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"
#include "stcrypt-debug.hpp"

#include <boost/preprocessor/cat.hpp>
//================================================================================================================================================
namespace stcrypt {

	template <class FunT>
	struct scope_guard_t
	{

		explicit scope_guard_t(FunT && fun) : m_fun( std::move(fun) ){}

		scope_guard_t(scope_guard_t<FunT> && other) : m_fun( std::move(other.m_fun) ){}
		scope_guard_t(scope_guard_t<FunT> const& other) : m_fun( other.m_fun ){}

		~scope_guard_t(){

			try{
				
				m_fun();

			}catch(...){
				STCRYPT_UNEXPECTED_IN_DTOR();
			}

		}
	private:
		scope_guard_t<FunT>& operator=(scope_guard_t<FunT> const&);
	private:
		FunT m_fun;
	};

	template <class FunT>	
	scope_guard_t<FunT> make_guard(FunT && fun){
		return scope_guard_t<FunT>( std::move(fun) );
	}


#define STCRYPT_SCOPE_EXIT auto const& BOOST_PP_CAT(sg__stcrypt__, __COUNTER__) = stcrypt::make_guard
	
}
//================================================================================================================================================
#endif
//================================================================================================================================================
