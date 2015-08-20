//================================================================================================================================================
// FILE: util-fun-param-printer.h
// (c) GIE 2010-04-27  14:29
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_FUN_PARAM_PRINTER_2010_04_27_14_29
#define H_GUARD_UTIL_FUN_PARAM_PRINTER_2010_04_27_14_29
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "boost/preprocessor/stringize.hpp"
#include "boost/io/ios_state.hpp"
#include "boost/type_traits.hpp"
#include "boost/preprocessor.hpp"
#include "boost/scope_exit.hpp"

#include <ostream>
//================================================================================================================================================
namespace stcrypt {

	#define STC_PARAMS_GEN_T(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)   ( BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/) )
	#define STC_PARAMS_GEN_TEMPLATES(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)  "[" BOOST_PP_STRINGIZE( BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/) ) ":%" BOOST_PP_STRINGIZE( BOOST_PP_INC(i) ) "%]"
	#define STC_PARAMS_GEN_CALL(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)  % BOOST_PP_TUPLE_ELEM(2/*size*/, 1/*extract idx*/, oid_def /*tuple*/)



	#define STC_DUMP_PARAMS(params) \
		boost::format fun_params(BOOST_PP_SEQ_FOR_EACH_I( STC_PARAMS_GEN_TEMPLATES, 0, params ));	\
		STCRYPT_LOG_PRINT_EX("in", (fun_params BOOST_PP_SEQ_FOR_EACH_I( STC_PARAMS_GEN_CALL, 0, params ) ).str().c_str() );	\
\
	BOOST_SCOPE_EXIT( ( &fun_params) 	BOOST_PP_SEQ_FOR_EACH_I( STC_PARAMS_GEN_T, 0, params ) ) {\
		STCRYPT_LOG_PRINT_EX("out", (fun_params BOOST_PP_SEQ_FOR_EACH_I( STC_PARAMS_GEN_CALL, 0, params ) ).str().c_str() );\
	}  BOOST_SCOPE_EXIT_END\

	template <class T, class V>
	std::string param_dump_array( T const*const v, V const* const count){
		std::stringstream os;
		os<< "@"<<std::hex << static_cast<void const*>(v)<<"=";
		if(v){
			if(!count || *count==0) {
				os << "<empty>";
			} else {
				os.fill('0');
				for(unsigned int i = 0;i<*count;++i){
					if(i) {
						os << " ";
						os.width(0);
					}
					os.width(std::numeric_limits<T>::digits/4);
					os<< std::hex << static_cast<unsigned int>( v[i] );
				}
			}
		} else {
			os << "<NULL>";
		}
		return os.str();
	}

	template <class T>
	std::string param_dump_array( T const*const v, DWORD const count){
		return param_dump_array(v, &count);
	}

	template <class T>
	std::string param_dump_via_ptr(T const* const v){
		std::stringstream os;
		os<< "@"<<std::hex << static_cast<void const*>(v)<<"=";
		if(v){
			os << std::dec << *v;
		} else {
			os << "<NULL>";
		}
		
		return os.str();
	}

	template <class T, class CountType>
	std::string param_dump_array_via_ptr(T const* const*const v, CountType const*const count){
		std::stringstream os;
		os<< "@"<<std::hex << static_cast<void const*>(v);
		if(v){
			os << param_dump_array(*v, count);
		} else {
			os << "<NULL>=<NULL>";
		}

		return os.str();
	}

	inline
	std::string param_dump_str(char const*const str){
		if(str){
			return str;
		} else {
			return "<NULL>";
		}

	}

	template<class T>
	std::string param_dump_hex(T const& v){
		std::stringstream os;
		os.width(std::numeric_limits<T>::digits/4);
		os.fill('0');
		os<< std::hex << v;

		return os.str();
	}



}
//================================================================================================================================================
#endif
//================================================================================================================================================
