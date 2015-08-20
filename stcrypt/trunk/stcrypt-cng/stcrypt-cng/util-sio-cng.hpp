//================================================================================================================================================
// FILE: util-sio-cng.h
// (c) GIE 2010-09-11  19:15
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_SIO_CNG_2010_09_11_19_15
#define H_GUARD_UTIL_SIO_CNG_2010_09_11_19_15
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "util-sio.hpp"
//================================================================================================================================================
namespace stcrypt {

	namespace sio {

		template<>
		struct io_size<BCRYPT_KEY_BLOB> {
			static size_t const value = io_size<unsigned int>::value;
		};

		template <> 
		struct write<BCRYPT_KEY_BLOB> {
			template <class OutputIter>
			static boost::tuple<size_t, OutputIter> apply(BCRYPT_KEY_BLOB const& v, OutputIter const& output){
				return sio::write<decltype(v.Magic)>::apply( v.Magic, output );
			}
		};

		template <> 
		struct read<BCRYPT_KEY_BLOB> {
			template <class InputIterator>
			static boost::tuple< boost::iterator_range<InputIterator>, size_t >
				apply(BCRYPT_KEY_BLOB& v, boost::iterator_range<InputIterator> const& input){
					return sio::read<decltype(v.Magic)>::apply(v.Magic, input);
			}

		};


	} // end ns sio


}
//================================================================================================================================================
#endif
//================================================================================================================================================
