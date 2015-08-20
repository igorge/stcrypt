//================================================================================================================================================
// FILE: util-sio.h
// (c) GIE 2010-09-08  16:26
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_SIO_2010_09_08_16_26
#define H_GUARD_UTIL_SIO_2010_09_08_16_26
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "util-raw-buffer-oiter.hpp"
#include "util-sio-exceptions.hpp"

#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range.hpp>
#include <boost/ref.hpp>
//================================================================================================================================================
namespace stcrypt{

	namespace sio {
		template <class T> struct io_size;
		template <class T> struct write;
		template <class T> struct read;

		template <class U> struct write<const U>{
			template <class OutputIter, class V>
			static boost::tuple<size_t, OutputIter> apply(V const& v, OutputIter const& output){
				return sio::write<U>::apply(v, output);
			}
		};

		
		// generic array
		template<class T, size_t N>
		struct io_size<T[N]> {
			static size_t const value = io_size<T>::value * N;
		};

		// unsigned char array
		template <size_t N>
		struct write<unsigned char[N]> {
			template <class OutputIter>
			static boost::tuple<size_t, OutputIter> apply(unsigned char const (&v)[N], OutputIter const& output){

				auto const new_out = std::copy(boost::begin(v), boost::end(v), output);

				return boost::make_tuple( sio::io_size<decltype(v)>::value , new_out );
			}
		};

		template <size_t N> 
		struct read<unsigned char[N]> {
			template <class InputIterator>
			static boost::tuple< boost::iterator_range<InputIterator>, size_t >
			apply(unsigned char (&v)[N], boost::iterator_range<InputIterator> const& input){

					auto iter = input.begin();
					auto const& end = input.end();

					unsigned char * out_cur = reinterpret_cast<unsigned char*>(&v);
					unsigned char const * const out_end = out_cur+sizeof(v);

					while(out_cur !=out_end){

						if( iter==end ) STCRYPT_THROW_EXCEPTION( sio::exception::underflow() );

						*out_cur = *iter;
						++iter;
						++out_cur;
					}

					return boost::make_tuple( boost::make_iterator_range(iter, end), sizeof(v) );

			}

		};


		// remove ref size
		template <class U> 
		struct io_size<U&>{
			static size_t const value = io_size<U>::value;
		};


		// remove ref write
		template <class U> 
		struct write<U&>{
			template <class OutputIter>
			static boost::tuple<size_t, OutputIter> apply(U const& v, OutputIter const& output){
				return sio::write<U>::apply(v, output);
			}
		};

		// remove const
		template <class U> 
		struct io_size<U const>{
			static size_t const value = io_size<U>::value;
		};

		template<>
		struct io_size<unsigned int> {
			static size_t const value = sizeof(unsigned int);
		};

		template<>
		struct io_size<unsigned char> {
			static size_t const value = sizeof(unsigned char);
		};

		template<>
		struct io_size<unsigned long> {
			static size_t const value = sizeof(unsigned long);
		};


		template <> 
		struct write<unsigned int> {
			template <class OutputIter>
			static boost::tuple<size_t, OutputIter> apply(unsigned int const v, OutputIter const& output){

				BYTE const* const raw_int = reinterpret_cast<BYTE const*>(&v);
				auto const new_out = std::copy(raw_int, raw_int+sizeof(v), output);

				return boost::make_tuple( sizeof(v), new_out );
			}
		};


		//
		// unsigned long
		//


		template <> 
		struct write<unsigned long> {
			template <class OutputIter>
			static boost::tuple<size_t, OutputIter> apply(unsigned long const v, OutputIter const& output){

				BYTE const* const raw_int = reinterpret_cast<BYTE const*>(&v);
				auto const new_out = std::copy(raw_int, raw_int+sizeof(v), output);

				return boost::make_tuple( sizeof(v), new_out );
			}
		};


		template <> 
		struct read<unsigned long> {
			template <class InputIterator>
			static boost::tuple< boost::iterator_range<InputIterator>, size_t >
			apply(unsigned long& v, boost::iterator_range<InputIterator> const& input){
				
				auto iter = input.begin();
				auto const& end = input.end();

				unsigned char * raw_int = reinterpret_cast<unsigned char*>(&v);
				unsigned char const * const raw_int_end = raw_int+sizeof(v);

				while(raw_int!=raw_int_end){

					if( iter==end ) STCRYPT_THROW_EXCEPTION( sio::exception::underflow() );

					*raw_int = *iter;
					++iter;
					++raw_int;
				}

				return boost::make_tuple( boost::make_iterator_range(iter, end), sizeof(unsigned long) );

			}

		};

	}


}
//================================================================================================================================================
#endif
//================================================================================================================================================
