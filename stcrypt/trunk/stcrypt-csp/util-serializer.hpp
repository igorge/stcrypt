//================================================================================================================================================
// FILE: util-serializer.h
// (c) GIE 2010-01-09  21:02
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_SERIALIZER_2010_01_09_21_02
#define H_GUARD_UTIL_SERIALIZER_2010_01_09_21_02
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-debug.hpp"
#include "stcrypt-exceptions.hpp"

#include "boost/optional.hpp"
#include "boost/utility/in_place_factory.hpp"
#include "boost/range/begin.hpp"
#include "boost/range/end.hpp"
#include "boost/range/iterator_range.hpp"
#include "boost/mpl/identity.hpp"
#include "boost/function_output_iterator.hpp"
//================================================================================================================================================
namespace stcrypt {
	
	namespace exception {

		namespace serialization {
			struct root {};
			struct eos : root {};
			struct bad_input_data : root {};
		}
	}

	template <class T>
	struct ptr2oiter_func {

		struct overflow_e : virtual stcrypt::exception::unexpected {};

		ptr2oiter_func(T*& ptr, T* const end): m_ptr(ptr), m_end(end) {}

		void operator()(T const v){
			if(m_ptr==m_end) STCRYPT_THROW_EXCEPTION( overflow_e() );
			*m_ptr = v;
			++m_ptr;
		}


		T*& m_ptr;
		T* const m_end;
	};

	template <class OutputIterator>
	struct out_serializer_t {

		out_serializer_t(OutputIterator const& out_iter)
			: m_out( out_iter )
		{}

		template <class T>
		out_serializer_t& operator <<(T const&v){
			serialize_out(*this,v);
			return *this;
		}

		OutputIterator m_out;
	};

	struct out_dummy_serializer_t {

	};

	template <class OutputIterator>
	out_serializer_t<OutputIterator> out_serializer(OutputIterator const& out_iter){
		return out_serializer_t<OutputIterator>(out_iter);
	}

	template <class InputIterator, class InputIteratorEnd>
	struct in_serializer_t {
		
		typedef typename std::iterator_traits<InputIterator>::value_type value_type;

		in_serializer_t(InputIterator const& in_iter, InputIteratorEnd const& in_end)
			: m_in( in_iter )
			, m_end( in_end )
		{}

		template <class T>
		void operator >>(T &v){
			serialize_in(*this,v);
		}

		void check_for_eos(){
			if( m_in==m_end )
				throw exception::serialization::eos();
		}

		value_type item(){
			check_for_eos();
			return *m_in;
		}

		void next(){
		#ifdef STCRYPT_DEBUG
			assert(m_in!=m_end);
		#endif
			++m_in;
		}

		boost::iterator_range< InputIterator > current_range() const {boost::make_iterator_range(m_in, m_end);}
		
	private:
		InputIterator m_in;
		InputIteratorEnd const m_end;
	};

	template <class InputIterator, class InputIteratorEnd>
	in_serializer_t<InputIterator, InputIteratorEnd> in_serializer(InputIterator const& in_iter, InputIteratorEnd const& in_end){
		return in_serializer_t<InputIterator, InputIteratorEnd>(in_iter, in_end);
	}



	template<class Archive>
	size_t serialize_size(Archive & ar, boost::mpl::identity<unsigned int> const & g){
		return sizeof(unsigned int);
	}


	
	/* unsigned int
	 *
	 *
	 */

	template<class Archive>
	void serialize_in(Archive & ar, unsigned int& g) {
		BYTE *  raw_int = reinterpret_cast<BYTE *>(&g);
		BYTE const *  const raw_int_end = raw_int+sizeof(g);

		while(raw_int!=raw_int_end){
			*raw_int = ar.item();
			ar.next(); ++raw_int;
		}
	}



	template<class Archive>
	void serialize_out(Archive & ar, unsigned int const g)
	{
		BYTE const* const raw_int = reinterpret_cast<BYTE const*>(&g);
		std::copy(raw_int, raw_int+sizeof(g), ar.m_out);
	}

// 	template<class Archive>
// 	void serialize_out(Archive & ar, size_t const g)
// 	{
// 		BYTE const* const raw_int = reinterpret_cast<BYTE const*>(&g);
// 		std::copy(raw_int, raw_int+sizeof(g), ar.m_out);
// 	}

	/* optional
	 *
	 *
	 */

	template<class Archive, class OptionalType>
	void serialize_out(Archive & ar, boost::optional<OptionalType> const & g)
	{
		if(g){
			ar << static_cast<unsigned int>( serialize_size(ar, *g) );
			ar << (*g);
		} else {
			ar << static_cast<unsigned int>(0);
		}
	}
	template<class Archive, class OptionalType>
	void serialize_in(Archive & ar, boost::optional<OptionalType>  & g)
	{
		unsigned int optional_data_size=0;
		ar >> optional_data_size;
		if(optional_data_size){
			g = boost::in_place();

			if( serialize_size(ar, *g)!=optional_data_size )
				throw exception::serialization::bad_input_data();

			ar >> (*g);
		} else {
			g.reset();
		}
	}


	template<class Archive, class OptionalType>
	size_t serialize_size(Archive & ar, boost::optional<OptionalType> const & g)
	{
		if(g){
			return sizeof(unsigned int)+serialize_size(ar, *g);
		} else {
			return sizeof(unsigned int);
		}
	}


//  	template<class Archive, class ArrayType, size_t N>
//  	void serialize_out(Archive & ar, ArrayType (&g)[N])
//  	{
//  	}

	/* unsigned char T[N]
	 *
	 *
	 */
	template<class Archive, size_t N>
	void serialize_out(Archive & ar, unsigned char const (&g)[N])
	{
		std::copy(boost::begin(g), boost::end(g), ar.m_out);
	}
	template<class Archive, size_t N>
	void serialize_in(Archive & ar, unsigned char (&g)[N])
	{
		unsigned char * curr = &g[0];
		unsigned char const* const end = curr+N;
		while(curr!=end){
			*curr = ar.item();
			++curr;
			ar.next();
		}

	}


	template<class Archive, size_t N>
	size_t serialize_size(Archive & ar, unsigned char const (&g)[N])
	{
		return N*sizeof(g[0]);
	}


	template<class Archive>
	size_t serialize_size(Archive & ar, unsigned int const g){
		return sizeof(g);
	}

// 	template<class Archive>
// 	size_t serialize_size(Archive & ar,size_t const g){
// 		return sizeof(size_t);
// 	}



}
//================================================================================================================================================
#endif
//================================================================================================================================================
