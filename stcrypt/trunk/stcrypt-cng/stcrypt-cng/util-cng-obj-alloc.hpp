//================================================================================================================================================
// FILE: util-cng-obj-alloc.h
// (c) GIE 2010-08-12  18:09
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_CNG_OBJ_ALLOC_2010_08_12_18_09
#define H_GUARD_UTIL_CNG_OBJ_ALLOC_2010_08_12_18_09
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include <boost/aligned_storage.hpp>
#include <limits>
//================================================================================================================================================
namespace stcrypt {

	template <class T>
	struct buffer_for_obj {
		BOOST_STATIC_CONSTANT(size_t, value=boost::alignment_of<T>::value+sizeof(T) );
	};

	template <class T, unsigned int count>
	struct buffer_for_obj_array {
		BOOST_STATIC_CONSTANT(size_t, value=( count? (count=1?boost::alignment_of<T>::value+sizeof(T) : boost::alignment_of<T>::value+sizeof(T) + (count-1)*sizeof(T)  ):0 ) );
	};

	template <class T>
	size_t get_buffer_size_for_obj_array(unsigned int const count){
		return ( count ? (count==1 ? buffer_for_obj<T>::value :  buffer_for_obj<T>::value + (count-1)*sizeof(T) ) :0 );
	}

	template <class T>
	void * aligned_ptr_in_buffer(BYTE * const buffer, ULONG const buffer_size, unsigned int count = 1, size_t * const allocated_size = 0){ //TODO: WARN: platform dependent code

		if(count==0) return 0;

		auto const object_size = sizeof(T) * count;
		auto const object_alignment = boost::alignment_of<T>::value;

		if( buffer_size < object_size ) return 0;

		ULONG_PTR const buffer_addr = reinterpret_cast<ULONG_PTR>( buffer );


		if( buffer_addr%object_alignment == 0 ){
			if(allocated_size) { *allocated_size=object_size; }
			return buffer;
		} else {

			if( buffer_size < object_alignment ) return 0;

			ULONG_PTR const object_addr_in_buffer = (buffer_addr/object_alignment + 1)*object_alignment; 

			auto const buffer_moved_by_bytes = object_addr_in_buffer-buffer_addr;
			if(  object_size > buffer_size - buffer_moved_by_bytes ) return 0;

			if(allocated_size) { *allocated_size=object_size+buffer_moved_by_bytes; }

			return reinterpret_cast<void*>( object_addr_in_buffer );
		}
	}

	template <class T>
	void * aligned_alloc_in_buffer(BYTE *& buffer, ULONG const buffer_size, size_t& buffer_size_free, unsigned int count=1){
		size_t allocated_bytes = 0;

		auto const ptr = aligned_ptr_in_buffer<T>( buffer, buffer_size, count, &allocated_bytes );
		if( !ptr ) return 0;

		buffer +=allocated_bytes;
		buffer_size_free = buffer_size - allocated_bytes;

		return ptr;
	}

}
//================================================================================================================================================
#endif
//================================================================================================================================================
