//================================================================================================================================================
// FILE: util-capi-get-param-impl.h
// (c) GIE 2009-11-11  13:34
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_CAPI_GET_PARAM_IMPL_2009_11_11_13_34
#define H_GUARD_UTIL_CAPI_GET_PARAM_IMPL_2009_11_11_13_34
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"

#include "boost/function.hpp"
//================================================================================================================================================
namespace stcrypt {

	// data_size - actual size of data
	// *data_len - size of allocated buffer by user
	//	when invoke user copy_func -- pass actual data size
	inline 
	void capi_get_param_impl(size_t const data_size, BYTE* const data, DWORD * const datalen, 
		boost::function<void (BYTE*const,DWORD const)> const& copy_func) // (dest, size)
	{
		assert(datalen);

		if( !data ) {
			*datalen=static_cast<DWORD>(data_size);
		} else if( *datalen < data_size ) {
			*datalen=static_cast<DWORD>(data_size);
			STCRYPT_THROW_EXCEPTION(exception::more_data());
		} else {
			copy_func( data, static_cast<DWORD>(data_size) );
			if( *datalen!=static_cast<DWORD>(data_size) ) {
				*datalen=static_cast<DWORD>(data_size);
			}
		}
	}


}
//================================================================================================================================================
#endif
//================================================================================================================================================
