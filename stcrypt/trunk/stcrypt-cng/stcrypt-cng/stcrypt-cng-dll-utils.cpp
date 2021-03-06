//================================================================================================================================================
// FILE: stcrypt-cng-dll-utils.cpp
// (c) GIE 2011-02-08  04:15
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-dll-utils.hpp"
//================================================================================================================================================
#include "stcrypt-cng-oid-exceptions.hpp"
//================================================================================================================================================
namespace stcrypt {

	std::wstring self_dll_path(){
		assert(this_module_handle);

		wchar_t large_enough_buffer_or_so_i_hope[MAX_PATH+1];
		auto const path_length = GetModuleFileNameW( this_module_handle, large_enough_buffer_or_so_i_hope, sizeof(large_enough_buffer_or_so_i_hope) );
		if( !path_length ) STCRYPT_UNEXPECTED();

		return std::wstring(large_enough_buffer_or_so_i_hope, path_length);
	}

}
//================================================================================================================================================
