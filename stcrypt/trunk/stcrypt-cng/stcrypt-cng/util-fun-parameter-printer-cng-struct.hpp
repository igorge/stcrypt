//================================================================================================================================================
// FILE: util-fun-parameter-printer-cng-struct.h
// (c) GIE 2010-09-22  18:18
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_FUN_PARAMETER_PRINTER_CNG_STRUCT_2010_09_22_18_18
#define H_GUARD_UTIL_FUN_PARAMETER_PRINTER_CNG_STRUCT_2010_09_22_18_18
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "util-fun-param-printer2.hpp"

#include <WinCrypt.h>
//================================================================================================================================================
namespace stcrypt {

	namespace pp{

		struct nprov_handle;
		struct nkey_handle;

	}

	inline  std::wostream& operator <<(std::wostream& os, pp_as_t<pp::nprov_handle, NCRYPT_PROV_HANDLE> const &v ){
		return ( os << pp_as<pp::hex_auto>( static_cast<UINT_PTR>( v.m_val ) ) );
	}


	inline  std::wostream& operator <<(std::wostream& os, pp_as_t<pp::nprov_handle, NCRYPT_PROV_HANDLE*> const &v ){
		if( v.m_val ){
			os << L"@" << pp_as<pp::hex_auto>( static_cast<void*>( v.m_val ) ) << L"=" <<  pp_as<pp::hex_auto>( static_cast<UINT_PTR>( *v.m_val ) ) ;
		} else {
			os << STC_P_NULL_LIT;
		}
		return os;
	}


	inline std::wostream& operator <<(std::wostream& os, pp_as_t<pp::nkey_handle, NCRYPT_KEY_HANDLE*> const &v ){
		if( v.m_val ){
			os << L"@" << pp_as<pp::hex_auto>( static_cast<void*>( v.m_val ) ) << L"=" <<  pp_as<pp::hex_auto>( static_cast<UINT_PTR>( *v.m_val ) ) ;
		} else {
			os << STC_P_NULL_LIT;
		}
		return os;
	}

	inline  std::wostream& operator <<(std::wostream& os, pp_as_t<pp::nkey_handle, NCRYPT_KEY_HANDLE> const &v ){
		return ( os << pp_as<pp::hex_auto>( static_cast<UINT_PTR>( v.m_val ) )  );
	}


}
//================================================================================================================================================
#endif
//================================================================================================================================================
