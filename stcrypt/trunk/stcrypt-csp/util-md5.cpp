//================================================================================================================================================
// FILE: util-md5.cpp
// (c) GIE 2009-11-11  23:38
//
//================================================================================================================================================
#include "stdafx.h"

//================================================================================================================================================
#include "util-md5.hpp"
#include "util-raii-helpers-crypt.hpp"
#include "boost/static_assert.hpp"
#include <WinCrypt.h>

#include <vector>
//================================================================================================================================================
namespace stcrypt {
	std::wstring create_md5_hash(std::string const data)
	{
		BOOST_STATIC_ASSERT(sizeof(std::string::value_type) ==sizeof(BYTE));

		cryptprov_ptr_t prov = create_cryptprov_ptr(NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT );
		crypthash_ptr_t hash = create_crypthash_ptr(*prov, CALG_MD5, 0, 0);
		if(!CryptHashData(*hash, reinterpret_cast<BYTE const*>( data.data() ), static_cast<DWORD>(data.size()),0)){DWORD const errc = GetLastError(); STCRYPT_THROW_EXCEPTION( exception::cryptoapi_error() << exception::cryptoapi_einfo(errc) );}

		typedef std::vector<BYTE> hash_type;
		hash_type hashed_data;

		DWORD hash_data_len;
		if(!CryptGetHashParam(*hash, HP_HASHVAL, 0, &hash_data_len, 0)){DWORD const errc = GetLastError(); STCRYPT_THROW_EXCEPTION( exception::cryptoapi_error() << exception::cryptoapi_einfo(errc) );}
		hashed_data.resize(hash_data_len);
		if(!CryptGetHashParam(*hash, HP_HASHVAL, &hashed_data[0], &hash_data_len, 0)){DWORD const errc = GetLastError(); STCRYPT_THROW_EXCEPTION( exception::cryptoapi_error() << exception::cryptoapi_einfo(errc) );}
		std::wostringstream conv;
		for(hash_type::const_iterator end=hashed_data.end(), i=hashed_data.begin(); i<end;++i)
		{
			conv << std::hex << *i;
		}
		return conv.str();
	}

}
//================================================================================================================================================
