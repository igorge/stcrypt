//================================================================================================================================================
// FILE: strcypt-cng-hash-provider.cpp
// (c) GIE 2010-08-10  15:10
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "strcypt-cng-gost34311.hpp"
#include "strcypt-cng-hash-provider.hpp"
#include "stcrypt-crypto-alg-ids.h"
//================================================================================================================================================
namespace stcrypt {


	bool is_hash_alg_valid(LPCWSTR const alg_id){
		if( wcscmp(CNG_G34311_ALGORITHM, alg_id)==0 ){
			return true;
		} else {
			return false;
		}
	}


	cng_hash_class_op_i_ptr create_hash_class( LPCWSTR const alg_id )
	{
		if( wcscmp(CNG_G34311_ALGORITHM, alg_id)==0 ){
			return cng_hash_class_op_i_ptr( new cng_gost34311_class() );
		} else {
			STCRYPT_THROW_EXCEPTION( exception::badalg() );
		}
	}



}
//================================================================================================================================================
