//================================================================================================================================================
// FILE: strcypt-cng-hash-provider.cpp
// (c) GIE 2010-08-10  15:10
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-gost28147-89.hpp"
#include "stcrypt-cng-symmetric-provider.hpp"
#include "stcrypt-crypto-alg-ids.h"
//================================================================================================================================================
namespace stcrypt {


	bool is_symmetric_alg_valid(LPCWSTR const alg_id){
		if( wcscmp(CNG_G28147_89, alg_id)==0 ){
			return true;
		} else {
			return false;
		}
	}


	cng_symmetric_class_op_i_ptr create_symmetric_class( LPCWSTR const alg_id )
	{

		if( wcscmp(CNG_G28147_89, alg_id)==0 ){
			return cng_symmetric_class_op_i_ptr( new cng_gost28147_class() );
		} else {
			STCRYPT_THROW_EXCEPTION( exception::badalg() );
		}
	}



}
//================================================================================================================================================
