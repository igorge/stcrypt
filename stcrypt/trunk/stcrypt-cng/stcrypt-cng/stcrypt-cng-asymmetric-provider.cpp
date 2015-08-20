//================================================================================================================================================
// FILE: strcypt-cng-asymmetric.cpp
// (c) GIE 2010-08-25  16:29
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-dstu4145.hpp"
#include "stcrypt-cng-asymmetric-provider.hpp"
#include "stcrypt-crypto-alg-ids.h"
//================================================================================================================================================
namespace stcrypt {
	bool is_asymmetric_alg_valid(LPCWSTR const alg_id){

		if( wcscmp(CNG_DSTU4145, alg_id)==0 ){
			return true;
		} else {
			return false;
		}
	}


	cng_asymmetric_class_op_i_ptr create_asymmetric_class( LPCWSTR const alg_id )
	{
		if( wcscmp(CNG_DSTU4145, alg_id)==0 ){
			return cng_asymmetric_class_op_i_ptr( new cng_dstu4145_class() );
		} else {
			STCRYPT_THROW_EXCEPTION( exception::badalg() );
		}
	}


}
//================================================================================================================================================
