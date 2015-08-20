//================================================================================================================================================
// FILE: stcrypt-dstu4145-ut.cpp
// (c) GIE 2010-01-14  23:28
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
//#include "stcrypt-key-gost28147_89.hpp"
#include "stcrypt-hash-base.hpp"
#include "stcrypt-csp-impl.hpp"
#include "stcrypt-key-factory.hpp"

#include "boost/test/unit_test.hpp"
#include "boost/range.hpp"
#include "boost/foreach.hpp"
#include "boost/assign.hpp"

#include <iostream>
#include <vector>
//================================================================================================================================================
BOOST_AUTO_TEST_SUITE( stcrypt_gost28147_89 )
//================================================================================================================================================
size_t const gost_28147_mac_size = 8;
//================================================================================================================================================
BOOST_AUTO_TEST_CASE( stcrypt_dstu4145__key_clone )
{
	using namespace stcrypt;

	key_storage_base_ptr keyset_storage( new volatile_key_storage_t("TEST KEYSET") );
	boost::intrusive_ptr<csp_t> this_csp ( new stcrypt::csp_t(keyset_storage, true ));

	key_base_ptr key1;
	key_base_ptr key1_clone;
	BOOST_CHECK_NO_THROW( key1=this_csp->generate_key(CALG_DSTU4145_KEYX,0) );
	BOOST_CHECK(key1.get());
	key1_clone = key1->clone();
	BOOST_CHECK(key1_clone.get());

}

//================================================================================================================================================
BOOST_AUTO_TEST_SUITE_END()
//================================================================================================================================================
