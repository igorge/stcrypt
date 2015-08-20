//================================================================================================================================================
// FILE: stcrypt-gost34311-ut.cpp
// (c) GIE 2009-11-18  14:10
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-hash-base.hpp"
#include "stcrypt-csp-impl.hpp"

#include "CryptoLibTypes.h"
#include "boost/test/unit_test.hpp"
#include "boost/range.hpp"
//================================================================================================================================================
BOOST_AUTO_TEST_SUITE( stcrypt_gost34311 )

BOOST_AUTO_TEST_CASE( stcrypt_gost34311__hash_test )
{

	using namespace stcrypt;

	std::string const data="Test  data to hash";
	unsigned char const data_hash[]={
	0x6f,0x94,0xf1,0xc8,0x1d,0xb1,0x74,0xbf,0x6d,0xe3,0x8b,0x7e,0xb1,0x13,0xb1,0xe0,
		0xb8,0x4c,0xbd,0x7f,0xac,0x44,0x3e,0x7e,0x82,0x86,0x84,0xd,0x2c,0x6c,0x76,0xac};

	TBLOCK256 data_hashed;

	BOOST_STATIC_ASSERT(sizeof(data_hashed)==sizeof(data_hash));

	key_storage_base_ptr keyset_storage( new volatile_key_storage_t("TEST KEYSET") );

	boost::intrusive_ptr<csp_t> this_csp ( new stcrypt::csp_t(keyset_storage, true) );

	boost::intrusive_ptr<hash_impl_base_t> this_hash = this_csp->create_hash_gost_34311();
	BOOST_CHECK( this_hash.get() );

	BOOST_CHECK_EQUAL( this_hash->get_alg_id(), CALG_ID_HASH_G34311 );

	BOOST_CHECK_EQUAL( this_hash->get_hash_size(), sizeof(TBLOCK256) );
	BOOST_CHECK_NO_THROW( this_hash->hash_data( reinterpret_cast<BYTE const*>( data.data() ), data.size()) );

	BOOST_CHECK_NO_THROW( this_hash->get_hash_value(&data_hashed[0], sizeof(data_hashed)) );
	BOOST_CHECK_MESSAGE( std::equal( boost::begin(data_hash), boost::end(data_hash), boost::begin(data_hashed) ), "Calculated hash value differs from original" );

	BOOST_CHECK_THROW( this_hash->hash_data( reinterpret_cast<BYTE const*>( data.data() ), data.size()), exception::hash_finilized );

	BOOST_CHECK_NO_THROW( this_hash->get_hash_value(&data_hashed[0], sizeof(data_hashed)) );
	BOOST_CHECK_MESSAGE( std::equal( boost::begin(data_hash), boost::end(data_hash), boost::begin(data_hashed) ), "Calculated hash value differs from original" );

}
//================================================================================================================================================
BOOST_AUTO_TEST_SUITE_END()
//================================================================================================================================================
