//================================================================================================================================================
// FILE: stcrypt-gost28147_89-ut.cpp
// (c) GIE 2009-12-02  16:58
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-key-gost28147_89.hpp"
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
BOOST_AUTO_TEST_CASE( stcrypt_gost28147_89__clone_simple )
{
	using namespace stcrypt;

	std::string const test_password="Secret Key";
	key_storage_base_ptr keyset_storage( new volatile_key_storage_t("TEST KEYSET") );
	boost::intrusive_ptr<csp_t> this_csp ( new stcrypt::csp_t(keyset_storage, true ));

	boost::intrusive_ptr<hash_impl_base_t> hashed_key = this_csp->create_hash_gost_34311();
	BOOST_CHECK( hashed_key.get() );
	BOOST_CHECK_NO_THROW( hashed_key->hash_data( reinterpret_cast<BYTE const*>( test_password.c_str() ), test_password.size()) );

	key_base_ptr key1;
	key_base_ptr key1_clone;
	BOOST_CHECK_NO_THROW( key1=this_csp->derive_key(CALG_ID_G28147_89_SIMPLE,0,hashed_key) );
	BOOST_CHECK(key1.get());
	key1_clone = key1->clone();
	BOOST_CHECK(key1_clone.get());

}



BOOST_AUTO_TEST_CASE( stcrypt_gost28147_89__clone_gamma )
{
	using namespace stcrypt;

	std::string const test_password="Secret Key";
	key_storage_base_ptr keyset_storage( new volatile_key_storage_t("TEST KEYSET") );
	boost::intrusive_ptr<csp_t> this_csp ( new stcrypt::csp_t(keyset_storage, true ));

	boost::intrusive_ptr<hash_impl_base_t> hashed_key = this_csp->create_hash_gost_34311();
	BOOST_CHECK( hashed_key.get() );
	BOOST_CHECK_NO_THROW( hashed_key->hash_data( reinterpret_cast<BYTE const*>( test_password.c_str() ), test_password.size()) );

	key_base_ptr key1;
	key_base_ptr key1_clone;
	BOOST_CHECK_NO_THROW( key1=this_csp->derive_key(CALG_ID_G28147_89_GAMMA_CBC,0,hashed_key) );
	BOOST_CHECK(key1.get());
	key1_clone = key1->clone();
	BOOST_CHECK(key1_clone.get());

}

BOOST_AUTO_TEST_CASE( stcrypt_gost28147_89__encrypt_GAMMA_CBC )
{
	using namespace stcrypt;

	BYTE const cookie=0xAA;
	std::string const test_password="Secret Key";
	std::string const test_data1="01234567";
	std::string const test_data2="Data!";
	std::string const test_data = test_data1+test_data2;

	std::vector<BYTE> const ecnrypted_reference_value = boost::assign::list_of(168)(227)(72)(235)(2)(30)(88)(199)(143)(239)(0)(194)(62);

	std::vector<BYTE> data_r1;
	std::vector<BYTE> data_r2;
	std::string data_r3;
	std::string data_r4;

	key_storage_base_ptr keyset_storage( new volatile_key_storage_t("TEST KEYSET") );
	boost::intrusive_ptr<csp_t> this_csp ( new stcrypt::csp_t(keyset_storage, true ));

	boost::intrusive_ptr<hash_impl_base_t> hashed_key = this_csp->create_hash_gost_34311();
	BOOST_CHECK( hashed_key.get() );
	BOOST_CHECK_NO_THROW( hashed_key->hash_data( reinterpret_cast<BYTE const*>( test_password.c_str() ), test_password.size()) );

	{
		key_base_ptr key1;
		BOOST_CHECK_NO_THROW( key1=this_csp->derive_key(CALG_ID_G28147_89_GAMMA_CBC,0,hashed_key) );

		{ // data_r1
			data_r1.assign(test_data1.begin(), test_data1.end());
			size_t const test_data_size = data_r1.size();
			data_r1.resize(test_data_size+1);
			data_r1[test_data_size]=cookie;

			BOOST_CHECK_NO_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_encrypt( reinterpret_cast<BYTE *const>(&data_r1[0]), test_data_size, test_data_size, 0, false) );
			std::vector<BYTE> res_state(data_r1);
			BOOST_CHECK_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_encrypt( reinterpret_cast<BYTE *const>(&data_r1[0]), test_data_size, test_data_size-1, 0, false), exception::bad_len );
			BOOST_CHECK_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_encrypt( reinterpret_cast<BYTE *const>(&data_r1[0]), test_data_size-1, test_data_size-1, 0, false), exception::bad_data );
			BOOST_CHECK_MESSAGE(res_state == data_r1, "Buffer modified when it should not");
			BOOST_CHECK_EQUAL(data_r1[test_data_size], cookie);
			data_r1.resize(test_data_size);
		}
		{
			std::vector<BYTE> tmp_buffer(test_data2.begin(), test_data2.end());
			size_t const test_data_size = tmp_buffer.size();
			tmp_buffer.resize(test_data_size+1);
			tmp_buffer[test_data_size]=cookie;
			BOOST_CHECK_NO_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_encrypt( reinterpret_cast<BYTE *const>(&tmp_buffer[0]), test_data_size, test_data_size, 0, true) );
			BOOST_CHECK_EQUAL(tmp_buffer[test_data_size], cookie);
			tmp_buffer.resize(test_data_size);
			std::copy(tmp_buffer.begin(), tmp_buffer.end(), std::back_inserter(data_r1));

		}
	}

	{ // data_r2
		key_base_ptr key1;
		BOOST_CHECK_NO_THROW( key1=this_csp->derive_key(CALG_ID_G28147_89_GAMMA_CBC,0,hashed_key) );

		data_r2.assign(test_data.begin(), test_data.end());
		size_t const test_data_size = data_r2.size();
		data_r2.resize(test_data_size+1);
		data_r2[test_data_size]=cookie;

		BOOST_CHECK_NO_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_encrypt( reinterpret_cast<BYTE *const>(&data_r2[0]), test_data_size, test_data_size, 0, true) );
		BOOST_CHECK_EQUAL(data_r2[test_data_size], cookie);
		data_r2.resize(test_data_size);


	}

	BOOST_CHECK_MESSAGE(ecnrypted_reference_value == data_r1, "ciphertext differs (chunked)");
	BOOST_CHECK_MESSAGE(ecnrypted_reference_value == data_r2, "ciphertext differs");

	{ // data_r3 (decode from data_r1)
		key_base_ptr key1;
		BOOST_CHECK_NO_THROW( key1=this_csp->derive_key(CALG_ID_G28147_89_GAMMA_CBC,0,hashed_key) );
		{//chunk 1

			std::vector<BYTE> tmp_buffer;

			tmp_buffer.assign(data_r1.begin(), data_r1.begin()+test_data1.size());
			size_t const test_data_size = tmp_buffer.size();
			tmp_buffer.resize(test_data_size+1);
			tmp_buffer[test_data_size]=cookie;

			BOOST_CHECK_NO_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_decrypt( reinterpret_cast<BYTE *const>(&tmp_buffer[0]), test_data_size, test_data_size, 0, false) );
			std::vector<BYTE> res_state(tmp_buffer);
			BOOST_CHECK_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_decrypt( reinterpret_cast<BYTE *const>(&tmp_buffer[0]), test_data_size, test_data_size-1, 0, false), exception::bad_len );
			BOOST_CHECK_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_decrypt( reinterpret_cast<BYTE *const>(&tmp_buffer[0]), test_data_size-1, test_data_size-1, 0, false), exception::bad_data );
			BOOST_CHECK_MESSAGE(res_state == tmp_buffer, "Buffer modified when it should not");
			BOOST_CHECK_EQUAL(tmp_buffer[test_data_size], cookie);
			tmp_buffer.resize(test_data_size);

			data_r3.assign(tmp_buffer.begin(), tmp_buffer.end());
		
			BOOST_CHECK_MESSAGE(test_data1==data_r3, "decoded plaintext chunk 1 differs");
		}
		{//chunk 2
			std::vector<BYTE> tmp_buffer(data_r1.begin()+test_data1.size(), data_r1.end());
			size_t const test_data_size = tmp_buffer.size();
			tmp_buffer.resize(test_data_size+1);
			tmp_buffer[test_data_size]=cookie;
			BOOST_CHECK_NO_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_decrypt( reinterpret_cast<BYTE *const>(&tmp_buffer[0]), test_data_size, test_data_size, 0, true) );
			BOOST_CHECK_EQUAL(tmp_buffer[test_data_size], cookie);
			tmp_buffer.resize(test_data_size);
			std::copy(tmp_buffer.begin(), tmp_buffer.end(), std::back_inserter(data_r3));

			BOOST_CHECK_MESSAGE(test_data==data_r3, "decoded plaintext differs (chunked)");
		}
	}

	{ // data_r4
		key_base_ptr key1;
		BOOST_CHECK_NO_THROW( key1=this_csp->derive_key(CALG_ID_G28147_89_GAMMA_CBC,0,hashed_key) );

		std::vector<BYTE> tmp_buffer(data_r1.begin()+test_data1.size(), data_r1.end());
		tmp_buffer.assign(data_r1.begin(), data_r1.end());
		size_t const test_data_size = tmp_buffer.size();
		tmp_buffer.resize(test_data_size+1);
		tmp_buffer[test_data_size]=cookie;

		BOOST_CHECK_NO_THROW( static_cast<cryptoapi_key_inplace_op_i*>(key1.get())->invoke_cipher_decrypt( reinterpret_cast<BYTE *const>(&tmp_buffer[0]), test_data_size, test_data_size, 0, true) );
		BOOST_CHECK_EQUAL(tmp_buffer[test_data_size], cookie);
		tmp_buffer.resize(test_data_size);

		data_r4.assign(tmp_buffer.begin(), tmp_buffer.end());

		BOOST_CHECK_MESSAGE(test_data==data_r4, "decoded plaintext differs");
	}



	

}

BOOST_AUTO_TEST_CASE( stcrypt_gost28147_89__MAC )
{
	using namespace stcrypt;
	std::string const test_data1 = "Data to be validated";
	std::string const test_data2 = "Second part of data to be validateD";
	std::string const test_data3 = "Something entirely different";
	std::string const test_data = test_data1+test_data2;
	std::string const test_password="Secret Key";

	std::vector<BYTE> const mac_reference_value = boost::assign::list_of(43)(195)(156)(32)(17)(146)(227)(113);
	std::vector<BYTE> const mac_clone_other_path_reference_value = boost::assign::list_of(112)(184)(26)(228)(218)(199)(187)(37);


	std::vector<BYTE> mac1_result;
	std::vector<BYTE> mac2_result;
	std::vector<BYTE> mac3_result;
	std::vector<BYTE> mac4_result;

	key_storage_base_ptr keyset_storage( new volatile_key_storage_t("TEST KEYSET") );
	boost::intrusive_ptr<csp_t> this_csp ( new stcrypt::csp_t(keyset_storage, true ));

	boost::intrusive_ptr<hash_impl_base_t> hashed_key = this_csp->create_hash_gost_34311();
	BOOST_CHECK( hashed_key.get() );

	BOOST_CHECK_NO_THROW( hashed_key->hash_data( reinterpret_cast<BYTE const*>( test_password.c_str() ), test_password.size()) );

	{
		key_base_ptr key = derive_gost28147_89_key_simple(this_csp.get(), hashed_key);
		BOOST_CHECK( key.get() );

		boost::intrusive_ptr<hash_impl_base_t> mac1 = create_gost_28147_mac(key);
		mac1->hash_data( reinterpret_cast<BYTE const*>(test_data.data()), test_data.size());
		mac1_result.resize( mac1->get_hash_size() );
		BOOST_CHECK_EQUAL(mac1_result.size(),gost_28147_mac_size);
		BOOST_CHECK_NO_THROW(mac1->get_hash_value(&mac1_result[0], static_cast<DWORD>(mac1_result.size())));

	}

	{
		key_base_ptr key = derive_gost28147_89_key_simple(this_csp.get(), hashed_key);
		BOOST_CHECK( key.get() );

		boost::intrusive_ptr<hash_impl_base_t> mac1 = create_gost_28147_mac(key);
		mac1->hash_data( reinterpret_cast<BYTE const*>(test_data1.data()), test_data1.size());
		mac1->hash_data( reinterpret_cast<BYTE const*>(test_data2.data()), test_data2.size());
		mac2_result.resize( mac1->get_hash_size() );
		BOOST_CHECK_EQUAL(mac2_result.size(),gost_28147_mac_size);
		BOOST_CHECK_NO_THROW(mac1->get_hash_value(&mac2_result[0], static_cast<DWORD>(mac2_result.size())));
	}

	{
		key_base_ptr key = derive_gost28147_89_key_simple(this_csp.get(), hashed_key);
		BOOST_CHECK( key.get() );

		boost::intrusive_ptr<hash_impl_base_t> mac1 = create_gost_28147_mac(key);
		mac1->hash_data( reinterpret_cast<BYTE const*>(test_data1.data()), test_data1.size());
		boost::intrusive_ptr<hash_impl_base_t> mac2 = mac1->clone();
		mac1->hash_data( reinterpret_cast<BYTE const*>(test_data3.data()), test_data3.size());
		mac2->hash_data( reinterpret_cast<BYTE const*>(test_data2.data()), test_data2.size());
		
		mac3_result.resize( mac1->get_hash_size() );
		BOOST_CHECK_EQUAL(mac3_result.size(),gost_28147_mac_size);
		BOOST_CHECK_NO_THROW(mac1->get_hash_value(&mac3_result[0], static_cast<DWORD>(mac3_result.size())));

		mac4_result.resize( mac2->get_hash_size() );
		BOOST_CHECK_EQUAL(mac4_result.size(),gost_28147_mac_size);
		BOOST_CHECK_NO_THROW(mac2->get_hash_value(&mac4_result[0], static_cast<DWORD>(mac4_result.size())));

	}

	
	BOOST_CHECK_MESSAGE(mac_reference_value == mac1_result, "MAC differs");
	BOOST_CHECK_MESSAGE(mac_reference_value==mac2_result, "MAC differs when chunked");
	BOOST_CHECK_MESSAGE(mac_reference_value==mac4_result, "MAC differs when cloned");

	BOOST_CHECK_MESSAGE(mac_clone_other_path_reference_value==mac3_result, "MAC differs when cloned in 'other' path");

}

BOOST_AUTO_TEST_CASE( stcrypt_gost28147_89__derive_key_simple )
{

	using namespace stcrypt;

	TBLOCK256 const generated_key = {
	 0xa0, 0x87, 0x87, 0xea, 0x61, 0xfa, 0x8, 0xea, 0x88, 0x9f, 0x9b, 0x36, 0x76, 0x1c, 0xe5, 0xf9, 0xbb, 0xee, 0x3f, 0xcb, 0x55, 0x1, 0xa7, 0x38, 0xbc, 0x16, 0xb5
	 , 0x39, 0x99, 0x8f, 0x95, 0x95};


	std::string const test_password="Secret Key";


	key_storage_base_ptr keyset_storage( new volatile_key_storage_t("TEST KEYSET") );
	boost::intrusive_ptr<csp_t> this_csp ( new stcrypt::csp_t(keyset_storage, true ));

	boost::intrusive_ptr<hash_impl_base_t> hashed_key = this_csp->create_hash_gost_34311();
	BOOST_CHECK( hashed_key.get() );

	BOOST_CHECK_NO_THROW( hashed_key->hash_data( reinterpret_cast<BYTE const*>( test_password.c_str() ), test_password.size()) );


	key_base_ptr key = derive_gost28147_89_key_simple(this_csp.get(), hashed_key);
	BOOST_CHECK( key.get() );

	gost28147_89_family_key_t* key_impl = dynamic_cast<gost28147_89_family_key_t*>(key.get());
	BOOST_CHECK(key_impl);

	BOOST_CHECK( key_impl->m_key.m_key );
	BOOST_CHECK( !key_impl->m_key.m_dke );
	BOOST_CHECK( !key_impl->m_key.m_iv );

	BOOST_STATIC_ASSERT(sizeof(generated_key)==sizeof(key_impl->m_key.m_key->data) );

	BOOST_CHECK_MESSAGE( std::equal( boost::begin(key_impl->m_key.m_key->data), 
									 boost::end(key_impl->m_key.m_key->data), 
									 boost::begin(generated_key) ), 
						 "Derived key value differs from original" );

}

//================================================================================================================================================
BOOST_AUTO_TEST_SUITE_END()
//================================================================================================================================================
