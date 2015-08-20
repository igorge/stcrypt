//================================================================================================================================================
// FILE: stcrypt-dstu4145-random.cpp
// (c) GIE 2010-01-03  04:04
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "util-raii-helpers-crypt.hpp"
#include "stcrypt-dstu4145-random.hpp"

#include "boost/range/begin.hpp"
//================================================================================================================================================
namespace {

	void fill_with_system_time(TBLOCK64& d){
		FILETIME t;
		BOOST_STATIC_ASSERT(sizeof(d)==sizeof(t.dwLowDateTime)+sizeof(t.dwHighDateTime));
		BOOST_STATIC_ASSERT(sizeof(d[0])==1);
		GetSystemTimeAsFileTime(&t);
		memcpy_s( &d[0], sizeof(d), &t.dwHighDateTime, sizeof(t.dwHighDateTime));
		memcpy_s( &d[0]+sizeof(t.dwHighDateTime), sizeof(d)-sizeof(t.dwHighDateTime), 
			&t.dwLowDateTime, sizeof(t.dwLowDateTime));
	}

}
namespace stcrypt {

	void dstu4145_random_t::init_(BYTE const * const seed_bonus, size_t const seed_bonus_size){
		typedef gost_34311_impl_t::hash_type hash_type;

		TBLOCK64 d;
		TBLOCK64 s;
		//TGOSTDKE dke;
		TBLOCK256 key;
		fill_with_system_time(d);
		{
			cryptprov_ptr_t const std_prov = create_cryptprov_ptr(0,0,PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
			hash_type m1, m2;
			DWORD const process_id = GetCurrentProcessId();
			STCRYPT_CHECK_MSCRYPTO( CryptGenRandom( *std_prov, sizeof(m1), &m1[0] ) );
			STCRYPT_CHECK_MSCRYPTO( CryptGenRandom( *std_prov, sizeof(m2), &m2[0] ) );

			{
				gost_34311_impl_t hasher;
				if(seed_bonus) hasher.hash_data(seed_bonus, seed_bonus_size);
				hasher.hash_data(&m1[0], sizeof(m1));
				hasher.hash_data(&d[0], sizeof(d) );
				hasher.hash_data(reinterpret_cast<BYTE const*>(&process_id), sizeof(process_id) );

				hasher.get_hash_value(key);
			}

			{
				gost_34311_impl_t hasher;
				if(seed_bonus) hasher.hash_data(seed_bonus, seed_bonus_size);
				hasher.hash_data(&m2[0], sizeof(m2));
				hasher.hash_data(&d[0], sizeof(d) );
				hasher.hash_data(reinterpret_cast<BYTE const*>(&process_id), sizeof(process_id) );

				hasher.get_hash_value(m2);

				BOOST_STATIC_ASSERT(sizeof(m1[0])==sizeof(s[0]));
				#pragma warning(disable:4996)
				std::copy( boost::begin(m2), boost::begin(m2)+sizeof(s), boost::begin(s) );
				#pragma warning(default:4996)
			}
		}

		STCRYPT_CHECK_CRYPTO( DSTU4145AcquireContext(&m_ctx) );
		STCRYPT_CHECK_CRYPTO( DSTU4145InitRng (m_ctx, &s, &d, 0/*&dke*/, &key) );
	}


	dstu4145_random_t::dstu4145_random_t()
		: m_ctx(0)
	{
		init_(0,0);
	}

	dstu4145_random_t::dstu4145_random_t(BYTE const * const seed_bonus, size_t const seed_bonus_size)
		: m_ctx(0)
	{
		init_(seed_bonus, seed_bonus_size);
	}

	void dstu4145_random_t::gen_random(BYTE * buffer, size_t const buffer_size){
		if(!buffer_size || !buffer) return;

		STCRYPT_CHECK_CRYPTO( DSTU4145GenRand(m_ctx, buffer, static_cast<DWORD>( buffer_size) ) );
	}


	dstu4145_random_t::~dstu4145_random_t(){
		 DWORD const r = DSTU4145DestroyContext(m_ctx);
		 assert(!r);
	}


}
//================================================================================================================================================
