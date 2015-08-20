//================================================================================================================================================
// FILE: stcrypt-gost3411-impl.h
// (c) GIE 2010-01-03  16:48
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_GOST3411_IMPL_2010_01_03_16_48
#define H_GUARD_STCRYPT_GOST3411_IMPL_2010_01_03_16_48
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "GOST_34311_95.h"

#include "stcrypt-cryptolib.hpp"
#include "stcrypt-debug.hpp"

#include "boost/noncopyable.hpp"
//================================================================================================================================================
namespace stcrypt {


	struct gost_34311_impl_t 
		: boost::noncopyable
	{

		typedef TBLOCK256 hash_type;

		gost_34311_impl_t(){

#ifdef STCRYPT_DEBUG
			m_finalized=false;
#endif

			//STCRYPT_CHECK_CRYPTO( GOST34311AcquireContext(&m_ctx) );
			//STCRYPT_CHECK_CRYPTO( GOST34311Init(m_ctx, 0 /*DKE*/, 0 /*iv*/) );
			m_alg.Init(0 /*DKE*/, 0 /*iv*/);
		}

		~gost_34311_impl_t(){
// 			if(DestroyContext(m_ctx)!=0)
// 			{
// 				assert(!"failed to release context");
// 			}
		}

		void hash_data(BYTE const * const data, size_t const len){
			#ifdef STCRYPT_DEBUG
				assert(!m_finalized);
			#endif

			//STCRYPT_CHECK_CRYPTO( GOST34311ProcessBuffer(m_ctx, const_cast<void*>(reinterpret_cast<void const *>( data )), static_cast<DWORD>( len ) ) );
			m_alg.ProcessBuffer(const_cast<void*>(reinterpret_cast<void const *>( data )), static_cast<DWORD>( len ));
		}

		void get_hash_value(hash_type& hash_value){
			#ifdef STCRYPT_DEBUG
				assert(!m_finalized);
			#endif

			//STCRYPT_CHECK_CRYPTO(GOST34311Final(m_ctx, &hash_value));
			m_alg.Final(&hash_value);

			#ifdef STCRYPT_DEBUG
				m_finalized=true;
			#endif

		}

		void copy_state_from(gost_34311_impl_t const& other){
			#ifdef STCRYPT_DEBUG
				assert(!m_finalized);
			#endif

			m_alg.copy_state_from(other.m_alg);
		}
			

	private:
		//cryptolib_context_t	m_ctx;
		Gost34311 m_alg;
#ifdef STCRYPT_DEBUG
		bool m_finalized;
#endif
	};


}
//================================================================================================================================================
#endif
//================================================================================================================================================
