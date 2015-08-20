//================================================================================================================================================
// FILE: stcrypt-gost3411.h
// (c) GIE 2009-11-03  18:12
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_GOST3411_2009_11_03_18_12
#define H_GUARD_STCRYPT_GOST3411_2009_11_03_18_12
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-gost3411-impl.hpp"
#include "stcrypt-hash-base.hpp"
//#include "stcrypt-csp-impl.hpp"
//================================================================================================================================================
#include "stcrypt-cryptolib.hpp"

#include "boost/optional.hpp"
//================================================================================================================================================
namespace stcrypt {
//================================================================================================================================================

	struct csp_t;

	struct hash_gost_34311_t 
		: hash_impl_base_t
	{
		typedef gost_34311_impl_t::hash_type hash_type;

		hash_gost_34311_t(boost::intrusive_ptr<csp_t> const& parent_csp);
		~hash_gost_34311_t();
		void init(); //delay init modes, for now default only

		virtual void hash_data(BYTE const * const data, size_t const len);
		virtual DWORD get_alg_id();
		virtual DWORD get_hash_size();
		virtual void  get_hash_value(BYTE* const data, DWORD const datalen);
		virtual void  set_hash_value(BYTE const * const data);
		virtual boost::intrusive_ptr<hash_impl_base_t> create_new();
		virtual boost::intrusive_ptr<hash_impl_base_t> clone();

	private:
		csp_t * get_parent_csp_(){
			return m_parent_csp.get();
		}
	private:
		boost::optional<gost_34311_impl_t>	m_impl;
		boost::intrusive_ptr<csp_t>	m_parent_csp;
		bool m_finalized;
		hash_type m_hash_value;

	};


}

//================================================================================================================================================
#endif
//================================================================================================================================================
