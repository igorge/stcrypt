//================================================================================================================================================
// FILE: stcrypt-gost3411.cpp
// (c) GIE 2009-11-03  18:12
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-debug.hpp"
#include "stcrypt-gost3411.hpp"
#include "stcrypt-crypto-alg-ids.h"
#include "stcrypt-csp-impl.hpp"

#include "boost/utility/in_place_factory.hpp"
#include "boost/range/begin.hpp"
#include "boost/range/end.hpp"
//================================================================================================================================================
namespace stcrypt {

	boost::intrusive_ptr<hash_impl_base_t> hash_gost_34311_t::create_new(){
		return  boost::intrusive_ptr<hash_impl_base_t>( new hash_gost_34311_t(m_parent_csp) );
	}

	boost::intrusive_ptr<hash_impl_base_t> hash_gost_34311_t::clone(){

		boost::intrusive_ptr<hash_gost_34311_t> cloned( new hash_gost_34311_t(m_parent_csp) );
		
		if(m_finalized){
			cloned->m_finalized = true;
			std::copy( boost::begin(m_hash_value), boost::end(m_hash_value), boost::begin(cloned->m_hash_value));
		} else if (m_impl) {
			cloned->init();
			cloned->m_impl->copy_state_from(*m_impl);
		}

		return cloned;

	}


	void hash_gost_34311_t::hash_data(BYTE const * const data, size_t const len)
	{
		if(m_finalized) STCRYPT_THROW_EXCEPTION(exception::hash_finilized());
		init();
		
		assert( m_impl );
		return m_impl->hash_data(data, len);
	}

	void hash_gost_34311_t::init()
	{
		if( m_impl ) return;

		m_impl = boost::in_place();		
	}

	void  hash_gost_34311_t::get_hash_value(BYTE* const data, DWORD const datalen)
	{
		assert(datalen==sizeof(hash_type));
		
		if(!m_finalized) {
			assert(m_impl);
			m_impl->get_hash_value(m_hash_value);
			m_impl.reset();
			m_finalized = true;
		}

		memcpy(data, &m_hash_value, sizeof(hash_type));
	}

	void  hash_gost_34311_t::set_hash_value(BYTE const * const data){
		m_impl.reset();
		m_finalized = true;
		memcpy(&m_hash_value, data, get_hash_size());
	}


	DWORD hash_gost_34311_t::get_alg_id()
	{
		return CALG_ID_HASH_G34311;
	}

	DWORD hash_gost_34311_t::get_hash_size()
	{
		return sizeof(hash_type);
	}



	hash_gost_34311_t::hash_gost_34311_t(boost::intrusive_ptr<csp_t> const& parent_csp)
		: m_parent_csp( parent_csp )
		, m_finalized( false )
	{
	}


	hash_gost_34311_t::~hash_gost_34311_t()
	{
		STCRYPT_TRACE_CALL
	}

}
//================================================================================================================================================
