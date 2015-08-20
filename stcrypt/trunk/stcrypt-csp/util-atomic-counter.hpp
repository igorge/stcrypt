//================================================================================================================================================
// FILE: util-atomic-counter.h
// (c) GIE 2009-11-02  15:52
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_ATOMIC_COUNTER_2009_11_02_15_52
#define H_GUARD_UTIL_ATOMIC_COUNTER_2009_11_02_15_52
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-debug.hpp"

#include <assert.h>
//================================================================================================================================================
#ifdef STCRYPT_DEBUG
	#define STCRYPT_DEBUG_CHECK_MAGIC(v,rv) assert(v==rv)
	#define STCRYPT_DEBUG_ZERO_MAGIC(v) v=0;
#else
	#define STCRYPT_DEBUG_CHECK_MAGIC(v,rv)
	#define STCRYPT_DEBUG_ZERO_MAGIC(v)
#endif


struct atomic_counter_impl_t
{
	typedef LONG refcnt;

protected:
	atomic_counter_impl_t(refcnt const init_value = 0)
		: m_counter( init_value )
#ifdef STCRYPT_DEBUG
		, m_STCRYPT_DEBUG_magic(0xAABBAABB)
#endif
	{}

	~atomic_counter_impl_t()
	{
		STCRYPT_DEBUG_CHECK_MAGIC(m_STCRYPT_DEBUG_magic,0xAABBAABB);
		STCRYPT_DEBUG_ZERO_MAGIC(m_STCRYPT_DEBUG_magic);
	}

	refcnt ccom_internal_inc_ref_()throw()
	{
		STCRYPT_DEBUG_CHECK_MAGIC(m_STCRYPT_DEBUG_magic,0xAABBAABB);
		return InterlockedIncrement(&m_counter);
	}

	refcnt ccom_internal_dec_ref_()throw()
	{
		STCRYPT_DEBUG_CHECK_MAGIC(m_STCRYPT_DEBUG_magic,0xAABBAABB);
		assert( m_counter );
		return InterlockedDecrement(&m_counter);
	}

	refcnt ccom_internal_inc_ref_()const throw()
	{
		STCRYPT_DEBUG_CHECK_MAGIC(m_STCRYPT_DEBUG_magic,0xAABBAABB);
		return InterlockedIncrement(&m_counter);
	}

	refcnt ccom_internal_dec_ref_()const throw()
	{
		STCRYPT_DEBUG_CHECK_MAGIC(m_STCRYPT_DEBUG_magic,0xAABBAABB);
		assert( m_counter );
		return InterlockedDecrement(&m_counter);
	}

#ifdef STCRYPT_DEBUG
	unsigned int m_STCRYPT_DEBUG_magic;
#endif

private:
	mutable LONG m_counter;
};

struct atomic_counter_def_impl_t
	: atomic_counter_impl_t
{
	refcnt add_ref() { return ccom_internal_inc_ref_(); }		
	refcnt dec_ref() { return ccom_internal_dec_ref_(); }

	virtual ~atomic_counter_def_impl_t() {}
};


inline void intrusive_ptr_add_ref(atomic_counter_def_impl_t * const p)
{
	p->add_ref();
}
inline void intrusive_ptr_release(atomic_counter_def_impl_t * const p)throw()
{
	if( p->dec_ref() ==0 ) delete p;
}

//================================================================================================================================================
#endif
//================================================================================================================================================
