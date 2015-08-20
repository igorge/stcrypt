//================================================================================================================================================
// FILE: stcrypt-hash-base.h
// (c) GIE 2009-11-03  19:06
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_HASH_BASE_2009_11_03_19_06
#define H_GUARD_STCRYPT_HASH_BASE_2009_11_03_19_06
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "util-capi-get-param-impl.hpp"
#include "stcrypt-exceptions.hpp"
#include "util-atomic-counter.hpp"

#include "boost/noncopyable.hpp"
#include "boost/bind.hpp"
#include "boost/intrusive_ptr.hpp"

#include <WinCrypt.h>
//================================================================================================================================================
namespace stcrypt {

	struct hash_impl_base_t
		: boost::noncopyable
		, atomic_counter_def_impl_t
	{

		virtual void hash_data(BYTE const * const data, size_t const len)=0;
	    virtual DWORD get_alg_id()=0;
		virtual DWORD get_hash_size()=0;
		virtual void  get_hash_value(BYTE* const data, DWORD const datalen)=0;
		virtual void  set_hash_value(BYTE const * const data)=0;
		virtual boost::intrusive_ptr<hash_impl_base_t> create_new()=0;
		virtual boost::intrusive_ptr<hash_impl_base_t> clone()=0;

		virtual void get_param(DWORD const param, BYTE* const data, DWORD * const datalen){
			assert(datalen);
			switch(param) {
				case HP_ALGID: return get_param__alg_id_(data, datalen);
				case HP_HASHSIZE: return get_param__hash_size_(data, datalen);
				case HP_HASHVAL: return get_param__hash_value_(data, datalen);
				default: STCRYPT_THROW_EXCEPTION(exception::badtype());
			}
		}

		virtual void set_param(DWORD const param, BYTE const * const data){
			switch(param) {
				case HP_HASHVAL: return set_hash_value(data);
				default: STCRYPT_THROW_EXCEPTION(exception::badtype());
			}
		}


		virtual ~hash_impl_base_t(){}
	private:
		void get_param__hash_value_(BYTE* const data, DWORD * const datalen){
			return capi_get_param_impl(get_hash_size(), data, datalen, boost::bind(&hash_impl_base_t::get_hash_value, this,_1,_2));
		}

		void get_param__alg_id_(BYTE* const data, DWORD * const datalen){
			DWORD const alg_id = get_alg_id();
			return capi_get_param_impl(sizeof(DWORD), data, datalen, boost::bind(memcpy, _1,&alg_id, _2));
		}
		void get_param__hash_size_(BYTE* const data, DWORD * const datalen){
			DWORD const hash_size = get_hash_size();
			return capi_get_param_impl(sizeof(DWORD), data, datalen, boost::bind(memcpy, _1,&hash_size, _2));
		}

	};

}
//================================================================================================================================================
#endif
//================================================================================================================================================
