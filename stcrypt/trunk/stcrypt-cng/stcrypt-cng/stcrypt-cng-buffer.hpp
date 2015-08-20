//================================================================================================================================================
// FILE: stcrypt-cng-buffer.h
// (c) GIE 2011-02-07  17:10
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_BUFFER_2011_02_07_17_10
#define H_GUARD_STCRYPT_CNG_BUFFER_2011_02_07_17_10
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"

#include <boost/noncopyable.hpp>

#include <stdlib.h>
#include <malloc.h>
#include <assert.h>
//================================================================================================================================================
namespace stcrypt { 
	
	struct buffer_t : boost::noncopyable {

		explicit buffer_t(size_t const size) : m_buffer( malloc(size) ), m_size(size) {
			if( !m_buffer ) STCRYPT_THROW_EXCEPTION( std::bad_alloc() );
		}


		buffer_t(buffer_t&& other){
			this->m_buffer = other.m_buffer;
			this->m_size = other.m_size;

			other.zero_out_();
		}

		buffer_t& operator=(buffer_t&& other){
			assert(this!=&other);

			this->free_();

			this->m_buffer = other.m_buffer;
			this->m_size = other.m_size;
		}

		~buffer_t(){
			try{
				this->free_();
			}catch(...){
				STCRYPT_UNEXPECTED_IN_DTOR();
			}
		}

		static void free(void * const ptr){
			::free(ptr);
		}

		void* data(){ return m_buffer; }

		void* release(){
			auto const r = this->data();
			this->zero_out_();
			return r;
		}

		
	private:

		void free_(){
			if(m_buffer){
				this->free(m_buffer);
			}
		}

		void zero_out_(){
			m_buffer=0;
			m_size=0;
		}

	private:
		void*	m_buffer;
		size_t	m_size;
	};

}

//================================================================================================================================================
#endif
//================================================================================================================================================
