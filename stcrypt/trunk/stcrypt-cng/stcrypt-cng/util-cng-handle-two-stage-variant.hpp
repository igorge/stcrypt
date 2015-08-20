//================================================================================================================================================
// FILE: util-cng-handle-two-stage-variant.h
// (c) GIE 2010-08-31  15:11
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_CNG_HANDLE_TWO_STAGE_VARIANT_2010_08_31_15_11
#define H_GUARD_UTIL_CNG_HANDLE_TWO_STAGE_VARIANT_2010_08_31_15_11
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"
#include "util-cng-obj-ref.hpp"
#include "strcypt-cng-provider.hpp"

#include <boost/intrusive_ptr.hpp>
#include <boost/mpl/identity.hpp>
#include <boost/cast.hpp>
//================================================================================================================================================
namespace stcrypt {

	template <class I1, class I2>
	struct cng_handle_varian_t
		: cng_obj_ref
		, cng_prop_op_i
	{
		virtual void destroy_self(){delete this;}

		template <class I>
		I* get(){ return this->get_( boost::mpl::identity<I>() ); }

		void set(I1 * const obj){ return this->set_i1_( obj ); };
		void set(I2 * const obj){ return this->set_i2_( obj ); };


		cng_handle_varian_t()
			: m_current( m_table_unexpected )
			, m_obj( 0 )
		{}

		explicit cng_handle_varian_t(boost::intrusive_ptr<I1>&& obj)
			: m_obj( std::move(obj) )
			, m_current( m_table_class )
		{}

		explicit cng_handle_varian_t(boost::intrusive_ptr<I2>&& obj)
			: m_obj( std::move(obj) )
			, m_current( m_table_object )
		{}

		~cng_handle_varian_t()
		{
		}

		virtual void set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags){
			auto const prop_iface = dynamic_cast<cng_prop_op_i*>( m_obj.get() );
			if( !prop_iface ) STCRYPT_THROW_EXCEPTION( exception::invalid_handle() );
			
			return prop_iface->set_prop(prop_name, prop_val, prop_val_size, flags);
		}
		
		virtual void get_prop(LPCWSTR const prop_name, PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags){
			auto const prop_iface = dynamic_cast<cng_prop_op_i*>( m_obj.get() );
			if( !prop_iface ) STCRYPT_THROW_EXCEPTION( exception::invalid_handle() );

			return prop_iface->get_prop(prop_name, prop_val_buffer, prop_val_buffer_size, prop_val_size, flags);
		}

	private:

		void set_i1_(I1 * const obj){
			m_obj.reset();
			m_current = m_table_unexpected;
			m_obj = obj;
			m_current = m_table_class;
		}

		void set_i2_(I2 * const obj){
			m_obj.reset();
			m_current = m_table_unexpected;
			m_obj = obj;
			m_current = m_table_object;
		}

		I1* get_i1(){
			return (this->*m_current.m_get_class)();
		}
		I2* get_i2(){
			return (this->*m_current.m_get_object)();
		}

		I1* get_(boost::mpl::identity<I1> const){
			return get_i1();
		}

		I2* get_(boost::mpl::identity<I2> const){
			return get_i2();
		}


	private:
		I1* get_class_unexpected_(){STCRYPT_UNEXPECTED();	}
		I2* get_object_unexpected_(){STCRYPT_UNEXPECTED();}

		I1* get_class__t_class_(){ return boost::polymorphic_downcast<I1*>( m_obj.get() ); }
		I2* get_object__t_class_(){ STCRYPT_THROW_EXCEPTION( exception::bad_key() ); }

		I1* get_class__t_object_(){ STCRYPT_THROW_EXCEPTION( exception::bad_key() ); }
		I2* get_object__t_object_(){ return boost::polymorphic_downcast<I2*>( m_obj.get() ); }


		typedef I1* (cng_handle_varian_t<I1,I2>::* get_class_func_t)();
		typedef I2* (cng_handle_varian_t<I1,I2>::* get_object_func_t)();

		struct dispatch_table_t {
			get_class_func_t	m_get_class;
			get_object_func_t	m_get_object;
		};

		dispatch_table_t m_current;
		boost::intrusive_ptr<cng_obj_ref>	 m_obj;

		static dispatch_table_t	m_table_unexpected;
		static dispatch_table_t	m_table_class;
		static dispatch_table_t	m_table_object;
	};


	template <class I1, class I2>
	typename cng_handle_varian_t<I1,I2>::dispatch_table_t cng_handle_varian_t<I1,I2>::m_table_unexpected = {
		&cng_handle_varian_t<I1,I2>::get_class_unexpected_, 
		&cng_handle_varian_t<I1,I2>::get_object_unexpected_, 
	};

	template <class I1, class I2>
	typename cng_handle_varian_t<I1,I2>::dispatch_table_t cng_handle_varian_t<I1,I2>::m_table_class = {
		&cng_handle_varian_t<I1,I2>::get_class__t_class_, 
		&cng_handle_varian_t<I1,I2>::get_object__t_class_, 
	};

	template <class I1, class I2>
	typename cng_handle_varian_t<I1,I2>::dispatch_table_t cng_handle_varian_t<I1,I2>::m_table_object = {
		&cng_handle_varian_t<I1,I2>::get_class__t_object_, 
		&cng_handle_varian_t<I1,I2>::get_object__t_object_, 
	};



}
//================================================================================================================================================
#endif
//================================================================================================================================================
