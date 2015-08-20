//================================================================================================================================================
// FILE: stcrypt-cng-dllmain-common.h
// (c) GIE 2011-02-07  16:31
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_DLLMAIN_COMMON_2011_02_07_16_31
#define H_GUARD_STCRYPT_CNG_DLLMAIN_COMMON_2011_02_07_16_31
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-crypto-alg-ids.h"

#include "stcrypt-exceptions.hpp"
//================================================================================================================================================

namespace stcrypt {

	namespace impl {

		template <class HandleType>
		void* from_handle_to_voidptr(HandleType const h){
			return reinterpret_cast<void*>( h );
		};

		inline void* from_handle_to_voidptr(void* const h){
			return h;
		};

	}

	inline
	void validate_provider_name(LPCWSTR const pszProviderName){
		if( wcscmp(pszProviderName, STCRYPT_PROVIDER_NAME_W)==0 )
			return;
		else if( wcscmp(pszProviderName, CNG_STCRYPT_KEYSTORAGE)==0 )
			return;
		else STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
	}


	template <class I, class U>
	I cng_object_from_handle(U const handle){
		auto const cng_obj = static_cast<cng_obj_ref*>( impl::from_handle_to_voidptr(handle) );
		#ifdef STCRYPT_DEBUG
			auto const cng_obj_actual_type = typeid(*cng_obj).name();
			auto const trying_to_convert_to = typeid(I).name();
		#endif
		return boost::polymorphic_downcast<I>( cng_obj );
	}



	template <class HandleType>
	void get_cng_object_property_impl(HandleType const hObject, LPCWSTR pszProperty, PUCHAR   pbOutput,	ULONG   cbOutput,	ULONG   *pcbResult, ULONG   dwFlags)
	{

			CSP_LOG_TRACE

			if(!hObject) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
			if(!pszProperty) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
			//if(!pbOutput) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );	// pbOutput can be null -- return data size;
			if(!pcbResult) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

			STCRYPT_LOG_PRINT_W_EX(L"PROP: ", pszProperty);

			auto const cng_base_object = cng_object_from_handle<cng_obj_ref*>( hObject );
			auto const cng_object = dynamic_cast<cng_prop_op_i*>( cng_base_object );
			
			if(!cng_object) STCRYPT_THROW_EXCEPTION( exception::invalid_cng_handle_op() );

			try{
				cng_object->get_prop(pszProperty, pbOutput, cbOutput, *pcbResult, dwFlags);
			} catch( stcrypt::exception::more_data const& e ) {
				auto const * const required_buffer = boost::get_error_info<stcrypt::exception::data_size_einfo>(e);
				if( !required_buffer ) STCRYPT_UNEXPECTED();
				*pcbResult = *required_buffer;
			}
	}


	template <class U, class I>
	U cast_cng_to_handle(I const iface){
		return static_cast<cng_obj_ref*>( iface );
	}

	template <class HandleType>
	void set_cng_object_property(HandleType const hObject, LPCWSTR const pszProperty, PUCHAR const pbInput, ULONG  const cbInput, ULONG const dwFlags)
	{
			CSP_LOG_TRACE

			if(!hObject) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter_handle() );
			if(!pszProperty) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );
			if(!pbInput) STCRYPT_THROW_EXCEPTION( stcrypt::exception::invalid_parameter() );

			STCRYPT_LOG_PRINT_W_EX(L"PROP: ", pszProperty);

			auto const cng_base_object = cng_object_from_handle<cng_obj_ref*>( hObject );
			auto const cng_object = dynamic_cast<cng_prop_op_i*>( cng_base_object );

			if(!cng_object) STCRYPT_THROW_EXCEPTION( exception::invalid_cng_handle_op() );

			cng_object->set_prop(pszProperty, pbInput, cbInput, dwFlags);

	}

}
//================================================================================================================================================
#endif
//================================================================================================================================================
