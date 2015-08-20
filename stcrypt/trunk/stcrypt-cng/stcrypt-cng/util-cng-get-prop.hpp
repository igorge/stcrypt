//================================================================================================================================================
// FILE: util-cng-get-prop.h
// (c) GIE 2010-08-12  15:35
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_CNG_GET_PROP_2010_08_12_15_35
#define H_GUARD_UTIL_CNG_GET_PROP_2010_08_12_15_35
//================================================================================================================================================
#pragma once
//================================================================================================================================================
namespace stcrypt {

	
	// prop_val_size -- on success, store returned property data size
	template <class CopyDataFunc>
	ULONG cng_get_prop_impl(ULONG const actual_data_size, PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, CopyDataFunc const& copy_func){
		if( !prop_val_buffer || prop_val_buffer_size<actual_data_size ) {
			STCRYPT_THROW_EXCEPTION( exception::more_data() << exception::data_size_einfo(actual_data_size) );
		} else {
			copy_func(prop_val_buffer, actual_data_size);
			return actual_data_size;
		}

	}

}
//================================================================================================================================================
#endif
//================================================================================================================================================
