//================================================================================================================================================
// FILE: stcrypt-key-blob.cpp
// (c) GIE 2009-11-06  15:30
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "util-serializer.hpp"
#include "stcrypt-key-blob.hpp"

#include "boost/utility/in_place_factory.hpp"
//================================================================================================================================================
namespace stcrypt {



	template<class Archive>
	size_t serialize_size(Archive & ar,  cryptoapi_key_blob_t const& g)
	{
		return serialize_size(ar, g.m_dke)+
			   serialize_size(ar, g.m_iv)+
			   serialize_size(ar, g.m_key)
			   #ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			   +serialize_size(ar,boost::mpl::identity<unsigned int>())*2
			   #endif			   
			   ;
	}

	template<class Archive>
	void serialize_out(Archive & ar,  cryptoapi_key_blob_t const& g)
	{
		#ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			unsigned int const k1 = debug_key_cookie;
			ar << k1;
		#endif

		ar <<  g.m_dke;
		ar <<  g.m_iv;
		ar <<  g.m_key;

		#ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			ar << k1;
		#endif

	}

	template<class Archive>
	void serialize_in(Archive & ar,  cryptoapi_key_blob_t & g)
	{
		#ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			unsigned int  k1;
			ar >> k1;
			if(k1!=debug_key_cookie){
				assert(!"Bad key cookie!");
				STCRYPT_UNEXPECTED();
			}
		#endif

		ar >>  g.m_dke;
		ar >>  g.m_iv;
		ar >>  g.m_key;

		#ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			ar >> k1;
			if(k1!=debug_key_cookie){
				assert(!"Bad key cookie!");
				STCRYPT_UNEXPECTED();
			}
		#endif

	}


	size_t cryptoapi_key_blob_t::blob_size(){

		out_dummy_serializer_t out_ser;
		return serialize_size(out_ser, *this);

	}

	void cryptoapi_key_blob_t::export_blob(std::vector<BYTE>& blob){
		out_serializer(std::back_inserter(blob)) << *this;
	}

	void cryptoapi_key_blob_t::import_blob(BYTE const * const blob, size_t const blob_size){

		in_serializer(blob, blob+blob_size) >> *this;

	}


	size_t cryptoapi_key_blob_t::key_material_size_from_components(bool const fill_key, bool const fill_iv, bool fill_dke){
		size_t const key_size = sizeof(key_type);
		size_t const iv_size = sizeof(iv_type);
		size_t const dke_size = sizeof(dke_type);

		size_t const key_material_size = (fill_key?key_size:0) + (fill_iv?iv_size:0) + (fill_dke?dke_size:0);

		return  key_material_size;
	}

	void cryptoapi_key_blob_t::set_iv(BYTE const * const iv, size_t const iv_size){
		size_t const req_iv_size = sizeof(iv_type);
		if(req_iv_size!=iv_size ) STCRYPT_UNEXPECTED();
		return fill_key_data_from_key_material_(iv, iv_size, false, true, false);
	}

	void cryptoapi_key_blob_t::fill_key_data_from_key_material(std::vector<BYTE> const& key_material, bool const fill_key, bool const fill_iv, bool fill_dke){
		return fill_key_data_from_key_material_(&key_material[0], key_material.size(), fill_key, fill_iv, fill_dke);
	}

	void cryptoapi_key_blob_t::fill_key_data_from_key_material(BYTE const* const material, size_t const material_size, bool const fill_key, bool const fill_iv, bool fill_dke){
		return fill_key_data_from_key_material_(material, material_size, fill_key, fill_iv, fill_dke);
	}

	void cryptoapi_key_blob_t::fill_key_data_from_key_material_(BYTE const* const material, size_t const material_size, bool const fill_key, bool const fill_iv, bool fill_dke){
		size_t const key_size = sizeof(key_type);
		size_t const iv_size = sizeof(iv_type);
		size_t const dke_size = sizeof(dke_type);
		
		size_t const key_material_size = (fill_key?key_size:0) + (fill_iv?iv_size:0) + (fill_dke?dke_size:0);
		
		if( material_size<key_material_size ) {
			STCRYPT_UNEXPECTED();
		}

		BYTE const * pos = material;

		if( fill_key ) {
			#pragma warning(disable:4996)
			m_key=boost::in_place(); 
			BOOST_STATIC_ASSERT( sizeof(m_key->data)==key_size );
			std::copy(pos, pos+key_size, boost::begin(m_key->data) );

			pos+=key_size;
			#pragma warning(default:4996)
		}

		if( fill_iv ) {
			#pragma warning(disable:4996)
			m_iv=boost::in_place(); 
			BOOST_STATIC_ASSERT( sizeof(m_iv->data)==iv_size );
			std::copy(pos, pos+iv_size, boost::begin(m_iv->data) );

			pos+=iv_size;
			#pragma warning(default:4996)
		}

		if( fill_dke ) {
			STCRYPT_UNIMPLEMENTED();
		}
		

#ifdef STCRYPT_DEBUG
		key_type const*const debug_key = fill_key?&m_key->data:0;
		iv_type const*const debug_iv = fill_iv?&m_iv->data:0;
#endif


	}
	
}
//================================================================================================================================================
