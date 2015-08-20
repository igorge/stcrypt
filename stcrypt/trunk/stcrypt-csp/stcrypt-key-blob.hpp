//================================================================================================================================================
// FILE: stcrypt-key-blob.h
// (c) GIE 2009-11-06  15:30
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_KEY_BLOB_2009_11_06_15_30
#define H_GUARD_STCRYPT_KEY_BLOB_2009_11_06_15_30
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "CryptoLibTypes.h"

#include "stcrypt-debug.hpp"
#include "stcrypt-exceptions.hpp"

#include "boost/optional.hpp"
#include "boost/range.hpp"
#include "boost/limits.hpp"

#include <vector>
//================================================================================================================================================
namespace stcrypt {

	namespace impl {
		template <class T> struct holder {
			typedef T value_type;

#ifdef STCRYPT_DEBUG
			holder():STCRYPT_DEBUG_magic1(0xAAAAAAAA), STCRYPT_DEBUG_magic2(0xAAAAAAAA){}
			~holder(){ assert(STCRYPT_DEBUG_magic1==0xAAAAAAAA);assert(STCRYPT_DEBUG_magic2==0xAAAAAAAA);}
#else
			holder(){}
#endif

#ifdef STCRYPT_DEBUG
			unsigned int STCRYPT_DEBUG_magic1;
#endif

			T data;
#ifdef STCRYPT_DEBUG
			unsigned int STCRYPT_DEBUG_magic2;
#endif

		};

		template<class Archive, class T>
		size_t serialize_size(Archive & ar,  holder<T> const& g)
		{
			return serialize_size(ar, g.data);
		}

		template<class Archive, class T>
		void serialize_out(Archive & ar,  holder<T> const& g)
		{
			ar <<  g.data;
		}

		template<class Archive, class T>
		void serialize_in(Archive & ar,  holder<T> & g)
		{
			ar >>  g.data;
		}

	}

	struct cryptoapi_key_blob_t {
		typedef unsigned char size_makrker_type;

		typedef TGOSTDKE	dke_type;
		typedef TBLOCK64    iv_type;
		typedef TBLOCK256	key_type;


		boost::optional< impl::holder<dke_type> >	m_dke;
		boost::optional< impl::holder<iv_type> >	m_iv;
		boost::optional< impl::holder<key_type> >	m_key;
		size_t blob_size();
		void export_blob(std::vector<BYTE>& blob);;
		void import_blob(BYTE const * const blob, size_t const blob_size);

		void set_iv(BYTE const * const iv, size_t const);

		static size_t key_component_size(){ return sizeof(key_type); }

		static size_t key_material_size_from_components(bool const fill_key=true, bool const fill_iv=true, bool fill_dke=true);
		void fill_key_data_from_key_material(std::vector<BYTE> const& key_material, bool const fill_key=true, bool const fill_iv=true, bool fill_dke=true);
		void fill_key_data_from_key_material(BYTE const* const material, size_t const material_size, bool const fill_key=true, bool const fill_iv=true, bool fill_dke=true);
	private:
		void fill_key_data_from_key_material_(BYTE const* const material, size_t const material_size, bool const fill_key=true, bool const fill_iv=true, bool fill_dke=true);

	};

}

//================================================================================================================================================
#endif
//================================================================================================================================================
