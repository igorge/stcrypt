//================================================================================================================================================
// FILE: stcrypt-key-factory.h
// (c) GIE 2009-11-06  15:43
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_KEY_FACTORY_2009_11_06_15_43
#define H_GUARD_STCRYPT_KEY_FACTORY_2009_11_06_15_43
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-hash-base.hpp"
#include "stcrypt-key-base.hpp"
#include "stcrypt-crypto-alg-ids.h"

#include <wincrypt.h>
//================================================================================================================================================
namespace stcrypt {
//================================================================================================================================================
// factory function(s)
//================================================================================================================================================
	struct csp_t;

	key_base_ptr derive_gost28147_89_key_simple(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key);
	key_base_ptr derive_gost28147_89_key_gamma(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key);
	key_base_ptr derive_gost28147_89_key_gamma_cbc(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key);

	key_base_ptr key_from_blob_gost28147_89_key_simple(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size);
	key_base_ptr key_from_blob_gost28147_89_key_gamma(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size);
	key_base_ptr key_from_blob_gost28147_89_key_gamma_cbc(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size);

	key_base_ptr generate_gost28147_89_key_simple(csp_t * const csp);
	key_base_ptr generate_gost28147_89_key_gamma(csp_t * const csp);
	key_base_ptr generate_gost28147_89_key_gamma_cbc(csp_t * const csp);

	key_base_ptr generate_dstu4145_sign(csp_t * const csp);
	key_base_ptr generate_dstu4145_keyx(csp_t * const csp);

	key_base_ptr key_from_blob_dstu4145_sign(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size);
	key_base_ptr key_from_blob_dstu4145_keyx(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size);



}
//================================================================================================================================================
#endif
//================================================================================================================================================
