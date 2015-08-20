//================================================================================================================================================
// FILE: stcrypt-key.cpp
// (c) GIE 2009-11-06  13:59
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "util-serializer.hpp" //need exceptions defs
#include "stcrypt-dstu4145-random.hpp"
#include "stcrypt-gost28147_89.hpp"
#include "stcrypt-csp-impl.hpp"
#include "stcrypt-key-gost28147_89.hpp"
//================================================================================================================================================
namespace stcrypt {


	//================================================================================================================================================
	void gost28147_89_family_key_t::export_key_blob(std::vector<BYTE>& key_blob){
		return m_key.export_blob(key_blob);
	}


	size_t gost28147_89_family_key_t::key_blob_size(){
		return m_key.blob_size();
	}

	gost28147_89_family_key_t::gost28147_89_family_key_t(csp_t * const csp,  ALG_ID const alg_id,  BYTE const * const blob_data, size_t const blob_size, key_op::load_from_blob const&)
		: cryptoapi_key_base_t(csp)
		, m_alg_id(alg_id)
		, m_op_mode(op_none)
	{
		assert(m_alg_id==CALG_ID_G28147_89_SIMPLE || m_alg_id==CALG_ID_G28147_89_GAMMA || m_alg_id==CALG_ID_G28147_89_GAMMA_CBC);

		m_key.import_blob(blob_data, blob_size);
	}

	gost28147_89_family_key_t::gost28147_89_family_key_t(gost28147_89_family_key_t const& other)
		: cryptoapi_key_base_t(other)
		, m_alg_id(other.m_alg_id)
		, m_op_mode(op_none)
		, m_key (other.m_key)
	{
		if(other.m_cipher)
			m_cipher=other.m_cipher->clone();

	}

	


	//================================================================================================================================================

	void gost28147_89_family_key_t::set_iv(BYTE const*const iv){
		m_key.set_iv(iv, this->get_cipher_info_block_()->block_size() );
	}

	DWORD gost28147_89_family_key_t::get_blocklen(){
		return static_cast<DWORD>( this->get_cipher_info_block_()->block_size()*std::numeric_limits<BYTE>::digits );
	}

	size_t gost28147_89_family_key_t::invoke_cipher_encrypt(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
		if( m_op_mode == op_none ) {
			if(!m_cipher )
				m_cipher = this->get_cipher_info_block_()->create_encrypt();
			m_op_mode=op_encrypt;
		} else if( m_op_mode == op_encrypt ) {
		} else if( m_op_mode == op_decrypt ) {
			STCRYPT_UNEXPECTED();
		} else {
			STCRYPT_UNEXPECTED();
		}
		
		if(!data)
			return m_cipher->suggest_buffer_size(data_len);

		size_t const result = invoke_cipher_encrypt_(data, data_len, buffer_len, hasher, final);

		if(final){
			m_cipher.reset();
			m_op_mode = op_none;
		}

		return result;

	}
	size_t gost28147_89_family_key_t::invoke_cipher_decrypt(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
		if( m_op_mode == op_none ) {
			assert(!m_cipher );
			m_cipher = this->get_cipher_info_block_()->create_decrypt();
			m_op_mode=op_decrypt;
		} else if( m_op_mode == op_decrypt ) {
		} else if( m_op_mode == op_encrypt ) {
			STCRYPT_UNEXPECTED();
		} else {
			STCRYPT_UNEXPECTED();
		}

		size_t const result = invoke_cipher_decrypt_(data, data_len, buffer_len, hasher, final);

		if(final){
			m_cipher.reset();
			m_op_mode = op_none;
		}

		return result;
	}

	size_t gost28147_89_family_key_t::invoke_cipher_encrypt_(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
		assert(m_cipher);
		
		m_cipher->validate_buffer(data, data_len, buffer_len, final);
		return m_cipher->process_data(data, data_len, buffer_len, hasher, final);
	}
	size_t gost28147_89_family_key_t::invoke_cipher_decrypt_(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){
		assert(m_cipher);

		m_cipher->validate_buffer(data, data_len, buffer_len, final);
		return m_cipher->process_data(data, data_len, buffer_len, hasher, final);
	}


	size_t gost28147_89_family_key_t::copy_data_from_hash_to_key_material_(std::vector<BYTE>& hash_data, boost::intrusive_ptr<hash_impl_base_t> const& hash, std::vector<BYTE>& key_material){
		hash_data.clear();
		size_t const hash_size = hash->get_hash_size();
		hash_data.resize(hash_size);
		hash->get_hash_value(&hash_data[0], static_cast<DWORD>( hash_data.size() )  );

		key_material.reserve(key_material.size()+hash_data.size());
		std::copy(hash_data.begin(), hash_data.end(), std::back_inserter(key_material));

		return hash_data.size();
	}

	void gost28147_89_family_key_t::derive_key_material_from_hash_(size_t const required_key_material_size, std::vector<BYTE> & key_material, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key){
		assert(required_key_material_size!=0);

		key_material.clear();

		boost::intrusive_ptr<hash_impl_base_t> current_hashed_key = hashed_key;
		std::vector<BYTE> current_hash;
		size_t produced_key_material = copy_data_from_hash_to_key_material_(current_hash, current_hashed_key, key_material);

		while (produced_key_material<required_key_material_size){
			current_hashed_key = current_hashed_key->create_new();
			current_hashed_key->hash_data( &current_hash[0], current_hash.size() );

			produced_key_material += copy_data_from_hash_to_key_material_(current_hash, current_hashed_key, key_material);			
		}
	}



	//================================================================================================================================================

	boost::intrusive_ptr<cryptoapi_key_base_t> gost28147_89_simple_key_t::clone(){
		return do_clone_(this);
	}

	gost28147_89_simple_key_t::~gost28147_89_simple_key_t()
	{
		if(m_cipher_info_block) 
			m_cipher_info_block->reset_parent();
	}

	gost28147_89_simple_key_t::gost28147_89_simple_key_t(gost28147_89_simple_key_t const& other, key_op::init_from_other const&)
		: gost28147_89_family_key_t(other)
	{

	}


	gost28147_89_simple_key_t::gost28147_89_simple_key_t(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size, key_op::load_from_blob const&)
		: gost28147_89_family_key_t(csp, CALG_ID_G28147_89_SIMPLE, blob_data, blob_size, key_op::load_from_blob())
	{
		if( m_key.m_iv || !m_key.m_key )
			STCRYPT_THROW_EXCEPTION(exception::bad_key());
	}

	gost28147_89_simple_key_t::gost28147_89_simple_key_t(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key, key_op::derive const&) 
		: gost28147_89_family_key_t(csp, CALG_ID_G28147_89_SIMPLE)
	{
		size_t const key_material_size = m_key.key_material_size_from_components(true,false,false);

		std::vector<BYTE> key_material;
		derive_key_material_from_hash_(key_material_size, key_material, hashed_key);

		m_key.fill_key_data_from_key_material(key_material,true,false,false);
	}

	gost28147_89_simple_key_t::gost28147_89_simple_key_t(csp_t * const csp, key_op::generate const&) 
		: gost28147_89_family_key_t(csp, CALG_ID_G28147_89_SIMPLE)
	{
		size_t const key_material_size = m_key.key_material_size_from_components(true,false,false);
		dstu4145_random_t rnd_gen;

		std::vector<BYTE> key_material(key_material_size);
		rnd_gen.gen_random(&key_material[0], key_material.size());

		m_key.fill_key_data_from_key_material(key_material,true,false,false);
	}



 	symmetric_block_cipher_info_block_i* gost28147_89_simple_key_t::get_cipher_info_block_() { return this->get_cipher_info_block__(); }

	//================================================================================================================================================

	gost28147_89_gamma_key_t::~gost28147_89_gamma_key_t()
	{
	}

	gost28147_89_gamma_key_t::gost28147_89_gamma_key_t(gost28147_89_gamma_key_t const& other, key_op::init_from_other const&)
		: gost28147_89_family_key_t(other)
	{
	}


	boost::intrusive_ptr<cryptoapi_key_base_t> gost28147_89_gamma_key_t::clone(){
		return do_clone_(this);
	}


	gost28147_89_gamma_key_t::gost28147_89_gamma_key_t(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key, key_op::derive const&) 
		: gost28147_89_family_key_t(csp, CALG_ID_G28147_89_GAMMA)
	{
		size_t const key_material_size = m_key.key_material_size_from_components(true,true,false);

		std::vector<BYTE> key_material;
		derive_key_material_from_hash_(key_material_size, key_material, hashed_key);

		m_key.fill_key_data_from_key_material(key_material,true,true,false);
	}

	gost28147_89_gamma_key_t::gost28147_89_gamma_key_t(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size, key_op::load_from_blob const&)
		: gost28147_89_family_key_t(csp, CALG_ID_G28147_89_GAMMA, blob_data, blob_size, key_op::load_from_blob())
	{
		if( !m_key.m_iv || !m_key.m_key )
			STCRYPT_THROW_EXCEPTION(exception::bad_key());
	}


	gost28147_89_gamma_key_t::gost28147_89_gamma_key_t(csp_t * const csp, key_op::generate const&) 
		: gost28147_89_family_key_t(csp, CALG_ID_G28147_89_GAMMA)
	{
		size_t const key_material_size = m_key.key_material_size_from_components(true,true,false);

		dstu4145_random_t rnd_gen;
		std::vector<BYTE> key_material(key_material_size);
		rnd_gen.gen_random(&key_material[0], key_material.size());

		m_key.fill_key_data_from_key_material(key_material,true,true,false);
	}


 	symmetric_block_cipher_info_block_i* gost28147_89_gamma_key_t::get_cipher_info_block_() { return this->get_cipher_info_block__(); }

	//================================================================================================================================================

	boost::intrusive_ptr<cryptoapi_key_base_t> gost28147_89_gamma_cbc_key_t::clone(){
		return do_clone_(this);
	}

	gost28147_89_gamma_cbc_key_t::~gost28147_89_gamma_cbc_key_t()
	{
	}
	gost28147_89_gamma_cbc_key_t::gost28147_89_gamma_cbc_key_t(gost28147_89_gamma_cbc_key_t const& other, key_op::init_from_other const&)
		: gost28147_89_family_key_t(other)
	{
	}



	gost28147_89_gamma_cbc_key_t::gost28147_89_gamma_cbc_key_t(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key, key_op::derive const&) 
		: gost28147_89_family_key_t(csp, CALG_ID_G28147_89_GAMMA_CBC)
	{
		size_t const key_material_size = m_key.key_material_size_from_components(true,true,false);

		std::vector<BYTE> key_material;
		derive_key_material_from_hash_(key_material_size, key_material, hashed_key);

		m_key.fill_key_data_from_key_material(key_material,true,true,false);

	}


	gost28147_89_gamma_cbc_key_t::gost28147_89_gamma_cbc_key_t(csp_t * const csp, key_op::generate const&) 
		: gost28147_89_family_key_t(csp, CALG_ID_G28147_89_GAMMA_CBC)
	{
		size_t const key_material_size = m_key.key_material_size_from_components(true,true,false);

		std::vector<BYTE> key_material(key_material_size);
		dstu4145_random_t rnd_gen;
		rnd_gen.gen_random(&key_material[0], key_material.size());

		m_key.fill_key_data_from_key_material(key_material,true,true,false);

	}

	gost28147_89_gamma_cbc_key_t::gost28147_89_gamma_cbc_key_t(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size, key_op::load_from_blob const&)
		: gost28147_89_family_key_t(csp, CALG_ID_G28147_89_GAMMA_CBC, blob_data, blob_size, key_op::load_from_blob())
	{
		if( !m_key.m_iv || !m_key.m_key )
			STCRYPT_THROW_EXCEPTION(exception::bad_key());
	}




	symmetric_block_cipher_info_block_i* gost28147_89_gamma_cbc_key_t::get_cipher_info_block_() { return this->get_cipher_info_block__(); }
	//================================================================================================================================================

	//
	//simple
	//

	key_base_ptr derive_gost28147_89_key_simple(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key){
		return key_base_ptr ( new gost28147_89_simple_key_t(csp, hashed_key, key_op::derive() ) );
	}


	key_base_ptr generate_gost28147_89_key_simple(csp_t * const csp){
		return key_base_ptr ( new gost28147_89_simple_key_t(csp, key_op::generate() ) );
	}

	key_base_ptr key_from_blob_gost28147_89_key_simple(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size){
		try {
			return key_base_ptr ( new gost28147_89_simple_key_t(csp, blob_data, blob_size, key_op::load_from_blob() ) );
		}catch(exception::serialization::root const&){
			STCRYPT_THROW_EXCEPTION(exception::bad_data());
		}

	}


	//
	//gamma
	//

	key_base_ptr generate_gost28147_89_key_gamma(csp_t * const csp){
		return key_base_ptr ( new gost28147_89_gamma_key_t(csp, key_op::generate() ) );
	}

	key_base_ptr derive_gost28147_89_key_gamma(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key){
		return key_base_ptr ( new gost28147_89_gamma_key_t(csp, hashed_key, key_op::derive() ) );
	}

	key_base_ptr key_from_blob_gost28147_89_key_gamma(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size){
		try {
			return key_base_ptr ( new gost28147_89_gamma_key_t(csp, blob_data, blob_size, key_op::load_from_blob() ) );
		}catch(exception::serialization::root const&){
			STCRYPT_THROW_EXCEPTION(exception::bad_data());
		}

	}

	
	//
	//gamma cbc
	//

	key_base_ptr generate_gost28147_89_key_gamma_cbc(csp_t * const csp){
		return key_base_ptr ( new gost28147_89_gamma_cbc_key_t(csp, key_op::generate() ) );
	}

	key_base_ptr derive_gost28147_89_key_gamma_cbc(csp_t * const csp, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key){
		return key_base_ptr ( new gost28147_89_gamma_cbc_key_t(csp, hashed_key, key_op::derive() ) );
	}

	key_base_ptr key_from_blob_gost28147_89_key_gamma_cbc(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size){
		try {
			return key_base_ptr ( new gost28147_89_gamma_cbc_key_t(csp, blob_data, blob_size, key_op::load_from_blob() ) );
		}catch(exception::serialization::root const&){
			STCRYPT_THROW_EXCEPTION(exception::bad_data());
		}

	}

}
//================================================================================================================================================
