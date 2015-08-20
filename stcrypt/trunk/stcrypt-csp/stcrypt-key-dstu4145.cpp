//================================================================================================================================================
// FILE: stcrypt-key-dstu4145.cpp
// (c) GIE 2010-01-05  18:01
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "util-serializer.hpp"
#include "stcrypt-key-dstu4145.hpp"
#include "stcrypt-csp-impl.hpp"
#include "stcrypt-debug.hpp"

#include "boost/utility/in_place_factory.hpp"
//================================================================================================================================================
namespace stcrypt {

	struct dstu_4145_key_config {
		bool m_ser_only_public;
	};

	struct dstu_4145_key_dummy_serializer
		: out_dummy_serializer_t
	{
		dstu_4145_key_dummy_serializer(dstu_4145_key_config & config)
			: m_config(config)
		{}
		dstu_4145_key_config & m_config;
	};


	template <class OutputIterator>
	struct dstu_4145_key_serializer_t
		: out_serializer_t<OutputIterator>
	{
		template <class T>
		void operator <<(T const&v){
			serialize_out(*this,v);
		}

		dstu_4145_key_serializer_t(dstu_4145_key_config & config, OutputIterator const iter)
			: out_serializer_t<OutputIterator>(iter)
			, m_config(config)
		{}
		dstu_4145_key_config & m_config;
	};

	template <class OutputIterator>
	dstu_4145_key_serializer_t<OutputIterator> dstu_4145_key_serializer(OutputIterator const& out_iter, dstu_4145_key_config & config){
		return dstu_4145_key_serializer_t<OutputIterator>(config, out_iter);
	}


	template<class Archive>
	void serialize_out(Archive & ar, dstu_4145_key_t const & g)
	{
		#ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			unsigned int const k1 = debug_key_cookie;
			ar << k1;
		#endif

		ar << g.m_std_mode;
		if(ar.m_config.m_ser_only_public){
			boost::optional<dstu_4145_key_t::private_part_type> null_priv;
			ar << null_priv;
		} else {
			ar << g.m_private_part;
		}
		ar << g.m_public_part;

		#ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			ar << k1;
		#endif

	}

	template<class Archive>
	void serialize_in(Archive & ar, dstu_4145_key_t & g)
	{
		#ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			unsigned int k1;
			ar >> k1;
			if(k1!=debug_key_cookie){
				assert(!"Bad key cookie!");
				STCRYPT_UNEXPECTED();
			}

		#endif

		ar >> g.m_std_mode;
		ar >> g.m_private_part;
		ar >> g.m_public_part;

		#ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			ar >> k1;
			if(k1!=debug_key_cookie){
				assert(!"Bad key cookie!");
				STCRYPT_UNEXPECTED();
			}
		#endif
	}

	template<class Archive>
	size_t serialize_size(Archive & ar, dstu_4145_key_t const & g){
		size_t ser_size =  serialize_size(ar, g.m_std_mode)+
			   serialize_size(ar, g.m_public_part)
			   #ifdef STCRYPT_DEBUG_KEYS_W_COOKIES
			   +serialize_size(ar,boost::mpl::identity<unsigned int>())*2
			   #endif			   
			   ;

		if(ar.m_config.m_ser_only_public){
			boost::optional<dstu_4145_key_t::private_part_type> null_priv;
			ser_size += serialize_size(ar, null_priv);
		} else {
			ser_size+= serialize_size(ar, g.m_private_part);
		}


		return ser_size;
	}


	

	template<class Archive>
	void serialize_out(Archive & ar, dstu_4145_key_t::public_part_type const & g)
	{
		ar << g.x;
		ar << g.y;
	}

	template<class Archive>
	void serialize_in(Archive & ar, dstu_4145_key_t::public_part_type & g)
	{
		ar >> g.x;
		ar >> g.y;
	}

	template<class Archive>
	size_t serialize_size(Archive & ar, dstu_4145_key_t::public_part_type const & g){
		return sizeof(g.x)+sizeof(g.y);
	}


	void dstu_4145_key_t::from_blob(BYTE const* const key_blob, size_t const key_blob_size){
		in_serializer(key_blob, key_blob+key_blob_size) >> *this;
	}

	size_t dstu_4145_key_t::blob_size(){
		dstu_4145_key_config config={false};
		return serialize_size( dstu_4145_key_dummy_serializer(config), *this );
	}


	void dstu_4145_key_t_to_blob_(dstu_4145_key_t&key, std::vector<BYTE>& out_cont, dstu_4145_key_config&config){

		#ifdef STCRYPT_DEBUG
			size_t const start_size = out_cont.size();
			size_t const saved_size = serialize_size( dstu_4145_key_serializer(std::back_inserter(out_cont), config), key );
		#endif

		dstu_4145_key_serializer(std::back_inserter(out_cont), config) << key;

		#ifdef STCRYPT_DEBUG
			size_t const end_size = out_cont.size();
			assert(saved_size==end_size-start_size);
		#endif

	}

	void dstu_4145_key_t::to_blob(std::vector<BYTE>& out_cont){
		dstu_4145_key_config config={false};
		dstu_4145_key_t_to_blob_(*this,out_cont, config);
	}

	size_t dstu_4145_key_t::public_part_blob_size(){
		dstu_4145_key_config config={true};
		return serialize_size( dstu_4145_key_dummy_serializer(config), *this );
	}

	void dstu_4145_key_t::public_part_to_blob(std::vector<BYTE>& out_cont){
		dstu_4145_key_config config={true};
		dstu_4145_key_t_to_blob_(*this,out_cont, config);
	}


	//================================================================================================================================================

	void dstu_4145_cryptoapi_key_t::export_key_blob(std::vector<BYTE>& key_blob){
		m_key.to_blob( key_blob );
	}
	size_t dstu_4145_cryptoapi_key_t::key_blob_size(){
		return m_key.blob_size();
	}

	dstu_4145_cryptoapi_key_t::~dstu_4145_cryptoapi_key_t(){
		try {
			if(m_cipher){
				notify_key_destroyed_i * notify_if = dynamic_cast<notify_key_destroyed_i*>(m_cipher.get());
				if( notify_if ) 
					notify_if->notify();
			}

		}catch(...){
			assert(false);
		}
	}

	dstu_4145_cryptoapi_key_t::dstu_4145_cryptoapi_key_t(dstu_4145_cryptoapi_key_t const& other, key_op::init_from_other const&)
		: cryptoapi_key_base_t(other)
		, m_key(other.m_key)
		, m_role(other.m_role)
	{

	}


	dstu_4145_cryptoapi_key_t::dstu_4145_cryptoapi_key_t(csp_t * const csp, role_type const role,  BYTE const* const key_blob, size_t const key_blob_size, key_op::load_from_blob const&)
		: cryptoapi_key_base_t(csp)
		, m_role(role)
	{
		m_key.from_blob(key_blob, key_blob_size);
	}


	dstu_4145_cryptoapi_key_t::dstu_4145_cryptoapi_key_t(csp_t * const csp, role_type const role,  key_op::generate const&)
		: cryptoapi_key_base_t(csp)
		, m_role(role)
	{
		CL_CONTEXT ctx=0;
		STCRYPT_CHECK_CRYPTO(DSTU4145AcquireContext(&ctx));
		try{
			
			m_key.m_private_part = boost::in_place();
			m_key.m_std_mode = 9; //TODO: rationale?
			STCRYPT_CHECK_CRYPTO(DSTU4145InitStd(ctx,m_key.m_std_mode));
			STCRYPT_CHECK_CRYPTO(DSTU4145GenKeys(ctx,&(*m_key.m_private_part), &m_key.m_public_part)); 

		} catch(...) {
			STCRYPT_DEBUG_CHECK_CRYPTO(DSTU4145DestroyContext(ctx));
			throw;
		}
		STCRYPT_CHECK_CRYPTO(DSTU4145DestroyContext(ctx));
	}

	asymmetric_cipher_base_t* dstu_4145_cryptoapi_key_t::get_cipher_(){
		if( !m_cipher ) {
			m_cipher = create_dstu4145_cipher(this) ;
		}

		return m_cipher.get();
	}


	size_t dstu_4145_cryptoapi_key_t::invoke_cipher_encrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len, hash_impl_base_t * const hasher, bool const final){
		if(hasher)
			STCRYPT_UNIMPLEMENTED();
		if(!final)
			STCRYPT_UNEXPECTED();

		return get_cipher_()->encrypt(data, data_len, out_buffer, out_buffer_len);
	}

	size_t dstu_4145_cryptoapi_key_t::invoke_cipher_decrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len, hash_impl_base_t * const hasher, bool const final){
		if(hasher)
			STCRYPT_UNIMPLEMENTED();
		if(!final)
			STCRYPT_UNEXPECTED();

		return get_cipher_()->decrypt(data, data_len, out_buffer, out_buffer_len);
	}

	DWORD dstu_4145_cryptoapi_key_t::get_blocklen(){
		STCRYPT_UNIMPLEMENTED();
	}

	ALG_ID dstu_4145_cryptoapi_key_t::get_alg_id()const{
		switch (m_role){
			case role_keyx: return CALG_DSTU4145_KEYX;
			case role_sign: return CALG_DSTU4145_SIGN;
			default: STCRYPT_UNEXPECTED();
		}

	}


	std::pair<size_t,size_t> dstu_4145_cryptoapi_key_t::buffers_sizes(){
		return get_cipher_()->buffers_sizes();
	}

	void dstu_4145_cryptoapi_key_t::export_public_key_blob(std::vector<BYTE>& key_blob){
		return m_key.public_part_to_blob(key_blob);
	}

	size_t dstu_4145_cryptoapi_key_t::public_key_blob_size(){
		return m_key.public_part_blob_size();
	}



	size_t dstu_4145_cryptoapi_key_t::get_signature_size(){ 
		return get_cipher_()->sign_size();
	}

	void dstu_4145_cryptoapi_key_t::sign(BYTE const* const data, size_t const data_size, BYTE * const sign_buffer, size_t const sign_buffer_sisze){
		return get_cipher_()->sign(data, data_size, sign_buffer, sign_buffer_sisze);
	}

	bool dstu_4145_cryptoapi_key_t::verify(BYTE const* const data, size_t const data_size, BYTE const * const sign_buffer, size_t const sign_buffer_sisze){
		return get_cipher_()->verify(data, data_size, sign_buffer, sign_buffer_sisze);
	}



	//================================================================================================================================================
	key_base_ptr generate_dstu4145_sign(csp_t * const csp){
		boost::intrusive_ptr<dstu_4145_cryptoapi_key_t> key( new dstu_4145_cryptoapi_key_t(csp, dstu_4145_cryptoapi_key_t::role_sign, key_op::generate()) );
		return key;
	}

	key_base_ptr key_from_blob_dstu4145_sign(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size){
		try{
			boost::intrusive_ptr<dstu_4145_cryptoapi_key_t> key( new dstu_4145_cryptoapi_key_t(csp, dstu_4145_cryptoapi_key_t::role_sign, blob_data, blob_size, key_op::load_from_blob()) );
			return key;
		}catch(exception::serialization::root const&){
			STCRYPT_THROW_EXCEPTION(exception::bad_data());
		}
	}
	key_base_ptr key_from_blob_dstu4145_keyx(csp_t * const csp, BYTE const * const blob_data, size_t const blob_size){
		try {
			boost::intrusive_ptr<dstu_4145_cryptoapi_key_t> key( new dstu_4145_cryptoapi_key_t(csp, dstu_4145_cryptoapi_key_t::role_keyx, blob_data, blob_size, key_op::load_from_blob()) );
			return key;
		}catch(exception::serialization::root const&){
			STCRYPT_THROW_EXCEPTION(exception::bad_data());
		}
	}


	key_base_ptr generate_dstu4145_keyx(csp_t * const csp){
		boost::intrusive_ptr<dstu_4145_cryptoapi_key_t> key( new dstu_4145_cryptoapi_key_t(csp, dstu_4145_cryptoapi_key_t::role_sign, key_op::generate()) );
		return key;
	}
	//================================================================================================================================================


}
//================================================================================================================================================
