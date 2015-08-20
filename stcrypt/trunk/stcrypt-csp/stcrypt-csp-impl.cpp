//================================================================================================================================================
// FILE: stcrypt-csp-impl.cpp
// (c) GIE 2009-11-02  15:49
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cryptoapi-csp-wrap.hpp"
#include "util-serializer.hpp"
#include "util-bittest.hpp"
#include "util-capi-get-param-impl.hpp"
#include "stcrypt-gost3411.hpp"
#include "stcrypt-csp-impl.hpp"
#include "boost/range.hpp"
#include "boost/function.hpp"
#include "boost/bind.hpp"
#include "boost/utility/in_place_factory.hpp"
//================================================================================================================================================
namespace {

	struct null_deleter
	{
		void operator()(void const *) const
		{
		}
	};


}

namespace stcrypt {

	//================================================================================================================================================
#define STCRYPT_SIZE_AND_STR(x) sizeof(x), x
	PROV_ENUMALGS supported_lags[]={
		{CALG_ID_HASH_G34311, 256, STCRYPT_SIZE_AND_STR("GOST-34311")},
		{CALG_ID_G28147_89_MAC, 64, STCRYPT_SIZE_AND_STR("GOST-28147-MAC")},
		{CALG_ID_G28147_89_SIMPLE, 256, STCRYPT_SIZE_AND_STR("GOST-28147S")},
		{CALG_ID_G28147_89_GAMMA, 256, STCRYPT_SIZE_AND_STR("GOST-28147G")},
		{CALG_ID_G28147_89_GAMMA_CBC, 256, STCRYPT_SIZE_AND_STR("GOST-28147GCBC")},
        {CALG_DSTU4145_KEYX, 0, STCRYPT_SIZE_AND_STR("DSTU-4145X")},
        {CALG_DSTU4145_SIGN, 0, STCRYPT_SIZE_AND_STR("DSTU-4145N")}
	};

	PROV_ENUMALGS_EX supported_algs_ex[]={
		{
				CALG_ID_HASH_G34311,
				256, //default key length
				256, //min length
				256, //max length
				0, //protocols CRYPT_FLAG_SIGNING
				STCRYPT_SIZE_AND_STR("GOST-34311"),
				STCRYPT_SIZE_AND_STR("STCRYPT GOST-34311")
		},
		{
				CALG_ID_G28147_89_MAC,
				64, //default key length
				64, //min length
				64, //max length
				0, //protocols CRYPT_FLAG_SIGNING
				STCRYPT_SIZE_AND_STR("GOST-28147-MAC"),
				STCRYPT_SIZE_AND_STR("STCRYPT GOST-28147-MAC")
		},
		{
				CALG_ID_G28147_89_SIMPLE,
				256, //default key length
				256, //min length
				256, //max length
				0, //protocols CRYPT_FLAG_SIGNING
				STCRYPT_SIZE_AND_STR("GOST-28147S"),
				STCRYPT_SIZE_AND_STR("STCRYPT GOST-28147-SIMPLE")
		},
		{
				CALG_ID_G28147_89_GAMMA,
				256, //default key length
				256, //min length
				256, //max length
				0, //protocols CRYPT_FLAG_SIGNING
				STCRYPT_SIZE_AND_STR("GOST-28147G"),
				STCRYPT_SIZE_AND_STR("STCRYPT GOST-28147-GAMMA")
		},
		{
				CALG_ID_G28147_89_GAMMA_CBC,
				256, //default key length
				256, //min length
				256, //max length
				0, //protocols CRYPT_FLAG_SIGNING
				STCRYPT_SIZE_AND_STR("GOST-28147GCBC"),
				STCRYPT_SIZE_AND_STR("STCRYPT GOST-28147-GAMMA-CBC")
		},
		{
				CALG_DSTU4145_KEYX,
				0, //default key length
				0, //min length
				0, //max length
				0, //protocols CRYPT_FLAG_SIGNING
				STCRYPT_SIZE_AND_STR("DSTU-4145X"),
				STCRYPT_SIZE_AND_STR("STCRYPT-DSTU-4145-KEYX")
		},
		{
				CALG_DSTU4145_SIGN,
				0, //default key length
				0, //min length
				0, //max length
				0, //protocols CRYPT_FLAG_SIGNING
				STCRYPT_SIZE_AND_STR("DSTU-4145N"),
				STCRYPT_SIZE_AND_STR("STCRYPT-DSTU-4145-SIGN")
		},
	};



	//================================================================================================================================================

	namespace exception {

		struct bad_output_buffer : root {};


	}

    typedef BYTE BLOB_HEADER_AS_BYTES[sizeof(BLOBHEADER)];

	struct csp_key_blob_header_t{
        BLOBHEADER m_std_header;
		ALG_ID m_alg_id;
	};

	template<class Archive>
	void serialize_out(Archive & ar, csp_key_blob_header_t const & g)
	{
        ar << *reinterpret_cast<BLOB_HEADER_AS_BYTES const*>(&g.m_std_header);
		ar << g.m_alg_id;
	}

	template<class Archive>
	void serialize_in(Archive & ar, csp_key_blob_header_t  & g)
	{
        ar >> *reinterpret_cast<BLOB_HEADER_AS_BYTES*>(&g.m_std_header);
		ar >> g.m_alg_id;
	}

	template<class Archive>
	size_t serialize_size(Archive & ar, boost::mpl::identity<csp_key_blob_header_t> const & g){
		return sizeof(BLOBHEADER)+serialize_size(ar, boost::mpl::identity<ALG_ID>());
	}

	template<class Archive>
	size_t serialize_size(Archive & ar, csp_key_blob_header_t const & g){
		return serialize_size(ar, boost::mpl::identity<csp_key_blob_header_t>() );
	}



	//================================================================================================================================================


	void csp_t::gen_random(BYTE * buffer, size_t const buffer_size){
		if( !m_generator)
			m_generator=boost::in_place(buffer, buffer_size);

		return m_generator->gen_random(buffer, buffer_size);

	}

	//================================================================================================================================================
	boost::weak_ptr<csp_t> csp_t::get_weak_ptr(){
		return boost::weak_ptr<csp_t>( m_this_for_weak_ptr );
	}

	//================================================================================================================================================
	csp_t::csp_t(key_storage_base_ptr const& key_storage, bool const is_verifycontext) 
		: m_keystorage( key_storage )
		, m_is_verifycontext( is_verifycontext )
		, m_this_for_weak_ptr(this, null_deleter())
	{
	}
	
	boost::intrusive_ptr<hash_impl_base_t> csp_t::create_hash(ALG_ID const alg_id, key_base_ptr const& key)
	{
		STCRYPT_LOG_PRINT_EX("ALGID", alg_id);

		switch(alg_id)
		{
		case CALG_SHA1:{
			cryptprov_ptr_t def_prov = create_cryptprov_ptr(0,0,PROV_RSA_FULL ,CRYPT_VERIFYCONTEXT);
			return create_sha1_hash(def_prov);
			}

		case CALG_ID_HASH_G34311 :
		case CALG_G34311_DSTU4145: /*hashing for G34311 + DSTU4145*/
			return create_hash_gost_34311();
		case CALG_ID_G28147_89_MAC:
			return create_gost_28147_mac(key);
		default:
			{STCRYPT_THROW_EXCEPTION(exception::badalg());}
		}
	}


	boost::intrusive_ptr<hash_impl_base_t> csp_t::create_hash_gost_34311()
	{
		return boost::intrusive_ptr<hash_impl_base_t>( new hash_gost_34311_t(this));
	}

	//================================================================================================================================================
	key_base_ptr	csp_t::derive_key(ALG_ID const alg_id, DWORD const flags, boost::intrusive_ptr<hash_impl_base_t> const& hashed_key){

		assert( hashed_key );

		if(test_if_any_in_mask<DWORD>(flags, CRYPT_CREATE_SALT | CRYPT_NO_SALT | CRYPT_UPDATE_KEY))
		{
			STCRYPT_THROW_EXCEPTION(exception::badflags()<<exception::flags_einfo(flags));
		}

		switch(alg_id){
			case CALG_ID_G28147_89_SIMPLE: return derive_gost28147_89_key_simple(this, hashed_key);
			case CALG_ID_G28147_89_GAMMA: return derive_gost28147_89_key_gamma(this, hashed_key);
			case CALG_ID_G28147_89_GAMMA_CBC: return derive_gost28147_89_key_gamma_cbc(this, hashed_key);
			default: STCRYPT_THROW_EXCEPTION(exception::badalg() << exception::algid_einfo(alg_id));
		}

	}
	//================================================================================================================================================
	key_base_ptr	csp_t::generate_key(ALG_ID const alg_id, DWORD const flags){

		if(test_if_any_in_mask<DWORD>(flags, CRYPT_CREATE_SALT))
		{
			STCRYPT_THROW_EXCEPTION(exception::badflags()<<exception::flags_einfo(flags));
		}

		if(test_if_any_in_mask<DWORD>(flags, CRYPT_NO_SALT ))
		{
			//STCRYPT_THROW_EXCEPTION(exception::badflags()<<exception::flags_einfo(flags));
		}

		if(test_if_any_in_mask<DWORD>(flags, CRYPT_UPDATE_KEY))
		{
			STCRYPT_THROW_EXCEPTION(exception::badflags()<<exception::flags_einfo(flags));
		}

		switch(alg_id){
			case CALG_ID_G28147_89_SIMPLE: return generate_gost28147_89_key_simple(this);
			case CALG_ID_G28147_89_GAMMA: return generate_gost28147_89_key_gamma(this);
			case CALG_ID_G28147_89_GAMMA_CBC: return generate_gost28147_89_key_gamma_cbc(this);
			case AT_KEYEXCHANGE: return generate_AT_KEYEXCHANGE_();
			case CALG_DSTU4145_KEYX: return generate_dstu4145_keyx(this);
			case AT_SIGNATURE: return generate_AT_SIGNATURE_();
			case CALG_DSTU4145_SIGN: return generate_dstu4145_sign(this);
				
			default: STCRYPT_THROW_EXCEPTION(exception::badalg() << exception::algid_einfo(alg_id));
		}
	}

	//================================================================================================================================================
	key_base_ptr csp_t::generate_AT_KEYEXCHANGE_(){
		if(is_verify_context())
			STCRYPT_THROW_EXCEPTION(exception::bad_permissions());

		key_base_ptr const key = generate_dstu4145_keyx( this );
		std::vector<BYTE> key_data;
		key->export_key_blob(key_data);
		m_keystorage->store_sign_keyx_data(key_data);

		m_key_sign = key;

		return key;
	}
	key_base_ptr csp_t::generate_AT_SIGNATURE_(){
		if(is_verify_context())
			STCRYPT_THROW_EXCEPTION(exception::bad_permissions());

		key_base_ptr const key = generate_dstu4145_sign( this );
		std::vector<BYTE> key_data;
		key->export_key_blob(key_data);
		m_keystorage->store_sign_sign_data(key_data);

		m_key_sign = key;

		return key;
	}

	key_base_ptr csp_t::get_key(DWORD const dwKeySpec){
		std::vector<BYTE> key_data;

		switch(dwKeySpec){
			case AT_SIGNATURE:
				if(!m_key_sign){
					m_keystorage->get_sign_key_data( key_data ); 
					m_key_sign= key_from_blob_dstu4145_sign(this, &key_data[0], key_data.size());
				}
				return m_key_sign;
			case AT_KEYEXCHANGE: 
				if(!m_key_keyx){
					m_keystorage->get_keyx_key_data( key_data ); 
					m_key_keyx =key_from_blob_dstu4145_keyx(this, &key_data[0], key_data.size());
				}
				return m_key_keyx;
			default: STCRYPT_THROW_EXCEPTION(exception::no_key());
		}
	}

	key_base_ptr csp_t::get_user_key(DWORD const dwKeySpec){
		return get_key(dwKeySpec);
	}

	//================================================================================================================================================
	void csp_t::set_param(DWORD const params, BYTE const * const data, DWORD const flags)
	{
		STCRYPT_UNIMPLEMENTED();
	}

	//================================================================================================================================================
	void csp_t::get_param(DWORD const param, BYTE* const data, DWORD * const datalen, DWORD const flags){
		assert(datalen);
		switch(param) {
				case PP_CONTAINER: check_null_flags_(flags); return get_param__container_name_(data, datalen);
				case PP_UNIQUE_CONTAINER: check_null_flags_(flags); return get_param__container_name_(data, datalen);
				case PP_NAME: check_null_flags_(flags); return get_param__name_(data, datalen);
				case PP_IMPTYPE: check_null_flags_(flags); return get_param__imp_type_(data, datalen);
				case PP_PROVTYPE: check_null_flags_(flags); return get_param__prov_type_(data, datalen);
				case PP_VERSION: check_null_flags_(flags); return get_param__version_(data, datalen);
				case PP_ENUMCONTAINERS:  return get_param__enum_containers_(data, datalen, flags);
				case PP_ENUMALGS:  return get_param__enum_algs_(data, datalen, flags);
				case PP_ENUMALGS_EX:  return get_param__enum_algs_ex_(data, datalen, flags);
				default: STCRYPT_THROW_EXCEPTION(exception::badtype());
		}
	}


	//================================================================================================================================================
	void csp_t_do_sign(key_base_ptr const key, BYTE const* const data_to_sign, size_t const data_to_sign_size,  BYTE*const signature_buffer,DWORD const signature_buffer_size){

		key->sign(data_to_sign, data_to_sign_size, signature_buffer, signature_buffer_size );

	}

	void csp_t::sign_hash(boost::intrusive_ptr<hash_impl_base_t> const& hash, DWORD const dwKeySpec,  LPBYTE const pbSignature, LPDWORD pcbSigLen){
		key_base_ptr const key = get_key(dwKeySpec);
		size_t const signature_size = key->get_signature_size();
		
		size_t const hash_size=hash->get_hash_size();
		std::vector<BYTE> hash_value(hash_size);
		hash->get_hash_value(&hash_value[0], static_cast<DWORD>(hash_value.size()));

		capi_get_param_impl(signature_size,pbSignature,pcbSigLen, boost::bind(csp_t_do_sign, key, &hash_value[0], hash_value.size(), _1,_2) );
	}

	void csp_t::verify_hash(boost::intrusive_ptr<hash_impl_base_t> const& hash, key_base_ptr const& key, BYTE const * const pbSignature, DWORD const cbSigLen){
		size_t const hash_size=hash->get_hash_size();
		std::vector<BYTE> hash_value(hash_size);
		hash->get_hash_value(&hash_value[0], static_cast<DWORD>(hash_value.size()));

		if(! key->verify(&hash_value[0], hash_value.size(), pbSignature, cbSigLen) )
			STCRYPT_THROW_EXCEPTION(exception::bad_signature());

	}

	void csp_t::hash_key(boost::intrusive_ptr<hash_impl_base_t> const& hash, key_base_ptr const& key){
		if( !hash )
			STCRYPT_THROW_EXCEPTION( stcrypt::exception::bad_hash() );

		if( !key )
			STCRYPT_THROW_EXCEPTION( stcrypt::exception::bad_key() );

        std::vector<BYTE> key_blob;
        key->export_key_blob( key_blob );
        hash->hash_data( &key_blob[0], key_blob.size() );


	}


	//================================================================================================================================================

	std::pair<size_t, size_t> buffers_sizes_from_input_with_granularity(size_t input_buffer_size, std::pair<size_t, size_t> const& granularity){
		unsigned int const input_buffer_size_in_blocks = static_cast<unsigned int>( (input_buffer_size/granularity.first) + (input_buffer_size%granularity.first==0?0:1) );
		return std::make_pair(input_buffer_size_in_blocks * granularity.first, input_buffer_size_in_blocks * granularity.second);

	}


	std::pair<size_t, size_t> buffers_sizes_from_output_with_granularity(size_t output_buffer_size, std::pair<size_t, size_t> const& granularity){
		if( output_buffer_size%granularity.second )
			STCRYPT_THROW_EXCEPTION(exception::bad_output_buffer());

		unsigned int const output_buffer_size_in_blocks = static_cast<unsigned int>( (output_buffer_size/granularity.second) );
		return std::make_pair<size_t, size_t>(output_buffer_size_in_blocks * granularity.first, output_buffer_size);

	}


	void csp_t_do_export_key_simpleblob(key_base_ptr const& key,key_base_ptr const& pub_key, std::pair<size_t,size_t> const& buffers_sizes, std::pair<size_t,size_t> const& full_buffers_sizes, LPBYTE const pbData,DWORD DataLen){
		std::vector<BYTE> key_blob_data;

        //non enc header
		csp_key_blob_header_t const header = { {SIMPLEBLOB, 0x02, 0,  key->get_alg_id()}, pub_key->get_alg_id()};
		size_t const header_size = serialize_size(out_dummy_serializer_t(),header);
		BYTE* header_oiter = &pbData[0];
		out_serializer( boost::make_function_output_iterator(ptr2oiter_func<BYTE>(header_oiter, &pbData[0]+header_size) ) ) << header;
		assert(header_oiter==&pbData[0]+header_size);

		key->export_key_blob(key_blob_data);
		
		if(key_blob_data.size()>full_buffers_sizes.first)
			STCRYPT_UNEXPECTED();
		
		size_t const buffer_for_enc_data = DataLen-header_size;
		if(full_buffers_sizes.second!=buffer_for_enc_data)
			STCRYPT_UNEXPECTED();

		
		key_blob_data.resize(full_buffers_sizes.first);

		BYTE* curr = &key_blob_data[0];
		BYTE const * const end = curr+key_blob_data.size();
		BYTE* out_curr  = header_oiter; //rigt after non encrypted header
		while( curr!=end ){
			assert(curr+buffers_sizes.first<=curr+key_blob_data.size());
			assert(out_curr <=out_curr+buffer_for_enc_data);

			size_t const r = static_cast<cryptoapi_key_buffer_op_i*>(pub_key.get())->invoke_cipher_encrypt(curr, buffers_sizes.first, out_curr, buffers_sizes.second, 0, true);
			assert(r==buffers_sizes.second);

			curr+=buffers_sizes.first;
			out_curr+=buffers_sizes.second;

		}

	}

	void csp_t_export_key_simpleblob(key_base_ptr const& key,key_base_ptr const& pub_key,LPBYTE const pbData,LPDWORD const pcbDataLen){
		if(!pub_key)
			STCRYPT_THROW_EXCEPTION(exception::bad_key());

		//TODO: check for CRYPT_EXPORTABLE and throw NTE_BAD_KEY_STATE

		size_t const key_blob_size = key->key_blob_size(); // part to be ecnrypted
		size_t const crypto_api_header_size = serialize_size(out_dummy_serializer_t(), boost::mpl::identity<csp_key_blob_header_t>());
		std::pair<size_t, size_t> const& buffers_sizes = pub_key->buffers_sizes();
		std::pair<size_t, size_t> const& full_buffers_sizes = buffers_sizes_from_input_with_granularity(key_blob_size, buffers_sizes );

		return capi_get_param_impl(full_buffers_sizes.second + crypto_api_header_size, pbData,pcbDataLen, boost::bind(csp_t_do_export_key_simpleblob, key, pub_key, boost::cref(buffers_sizes), boost::cref(full_buffers_sizes), _1,_2) );

	}

	void csp_t_do_export_key_privateblob(key_base_ptr const& key,key_base_ptr const& pub_key,/* std::pair<size_t,size_t> const& buffers_sizes, std::pair<size_t,size_t> const& full_buffers_sizes,*/ LPBYTE const pbData,DWORD DataLen){
		std::vector<BYTE> key_blob_data;

		//csp_key_blob_header_t const header = {key->get_alg_id()};
        csp_key_blob_header_t const header = { {PRIVATEKEYBLOB, 0x02, 0,  key->get_alg_id()}, key->get_alg_id()};
		out_serializer(std::back_inserter(key_blob_data)) << header;

		key->export_key_blob(key_blob_data);
		if(key_blob_data.size()!=DataLen){
			assert(false);
			STCRYPT_UNEXPECTED();
		}
		std::copy(key_blob_data.begin(), key_blob_data.end(), pbData);
	}


	void csp_t_export_key_privateblob(key_base_ptr const& key,key_base_ptr const& pub_key,LPBYTE const pbData,LPDWORD const pcbDataLen){
		if(pub_key)
			STCRYPT_UNIMPLEMENTED();

		//TODO: check for CRYPT_EXPORTABLE and throw NTE_BAD_KEY_STATE

		size_t const key_blob_size = key->key_blob_size() + serialize_size(out_dummy_serializer_t(), boost::mpl::identity<csp_key_blob_header_t>());
		//std::pair<size_t, size_t> const& buffers_sizes = pub_key->buffers_sizes();
		//std::pair<size_t, size_t> const& full_buffers_sizes = buffers_sizes_from_input_with_granularity(key_blob_size, buffers_sizes );

		return capi_get_param_impl( key_blob_size/*full_buffers_sizes.second*/, pbData,pcbDataLen, boost::bind(csp_t_do_export_key_privateblob, key, pub_key /*, boost::cref(buffers_sizes), boost::cref(full_buffers_sizes)*/, _1,_2) );

	}

	void csp_t_do_export_key_publicblob(key_base_ptr const& key,key_base_ptr const& pub_key,/* std::pair<size_t,size_t> const& buffers_sizes, std::pair<size_t,size_t> const& full_buffers_sizes,*/ LPBYTE const pbData,DWORD DataLen){
		std::vector<BYTE> key_blob_data;

        csp_key_blob_header_t const header = { {PUBLICKEYBLOB, 0x02, 0,  key->get_alg_id()}, key->get_alg_id()};
		out_serializer(std::back_inserter(key_blob_data)) << header;

		key->export_public_key_blob(key_blob_data);
		if(key_blob_data.size()!=DataLen){
			assert(false);
			STCRYPT_UNEXPECTED();
		}
		std::copy(key_blob_data.begin(), key_blob_data.end(), pbData);
	}



	void csp_t_export_key_publicblob(key_base_ptr const& key,key_base_ptr const& pub_key,LPBYTE const pbData,LPDWORD const pcbDataLen){
		if(pub_key)
			STCRYPT_UNIMPLEMENTED();

		//TODO: check for CRYPT_EXPORTABLE and throw NTE_BAD_KEY_STATE

		size_t const key_blob_size = key->public_key_blob_size() + serialize_size(out_dummy_serializer_t(), boost::mpl::identity<csp_key_blob_header_t>());
		//std::pair<size_t, size_t> const& buffers_sizes = pub_key->buffers_sizes();
		//std::pair<size_t, size_t> const& full_buffers_sizes = buffers_sizes_from_input_with_granularity(key_blob_size, buffers_sizes );

		return capi_get_param_impl( key_blob_size/*full_buffers_sizes.second*/, pbData,pcbDataLen, boost::bind(csp_t_do_export_key_publicblob, key, pub_key /*, boost::cref(buffers_sizes), boost::cref(full_buffers_sizes)*/, _1,_2) );

	}


	void csp_t::export_key(key_base_ptr const& key,key_base_ptr const& pub_key,DWORD const dwBlobType,DWORD const dwFlags,LPBYTE const pbData,LPDWORD const pcbDataLen){
		
		switch(dwBlobType){
			case SIMPLEBLOB: return csp_t_export_key_simpleblob(key, pub_key, pbData, pcbDataLen);
			case PRIVATEKEYBLOB: return csp_t_export_key_privateblob(key, pub_key, pbData, pcbDataLen);
			case PUBLICKEYBLOB: return csp_t_export_key_publicblob(key, pub_key, pbData, pcbDataLen);
			default: STCRYPT_THROW_EXCEPTION(exception::badtype());
		}

	}

	key_base_ptr csp_t::import_key(key_base_ptr const& pub_key,DWORD const dwFlags,BYTE const * const pbData,DWORD const DataLen){
	
		if( test_if_any_out_of_mask<DWORD>( dwFlags, CRYPT_EXPORTABLE | CRYPT_NO_SALT) ) //TODO: handle CRYPT_EXPORTABLE
 			STCRYPT_THROW_EXCEPTION(stcrypt::exception::badflags());

		
		in_serializer_t<BYTE const*, BYTE const*> in_ser(pbData, pbData+DataLen);
		csp_key_blob_header_t header;
		in_ser >> header;

		size_t const ser_header_size = serialize_size(in_ser, header);

		BYTE const*key_blob_begin=0;
		BYTE const*key_blob_end=0;
		size_t key_blob_size=0;

		std::vector<BYTE> key_blob;

		if(!pub_key) {
			key_blob_begin = pbData+ser_header_size;
			key_blob_size = DataLen - ser_header_size;
			key_blob_end = key_blob_begin + key_blob_size;

		} else { //we have public key, so decrypt blob using it

			size_t const encrypted_blob_size = DataLen - ser_header_size;
			BYTE const*const encrypted_blob = pbData +ser_header_size;

			std::pair<size_t, size_t> const& buffers_sizes = pub_key->buffers_sizes();
			std::pair<size_t, size_t> const& full_buffers_sizes = buffers_sizes_from_output_with_granularity(encrypted_blob_size, buffers_sizes );

			key_blob.resize(full_buffers_sizes.first);

			BYTE const* src_current = encrypted_blob;
			BYTE const*const src_end = src_current + encrypted_blob_size;
			BYTE * dst_current = &key_blob[0];
			BYTE * const dst_end = dst_current + key_blob.size();

			while(src_current!=src_end){
				assert(src_current+buffers_sizes.second<=src_end );
				assert(dst_current+buffers_sizes.first<=dst_end);

				size_t const r = static_cast<cryptoapi_key_buffer_op_i*>(pub_key.get())->invoke_cipher_decrypt(src_current, buffers_sizes.second, dst_current, buffers_sizes.first, 0, true);
				assert(r==buffers_sizes.first);

				src_current+=buffers_sizes.second;
				dst_current+=buffers_sizes.first;

			}

			key_blob_begin = &key_blob[0];
			key_blob_size = key_blob.size();
			key_blob_end = key_blob_begin + key_blob_size;
			
		}

		switch(header.m_std_header.aiKeyAlg){
			case CALG_ID_G28147_89_SIMPLE: return key_from_blob_gost28147_89_key_simple(this, key_blob_begin  , key_blob_size);
			case CALG_ID_G28147_89_GAMMA: return key_from_blob_gost28147_89_key_gamma(this, key_blob_begin , key_blob_size );
			case CALG_ID_G28147_89_GAMMA_CBC: return key_from_blob_gost28147_89_key_gamma_cbc(this, key_blob_begin , key_blob_size );
			case CALG_DSTU4145_SIGN: return key_from_blob_dstu4145_sign(this, key_blob_begin  , key_blob_size);
			case CALG_DSTU4145_KEYX: return key_from_blob_dstu4145_keyx(this, key_blob_begin , key_blob_size );
			default: STCRYPT_THROW_EXCEPTION( exception::badalg() );
		}

	}


	//================================================================================================================================================



	//////////////////////////////////////////////////////////////////////////
	// enum_containers_impl_type
	void csp_t::get_param__enum_containers_(BYTE* const data, DWORD * const datalen, DWORD const flags){
		return key_storage_manager_()->enum_containers(data, datalen, flags);
	}
	//////////////////////////////////////////////////////////////////////////
	// enum_algs_ex_impl_type
	void csp_t::get_param__enum_algs_ex_(BYTE* const data, DWORD * const datalen, DWORD const flags){
		return get_algs_ex_enum()->get_param__enum_impl_(data, datalen, flags);
	}

	std::pair<csp_t::enum_algs_ex_impl_type::iterator_type,csp_t::enum_algs_ex_impl_type::iterator_type> 
		csp_t::init_iters_(enum_algs_ex_impl_type::tag_type const) 
	{
		return std::make_pair( boost::begin(supported_algs_ex), boost::end(supported_algs_ex));
	}

	void csp_t::from_iter_to_item_(enum_algs_ex_impl_type::tag_type const, enum_algs_ex_impl_type::iterator_type& iter, enum_algs_ex_impl_type::item_type& item){
		item = iter;
	}

	void csp_t::copy_func_(enum_algs_ex_impl_type::tag_type const, enum_algs_ex_impl_type::item_type const& item, BYTE* const data, DWORD const datalen){
		assert(sizeof(PROV_ENUMALGS_EX)==datalen);
		memcpy(data, item, datalen);
	}
	size_t csp_t::item_size_(enum_algs_ex_impl_type::tag_type const, enum_algs_ex_impl_type::item_type const& item)const{
		return sizeof(PROV_ENUMALGS_EX);
	}

	//////////////////////////////////////////////////////////////////////////
	// enum_algs_impl_type
	void csp_t::get_param__enum_algs_(BYTE* const data, DWORD * const datalen, DWORD const flags){
		return get_algs_enum()->get_param__enum_impl_(data, datalen, flags);
	}

	std::pair<csp_t::enum_algs_impl_type::iterator_type,csp_t::enum_algs_impl_type::iterator_type> 
		csp_t::init_iters_(enum_algs_impl_type::tag_type const) 
	{
		return std::make_pair( boost::begin(supported_lags), boost::end(supported_lags));
	}

	void csp_t::from_iter_to_item_(enum_algs_impl_type::tag_type const, enum_algs_impl_type::iterator_type& iter, enum_algs_impl_type::item_type& item){
		item = iter;
	}

	void csp_t::copy_func_(enum_algs_impl_type::tag_type const, enum_algs_impl_type::item_type const& item, BYTE* const data, DWORD const datalen){
		assert(sizeof(PROV_ENUMALGS)==datalen);
		memcpy(data, item, datalen);
	}
	size_t csp_t::item_size_(enum_algs_impl_type::tag_type const, enum_algs_impl_type::item_type const& item)const{
		return sizeof(PROV_ENUMALGS);
	}
	//////////////////////////////////////////////////////////////////////////

	void csp_t::get_param__name_(BYTE* const data, DWORD * const datalen){
		char name[]=STCRYPT_PROVIDER_NAME_A;
		capi_get_param_impl(sizeof(name), data, datalen, 
			boost::bind(memcpy, _1, name, _2));
	}
	void csp_t::get_param__container_name_(BYTE* const data, DWORD * const datalen){
		assert(m_keystorage);
		capi_get_param_impl(m_keystorage->name().size()+1, data, datalen, 
			boost::bind(memcpy, _1, m_keystorage->name().c_str(), _2));
	}
	void csp_t::get_param__version_(BYTE* const data, DWORD * const datalen){
		DWORD const ver = 0x0001;
		capi_get_param_impl(sizeof(ver), data, datalen, 
			boost::bind(memcpy, _1, &ver, _2));
	}
	void csp_t::get_param__prov_type_(BYTE* const data, DWORD * const datalen){
		DWORD const prov_type = provider_type;
		capi_get_param_impl(sizeof(prov_type), data, datalen, 
			boost::bind(memcpy, _1, &prov_type, _2));
	}
	void csp_t::get_param__imp_type_(BYTE* const data, DWORD * const datalen){
		DWORD const implType = CRYPT_IMPL_SOFTWARE ;
		capi_get_param_impl(sizeof(implType), data, datalen, 
			boost::bind(memcpy, _1, &implType, _2));
	}

	//================================================================================================================================================




}
//================================================================================================================================================
