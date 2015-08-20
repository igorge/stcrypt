//================================================================================================================================================
// FILE: strcypt-cng-dstu4145.cpp
// (c) GIE 2010-08-25  16:30
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-dstu4145-impl.hpp"
#include "stcrypt-cng-dstu4145.hpp"
#include "util-cng-get-prop.hpp"
#include "stcrypt-crypto-alg-ids.h"
#include "util-sio.hpp"
#include "util-sio-cng.hpp"

#include <boost/tuple/tuple.hpp>
#include <boost/function_output_iterator.hpp>
#include <boost/utility/in_place_factory.hpp>
//================================================================================================================================================
namespace stcrypt {


	struct dstu4145_b_alg_id { static wchar_t const*const alg_id; };
	wchar_t const*const dstu4145_b_alg_id::alg_id = CNG_DSTU4145;

	struct cng_dstu4145_object
		: cng_asymmetric_object_op_i
		, cng_prop_op_i
		, dstu4145_b_alg_id
	{
		typedef BCRYPT_KEY_BLOB blob_header_type;
		typedef BCRYPT_KEY_BLOB blob_footer_type;

		typedef dstu4145_t::public_part_type public_part_type;
		typedef dstu4145_t::private_part_type private_part_type;

		struct tag_generate{};
		struct tag_import{};

		virtual boost::tuple<size_t,size_t> buffers_sizes()const{
			return m_impl.buffers_sizes();
		}

		virtual ULONG calc_encrypt_buffer_size(ULONG const input_size){
			auto const& b_sizes = this->buffers_sizes();

			auto const buffers_count = input_size / boost::get<0>(b_sizes) + (  input_size%boost::get<0>(b_sizes)==0?0:1 );

			return buffers_count* boost::get<1>(b_sizes);
		}

		virtual ULONG calc_decrypt_buffer_size(ULONG const input_size){
			auto const& b_sizes = this->buffers_sizes();

			STCRYPT_CHECK_EX(input_size%boost::get<1>(b_sizes)==0, stcrypt::exception::invalid_parameter());

			auto const buffers_count = input_size / boost::get<1>(b_sizes);

			return buffers_count* boost::get<0>(b_sizes);
		}

		virtual ULONG encrypt(PUCHAR const input, ULONG const input_size, PUCHAR const output, ULONG const output_size){
			return m_impl.encrypt(input, input_size, output, output_size);
		}


		virtual ULONG decrypt(PUCHAR const input, ULONG const input_size, PUCHAR const output, ULONG const output_size){
			return m_impl.decrypt(input, input_size, output, output_size);
		}

		size_t private_blob_size()const{
			if( m_impl.private_part_size()==0 ) STCRYPT_THROW_EXCEPTION( exception::invalid_blob_type() << exception::blob_type_name_einfo(BCRYPT_PRIVATE_KEY_BLOB) );

			auto const blob_size = sio::io_size<blob_header_type>::value + m_impl.public_part_size() + m_impl.private_part_size() + sio::io_size<blob_footer_type>::value;
			return blob_size;
		}

		size_t public_blob_size()const{
			auto const blob_size = sio::io_size<blob_header_type>::value + m_impl.public_part_size() + sio::io_size<blob_footer_type>::value;
			return blob_size;
		}


		explicit cng_dstu4145_object(tag_generate const&)
			: m_impl ( dstu4145_t::tag_generate() )
		{}

		explicit cng_dstu4145_object(tag_import const&, boost::optional<private_part_type const &> const& private_part, boost::optional<public_part_type const&> const& public_part)
			: m_impl ( dstu4145_t::tag_import(), private_part, public_part )
		{}

		virtual void destroy_self(){delete this;}

		virtual DWORD key_strength(){
			return boost::get<1>( this->buffers_sizes() )*2*8; //TODO: //HACK: can asym encrypt\decrypt at most two buffers?
			//return m_impl.signature_block_size()*16*8; //TODO:
		}

		virtual DWORD block_length(){
			return boost::get<0>( this->buffers_sizes() )*8; //TODO: //HACK: 
		}

		virtual DWORD key_length(){
			return m_impl.key_length() * 8;
		}



		virtual ULONG key_blob_size(LPCWSTR pszBlobType){
			assert(pszBlobType);

			if( wcscmp(BCRYPT_PRIVATE_KEY_BLOB, pszBlobType)==0 ){
				return private_blob_size();
			} else if( wcscmp(BCRYPT_PUBLIC_KEY_BLOB, pszBlobType)==0 ){
				return public_blob_size();
			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_blob_type() << exception::blob_type_name_einfo(pszBlobType) );
			}
		}

		virtual ULONG export_key_blob(LPCWSTR pszBlobType, PUCHAR pbOutput,  ULONG cbOutput){
			assert(pszBlobType);
			assert(pbOutput);

			if( wcscmp(BCRYPT_PRIVATE_KEY_BLOB, pszBlobType)==0 ){
				
				auto const blob_size = private_blob_size();
				if( cbOutput<blob_size ) STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair(cbOutput, blob_size) ) );
				
				
				blob_header_type const blob_header = {CNG_DSTU4145_BLOB_MAGIC_PRIVATE}; 
				blob_footer_type const blob_footer = {CNG_DSTU4145_BLOB_MAGIC_PRIVATE}; 


				BYTE* current_write_pointer = pbOutput;
				auto const blob_buffer_end = current_write_pointer + cbOutput;

				auto const output_iterator =  boost::make_function_output_iterator( sio::raw_buffer_appender<BYTE>(current_write_pointer, blob_buffer_end) );
				
				sio::write<decltype(blob_header)>::apply( blob_header, output_iterator );
				m_impl.private_part( output_iterator );
				m_impl.public_part( output_iterator );
				sio::write<decltype(blob_footer)>::apply( blob_header, output_iterator );

				return blob_size;


			} else if( wcscmp(BCRYPT_PUBLIC_KEY_BLOB, pszBlobType)==0 ){

				auto const blob_size = public_blob_size();
				if( cbOutput<blob_size ) STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair(cbOutput, blob_size) ) );


				blob_header_type const blob_header = {CNG_DSTU4145_BLOB_MAGIC_PUBLIC}; 
				blob_footer_type const blob_footer = {CNG_DSTU4145_BLOB_MAGIC_PUBLIC}; 


				BYTE* current_write_pointer = pbOutput;
				auto const blob_buffer_end = current_write_pointer + cbOutput;

				auto const output_iterator =  boost::make_function_output_iterator( sio::raw_buffer_appender<BYTE>(current_write_pointer, blob_buffer_end) );

				sio::write<decltype(blob_header)>::apply( blob_header, output_iterator );
				m_impl.public_part( output_iterator );
				sio::write<decltype(blob_footer)>::apply( blob_header, output_iterator );

				return blob_size;

			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_blob_type() << exception::blob_type_name_einfo(pszBlobType) );
			}
		}



		virtual DWORD sign_hash(PBYTE const input, DWORD const input_size, PBYTE output, DWORD const output_size,  ULONG const flags){

			auto const sign_size = this->signature_size();
			if( output_size<sign_size ) STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair(output_size, sign_size)) ) ;


			if( input_size>m_impl.signature_block_size() ){
				STCRYPT_UNIMPLEMENTED();
			}

			m_impl.sign(input, input_size, output, output_size);
			
			return sign_size;			
		}



		virtual bool verify_signature(PBYTE const hash, DWORD const hash_size, PBYTE signature, DWORD const signature_size,  ULONG const flags){
			assert(hash);
			assert(signature);

			auto const sign_size = this->signature_size();
			if( signature_size<sign_size ) STCRYPT_THROW_EXCEPTION( exception::bad_signature_size() << exception::bad_signature_size_einfo(signature_size) ) ;

			if( hash_size>m_impl.signature_block_size() ){
				STCRYPT_UNIMPLEMENTED();
			}

			return m_impl.verify(hash, hash_size, signature, signature_size);
		}



		virtual DWORD signature_size(){ return m_impl.signature_size(); }
		


		virtual void set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags){
			STCRYPT_UNIMPLEMENTED();
		}

		virtual void get_prop(LPCWSTR const prop_name, PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags){
			assert(prop_name);
 
			if(flags) STCRYPT_THROW_EXCEPTION( exception::badflags() << exception::flags_einfo(flags) );

			if( wcscmp(BCRYPT_KEY_STRENGTH, prop_name)==0 ){

				prop_val_size = cng_get_prop_impl( sizeof( decltype(this->key_strength() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
					auto const key_strength = this->key_strength();
					auto const r = memcpy_s( dest, size, &key_strength, sizeof(key_strength) );	assert(!r);
				});

			} else if( wcscmp(BCRYPT_BLOCK_LENGTH, prop_name)==0 ){

				prop_val_size = cng_get_prop_impl( sizeof( decltype(this->block_length() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
					auto const block_length = this->block_length();
					auto const r = memcpy_s( dest, size, &block_length, sizeof(block_length) );	assert(!r);
				});

			} else if( wcscmp(BCRYPT_KEY_LENGTH, prop_name)==0 ){

				prop_val_size = cng_get_prop_impl( sizeof( decltype(this->key_length() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
					auto const key_length = this->key_length();
					auto const r = memcpy_s( dest, size, &key_length, sizeof(key_length) );	assert(!r);
				});

			} else if( wcscmp(BCRYPT_ALGORITHM_NAME, prop_name)==0 ){

				auto const prop_val_req_size = (wcslen(this->alg_id)+1)*sizeof(wchar_t);

				prop_val_size = cng_get_prop_impl( prop_val_req_size , prop_val_buffer, prop_val_buffer_size, [&](PUCHAR const dest, ULONG const size){
					auto const r = memcpy_s( dest, size, this->alg_id, prop_val_req_size );	assert(!r);
				});

			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
			}

		}

		dstu4145_t	m_impl;

	};


	struct cng_dstu4145_object_ctor
		: cng_asymmetric_object_ctor_op_i
	{
		virtual void destroy_self(){delete this;}

		virtual cng_asymmetric_object_op_i_ptr_t create(){
			return cng_asymmetric_object_op_i_ptr_t( new cng_dstu4145_object( cng_dstu4145_object::tag_generate( ) ) );
		}

		cng_dstu4145_object_ctor(ULONG const key_bit_length){
		}

	};


	void cng_dstu4145_class::get_prop(LPCWSTR const prop_name,  PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags){
		assert(prop_name);

		if(flags) STCRYPT_THROW_EXCEPTION( exception::badflags() << exception::flags_einfo(flags) );

		if( wcscmp(BCRYPT_PADDING_SCHEMES, prop_name)==0 ){

			prop_val_size = cng_get_prop_impl( sizeof( decltype(this->cng_padding_schemes() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
				auto const obj_length = this->cng_padding_schemes();
				auto const r = memcpy_s( dest, size, &obj_length, sizeof(obj_length) );	assert(!r);
			});
		} else {
			STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
		}

	}

	namespace {

		template <class HeaderType, class Exception, class Range>
		Range validate_blob_magic(ULONG const m, Range const& input_range){
			HeaderType blob_header; 
			Range tmp = boost::get<0>( sio::read<decltype(blob_header)>::apply(blob_header, input_range) );

			if( m!=blob_header.Magic ) STCRYPT_THROW_EXCEPTION( Exception() );

			return std::move(tmp);
		}

		template <class HeaderType, class Exception, class Range>
		Range validate_blob_header(ULONG const m, Range const& input_range){
			return validate_blob_magic<HeaderType, Exception, Range>(m, input_range);
		}
		template <class HeaderType, class Exception, class Range>
		Range validate_blob_footer(ULONG const m, Range const& input_range){
			return validate_blob_magic<HeaderType, Exception, Range>(m, input_range);
		}

	}

	cng_asymmetric_object_handle_ptr_t cng_dstu4145_class::import_key_pair(LPCWSTR const pszBlobType, PUCHAR const pbInput, ULONG const cbInput){
		assert(pszBlobType);
		assert(pbInput);

		if( wcscmp(BCRYPT_PRIVATE_KEY_BLOB, pszBlobType)==0 ){

			cng_dstu4145_object::private_part_type	private_part;
			cng_dstu4145_object::public_part_type   public_part;

			auto input_range = boost::make_iterator_range(pbInput, pbInput+cbInput);

			input_range = validate_blob_header<cng_dstu4145_object::blob_header_type, exception::key_import_invalid_key_blob_magic>(CNG_DSTU4145_BLOB_MAGIC_PRIVATE, input_range);

			input_range = boost::get<0>( sio::read<decltype(private_part)>::apply(private_part, input_range) );
			input_range = boost::get<0>( sio::read<decltype(public_part)>::apply(public_part, input_range) );

			input_range = validate_blob_footer<cng_dstu4145_object::blob_header_type, exception::key_import_corrupted_key_blob>(CNG_DSTU4145_BLOB_MAGIC_PRIVATE, input_range);

			return cng_asymmetric_object_handle_ptr_t( new cng_asymmetric_object_handle_t( cng_asymmetric_object_op_i_ptr_t( new cng_dstu4145_object(cng_dstu4145_object::tag_import(), private_part, public_part) ) ) );

		} else if( wcscmp(BCRYPT_PUBLIC_KEY_BLOB, pszBlobType)==0 ){

			cng_dstu4145_object::public_part_type   public_part;

			auto input_range = boost::make_iterator_range(pbInput, pbInput+cbInput);

			input_range = validate_blob_header<cng_dstu4145_object::blob_header_type, exception::key_import_invalid_key_blob_magic>(CNG_DSTU4145_BLOB_MAGIC_PUBLIC, input_range);
			input_range = boost::get<0>( sio::read<decltype(public_part)>::apply(public_part, input_range) );
			input_range = validate_blob_footer<cng_dstu4145_object::blob_header_type, exception::key_import_corrupted_key_blob>(CNG_DSTU4145_BLOB_MAGIC_PUBLIC, input_range);

			return cng_asymmetric_object_handle_ptr_t( new cng_asymmetric_object_handle_t( cng_asymmetric_object_op_i_ptr_t( new cng_dstu4145_object(cng_dstu4145_object::tag_import(), boost::none, public_part) ) ) );

		} else {
			STCRYPT_THROW_EXCEPTION( exception::invalid_blob_type() << exception::blob_type_name_einfo(pszBlobType) );
		}


	}


	cng_asymmetric_object_handle_ptr_t cng_dstu4145_class::generate_key_pair(ULONG const key_bit_length, ULONG const dwFlags){
		return cng_asymmetric_object_handle_ptr_t( new cng_asymmetric_object_handle_t( cng_asymmetric_object_ctor_op_i_ptr_t( new cng_dstu4145_object_ctor(key_bit_length) ) ) );
	}





}
//================================================================================================================================================
