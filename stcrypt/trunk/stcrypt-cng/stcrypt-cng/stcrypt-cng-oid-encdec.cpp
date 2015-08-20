//================================================================================================================================================
// FILE: stcrypt-cng-oid-encdec.cpp
// (c) GIE 2010-09-14  18:09
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "util-fun-parameter-printer-cng-struct.hpp"
#include "stcrypt-cng-oid-encdec.hpp"
#include "stcrypt-cng-oid-exceptions.hpp"
#include "util-bittest.hpp"
#include "util-raw-buffer-oiter.hpp"

#include <boost/numeric/conversion/converter.hpp>
#include <boost/iostreams/stream.hpp>
#include <boost/iostreams/device/back_inserter.hpp>
#include <boost/scope_exit.hpp>

#include "BIT_STRING.h"

#include <WinCrypt.h>
//================================================================================================================================================
namespace stcrypt {


	namespace impl { 
		
		namespace {

			template <class OutputIterator>
			int save_to_iter(const void *buffer, size_t size, void *key){
				assert(key);

				if(size!=0){
					assert(buffer);
					
					auto & out_iter = *static_cast<OutputIterator*>(key);
					auto buffer_typed = static_cast<unsigned char const*>(buffer);

					out_iter = std::copy( buffer_typed, buffer_typed+size, out_iter);

				} else {
					STCRYPT_LOG_PRINT_EX("x509asn-warning","ASN.1 generator requested 0-sized write");
				}

				return 0;            

			}


			void * WINAPI encdec_alloc_func__sys(size_t size){
				return LocalAlloc(0, size);
			}

			void WINAPI encdec_free_func__sys(void * m){
				assert(m);
				auto const r = LocalFree( m );			
				assert(r==0);
			}


		} // end anon ns

	} // end impl ns

	
	void encode_object_ex( 
		DWORD const dwCertEncodingType, 
		LPCSTR const lpszStructType, 
		const void * const pvStructInfo, 
		DWORD const dwFlags, 
		PCRYPT_ENCODE_PARA const pEncodePara, 
		void *const pvEncoded, 
		DWORD *const pcbEncoded)
	{
		assert(lpszStructType);
		assert(pvStructInfo);
		assert(pcbEncoded);

		typedef std::vector<char> blob_container_t;

		PFN_CRYPT_ALLOC const alloc_func = (pEncodePara?(pEncodePara->pfnAlloc?pEncodePara->pfnAlloc:&impl::encdec_alloc_func__sys):&impl::encdec_alloc_func__sys);
		PFN_CRYPT_FREE  const free_func = (pEncodePara?(pEncodePara->pfnFree?pEncodePara->pfnFree:&impl::encdec_free_func__sys):&impl::encdec_free_func__sys);

		auto const we_do_alloc_mem = test_mask<decltype(dwFlags)>(dwFlags, CRYPT_ENCODE_ALLOC_FLAG);
		auto const cng_struct = reinterpret_cast<cng_blob_info_t const*>( pvStructInfo );


		BIT_STRING_t data_out={0};

		data_out.buf = const_cast<unsigned char*>( cng_struct->m_blob );
		data_out.size = cng_struct->m_blob_size;
		data_out.bits_unused = 0;

		asn_enc_rval_t const asn_r = der_encode(&asn_DEF_BIT_STRING, &data_out, 0 /*estimate*/ , 0);
		if( asn_r.encoded==-1 ) {
			STCRYPT_UNEXPECTED();
		}
		size_t const required_buffer_size = asn_r.encoded;

		if( we_do_alloc_mem ){

			if(!pvEncoded) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );

			auto encoded_struct_buffer = reinterpret_cast<unsigned char*> ( alloc_func(required_buffer_size) );
			if( !encoded_struct_buffer ) STCRYPT_UNEXPECTED();

			BOOST_SCOPE_EXIT( (&encoded_struct_buffer) (free_func) ) { if(encoded_struct_buffer) { free_func(encoded_struct_buffer); } }  BOOST_SCOPE_EXIT_END

			auto current_pos = encoded_struct_buffer;

			auto iter = raw_buffer_oiter_for<unsigned char>::construct( current_pos, current_pos+required_buffer_size);

			asn_enc_rval_t const asn_r2 =  der_encode(&asn_DEF_BIT_STRING, &data_out,  impl::save_to_iter<decltype(iter)>, &iter);
			if( asn_r2.encoded!=required_buffer_size ) STCRYPT_UNEXPECTED();

			*static_cast<unsigned char**>( pvEncoded ) = encoded_struct_buffer;
			encoded_struct_buffer = 0;

			*pcbEncoded = required_buffer_size;

		} else {

			if(pvEncoded) {
				if( *pcbEncoded < required_buffer_size ) {
					*pcbEncoded = required_buffer_size;
					STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair(*pcbEncoded, required_buffer_size) ) );
				}
				
				auto current_pos = reinterpret_cast<unsigned char*>( pvEncoded );

				auto iter = raw_buffer_oiter_for<unsigned char>::construct( current_pos, current_pos+required_buffer_size);

				asn_enc_rval_t const asn_r2 =  der_encode(&asn_DEF_BIT_STRING, &data_out,  impl::save_to_iter<decltype(iter)>, &iter);
				if( asn_r2.encoded!=required_buffer_size ) STCRYPT_UNEXPECTED();
			}

			*pcbEncoded = required_buffer_size;

		}


	}


	void decode_object_ex(
		DWORD const dwCertEncodingType,
		LPCSTR const lpszStructType,
		const BYTE * const pbEncoded,
		DWORD const cbEncoded,
		DWORD const dwFlags,
		PCRYPT_DECODE_PARA const pDecodePara,
		void * const pvStructInfo,
		DWORD * const pcbStructInfo
		)
	{
		STCRYPT_LOG_PRINT_W_EX(L"Struct type", lpszStructType);

		PFN_CRYPT_ALLOC const alloc_func = (pDecodePara?(pDecodePara->pfnAlloc?pDecodePara->pfnAlloc:&impl::encdec_alloc_func__sys):&impl::encdec_alloc_func__sys);
		PFN_CRYPT_FREE  const free_func = (pDecodePara?(pDecodePara->pfnFree?pDecodePara->pfnFree:&impl::encdec_free_func__sys):&impl::encdec_free_func__sys);

		auto const we_do_alloc_mem = test_mask<decltype(dwFlags)>(dwFlags, CRYPT_DECODE_ALLOC_FLAG);


		BIT_STRING_t * data_out=0; //TODO!!! free on scope exit

		asn_dec_rval_t const status = ber_decode(0, &asn_DEF_BIT_STRING, (void**)(&data_out), pbEncoded, cbEncoded );
		BOOST_SCOPE_EXIT ( (&data_out) ) { if(data_out){ ASN_STRUCT_FREE(asn_DEF_BIT_STRING, data_out); } } BOOST_SCOPE_EXIT_END;

		if( status.code!=RC_OK ){ STCRYPT_UNEXPECTED1("ber_decode have failed"); }

		assert( data_out );
		if( data_out->bits_unused!=0 ) STCRYPT_UNEXPECTED();
		size_t const asn_decoded_blob_size = data_out->size;
		size_t const header_sizes = sizeof(cng_blob_info_t);
		size_t const required_buffer_size = asn_decoded_blob_size + header_sizes ;


		auto const set_up_blob = [&](unsigned char* const ret_data){

			unsigned char* const ret_data_blob = ret_data + header_sizes;
			cng_blob_info_t * ret_header = reinterpret_cast<cng_blob_info_t*>( ret_data );

			memcpy(ret_data_blob, data_out->buf, asn_decoded_blob_size);

			ret_header->m_type =-1;
			ret_header->m_blob=ret_data_blob;
			ret_header->m_blob_size=asn_decoded_blob_size;

		};

		if( we_do_alloc_mem ) {
			if(!pvStructInfo) STCRYPT_UNEXPECTED();
			
			unsigned char* ret_data = static_cast<unsigned char*>( alloc_func(required_buffer_size) );
			if( !ret_data ) STCRYPT_UNEXPECTED();
			BOOST_SCOPE_EXIT( (&ret_data) (free_func) ) { if(ret_data) { free_func(ret_data); } }  BOOST_SCOPE_EXIT_END;

			set_up_blob( ret_data );

			*pcbStructInfo = required_buffer_size;
			*static_cast<unsigned char**>(pvStructInfo) = ret_data;
			ret_data = 0; // remove self mem ownership
		} else {

			if( !pvStructInfo ){
				*pcbStructInfo = required_buffer_size;
			} else {
				if( *pcbStructInfo < required_buffer_size ) {
					*pcbStructInfo = required_buffer_size;
					STCRYPT_THROW_EXCEPTION( exception::small_buffer() << exception::small_buffer_einfo( std::make_pair(*pcbStructInfo, required_buffer_size) ) );
				}

				set_up_blob( static_cast<unsigned char*>( pvStructInfo ) );

				*pcbStructInfo = required_buffer_size;
			}

		} // end of else of we_do_alloc_mem


	} // end of decode_object_ex




}

BOOL WINAPI STCRYPT_CryptEncodeObjectEx(
	__in     DWORD dwCertEncodingType,
	__in     LPCSTR lpszStructType,
	__in     const void *pvStructInfo,
	__in     DWORD dwFlags,
	__in     PCRYPT_ENCODE_PARA pEncodePara,
	__out    void *pvEncoded,
	__inout  DWORD *pcbEncoded
	){
		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(dword, dwCertEncodingType);
			STC_IN_P(string, lpszStructType);
		});

		if( !lpszStructType ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pvStructInfo ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );
		if( !pcbEncoded ) STCRYPT_THROW_EXCEPTION ( stcrypt::exception::invalid_parameter() );

		// If the high-order word of the lpszStructType parameter is zero, the low-order word specifies 
		// the integer identifier for the type of the specified structure. Otherwise, this parameter 
		// is a long pointer to a null-terminated string. 
		if( !stcrypt::test_if_any_in_mask<DWORD>(reinterpret_cast<DWORD>( lpszStructType ), 0xFFFF0000) ) STCRYPT_UNEXPECTED();

		stcrypt::encode_object_ex( dwCertEncodingType, lpszStructType, pvStructInfo, dwFlags, pEncodePara, pvEncoded, pcbEncoded);

		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_END
}


BOOL WINAPI STCRYPT_CryptDencodeObjectEx(
	__in     DWORD dwCertEncodingType,
	__in     LPCSTR lpszStructType,
	__in     const BYTE *pbEncoded,
	__in     DWORD cbEncoded,
	__in     DWORD dwFlags,
	__in     PCRYPT_DECODE_PARA pDecodePara,
	__out    void *pvStructInfo,
	__inout  DWORD *pcbStructInfo
	){
		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_BEGIN
		CSP_LOG_TRACE

		STC_PP({
			STC_IN_P(dword, dwCertEncodingType);
			STC_IN_P(string, lpszStructType);
			STC_IN_P_EX(array_any, stcrypt::pp_a(pbEncoded, cbEncoded),  pbEncoded);
			STC_IN_P(dword, cbEncoded);
			STC_IN_P(dword, dwFlags);
			STC_IN_P(hex_auto, pDecodePara);
			STC_OUT_P(hex_auto, pvStructInfo);
			STC_OUT_P(dword, pcbStructInfo);
		});


		// If the high-order word of the lpszStructType parameter is zero, the low-order word specifies 
		// the integer identifier for the type of the specified structure. Otherwise, this parameter 
		// is a long pointer to a null-terminated string. 
		if( !stcrypt::test_if_any_in_mask<DWORD>(reinterpret_cast<DWORD>( lpszStructType ), 0xFFFF0000) ) STCRYPT_UNEXPECTED();

		stcrypt::decode_object_ex(dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pDecodePara, pvStructInfo, pcbStructInfo);

		CNG_CSP_CNG_OID_FUNC_CPP_EXCEPTION_GUARD_END
}



//================================================================================================================================================
