//================================================================================================================================================
// FILE: ms_cert_store_utils.h
// (c) GIE 2011-02-03  00:05
//
//================================================================================================================================================
#ifndef H_GUARD_MS_CERT_STORE_UTILS_2011_02_03_00_05
#define H_GUARD_MS_CERT_STORE_UTILS_2011_02_03_00_05
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "../../stcrypt-cng/stcrypt-exceptions.hpp"

#include "gie/gie_auto_vector.hpp"

#include <boost/noncopyable.hpp>
#include <boost/scope_exit.hpp>

#include <assert.h>
//================================================================================================================================================
namespace ms_cert {

	struct store_handle_t : boost::noncopyable
	{
		store_handle_t() : m_handle(0) {}
		explicit store_handle_t(HCERTSTORE const handle) : m_handle (handle) {}
		~store_handle_t(){ release_(); }
		store_handle_t(store_handle_t&& other){
			release_();
			m_handle = other.m_handle;
			other.m_handle = 0;
		}

		HCERTSTORE handle()const{ return m_handle; }

		typedef HCERTSTORE store_handle_t::*unspecified_bool_type;

		operator unspecified_bool_type() const // never throws
		{
			return m_handle == 0? 0: &store_handle_t::m_handle;
		}

	private:
		void release_(){ if(m_handle){auto const r = CertCloseStore(m_handle, 0); assert(m_handle); }  }
		HCERTSTORE	m_handle;
	};


	struct pccert_context_t : boost::noncopyable
	{
		pccert_context_t() : m_handle(0) {}
		explicit pccert_context_t( PCCERT_CONTEXT const handle) : m_handle (handle) {}
		~pccert_context_t(){ release_(); }
		pccert_context_t(pccert_context_t&& other){
			release_();
			m_handle = other.m_handle;
			other.m_handle = 0;
		}

		pccert_context_t& operator=(pccert_context_t&& other){
			release_();
			m_handle = other.m_handle;
			other.m_handle = 0;

			return *this;
		}

		pccert_context_t& operator=(PCCERT_CONTEXT&& other){
			release_();
			m_handle = other;

			return *this;
		}

		PCCERT_CONTEXT handle()const{ return m_handle; }

		typedef PCCERT_CONTEXT pccert_context_t::*unspecified_bool_type;

		operator unspecified_bool_type() const // never throws
		{
			return m_handle == 0? 0: &pccert_context_t::m_handle;
		}

	private:
		void release_(){ if(m_handle){auto const r = CertFreeCertificateContext(m_handle); assert(m_handle); }  }
		PCCERT_CONTEXT	m_handle;
	};



	inline
	void cert_str_to_name_blob(wchar_t const*const cert_str, CERT_NAME_BLOB& cert_name_blob, std::vector<unsigned char>& cert_name_blob_data){

		typedef std::vector<unsigned char> VectorT;

		VectorT& data = cert_name_blob_data;

		cert_name_blob = CERT_NAME_BLOB();

		DWORD const p_encoding_type = X509_ASN_ENCODING;
		DWORD const p_str_type = CERT_X500_NAME_STR;

		if( CertStrToNameW(
			p_encoding_type, 
			cert_str, 
			p_str_type, 
			NULL,
			0, 
			&cert_name_blob.cbData, 
			NULL) ==0){
				STCRYPT_UNEXPECTED();
		}

		data.resize(cert_name_blob.cbData);
		cert_name_blob.pbData = &data[0];
		if( !CertStrToNameW(p_encoding_type, cert_str, 
			p_str_type, NULL, &data[0], &cert_name_blob.cbData, NULL) ){
				STCRYPT_UNEXPECTED();
		} 


	}

	inline
	std::wstring cert_name_to_str(CERT_NAME_BLOB const& cert_name_blob){

		auto const chars_required = CertNameToStrW(X509_ASN_ENCODING, &( const_cast<CERT_NAME_BLOB&>( cert_name_blob ) ),  CERT_X500_NAME_STR,  0, 0);
		gie::monotonic::vector<wchar_t, 4*1024> tmp_buf;
		tmp_buf.resize(chars_required);
		auto const chars_returned = CertNameToStrW(X509_ASN_ENCODING, &( const_cast<CERT_NAME_BLOB&>( cert_name_blob ) ),  CERT_X500_NAME_STR,  tmp_buf.data(), tmp_buf.size() );
		STCRYPT_CHECK(chars_required==chars_returned);

		STCRYPT_CHECK( tmp_buf.size()>2 );
		return std::wstring(tmp_buf.data(), tmp_buf.size()-1);

	}

	inline
	std::wstring cert_get_name_string(CERT_CONTEXT const& cert_ctx, bool const issuer=false){
		auto const chars_required = CertGetNameStringW(&( const_cast<CERT_CONTEXT&>( cert_ctx ) ), CERT_NAME_RDN_TYPE, issuer?CERT_NAME_ISSUER_FLAG:0,  0, 0, 0);
		gie::monotonic::vector<wchar_t, 4*1024> tmp_buf;
		tmp_buf.resize(chars_required);
		auto const chars_returned = CertGetNameStringW(&( const_cast<CERT_CONTEXT&>( cert_ctx ) ), CERT_NAME_RDN_TYPE, issuer?CERT_NAME_ISSUER_FLAG:0,  0, tmp_buf.data(), tmp_buf.size());
		STCRYPT_CHECK(chars_required==chars_returned);

		STCRYPT_CHECK( tmp_buf.size()>2 );
		return std::wstring(tmp_buf.data(), tmp_buf.size()-1);
	}

	inline
	std::wstring cert_get_name_string(CERT_CONTEXT const * const cert_ctx, bool const issuer=false){
		return cert_get_name_string( *cert_ctx, issuer );
	}
	inline
	std::wstring cert_get_name_string(pccert_context_t const& cert_ctx, bool const issuer=false){
		return cert_get_name_string( cert_ctx.handle(), issuer );
	}


	inline 
	boost::optional< boost::tuple<std::wstring, std::wstring> > cert_get_private_key_storage_name(CERT_CONTEXT const& cert_ctx){
		DWORD size=0;
		
		if( !CertGetCertificateContextProperty(&cert_ctx, CERT_KEY_PROV_INFO_PROP_ID, 0, &size) ){
			return boost::none;
		};
		STCRYPT_CHECK(size!=0);

		std::vector<BYTE> tmp(size);

		STCRYPT_CHECK( CertGetCertificateContextProperty(&cert_ctx, CERT_KEY_PROV_INFO_PROP_ID, tmp.data(), &size) ) ;
		tmp.resize(size);

		auto const prov_info = reinterpret_cast<CRYPT_KEY_PROV_INFO*>( tmp.data() );
		return boost::make_tuple( prov_info->pwszProvName, prov_info->pwszContainerName );		
	}

// 	inline
// 	std::vector<unsigned char> encode_certificate(CERT_CONTEXT const& certificate_context){
// 		std::vector<unsigned char> tmp;
// 
// 		DWORD size = 0;
// 		if( !CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT, &certificate_context, 0, 0, 0, &size) ){
// 			auto const err = GetLastError();
// 			STCRYPT_UNEXPECTED();
// 		}
// 
// 		return tmp;
// 	}

	inline
	void import_into_ms_store2(PCCERT_CONTEXT ms_cert_ctx, std::wstring const& cert_store_name ){


		HCERTSTORE const ms_cert_store = CertOpenStore (
			CERT_STORE_PROV_SYSTEM,
			0,
			0,
			/* CERT_STORE_OPEN_EXISTING_FLAG | */
			CERT_SYSTEM_STORE_CURRENT_USER, //CERT_SYSTEM_STORE_LOCAL_MACHINE,
			cert_store_name.c_str());

		if(ms_cert_store==0) STCRYPT_UNEXPECTED1("CertOpenStore have failed");

		BOOST_SCOPE_EXIT( (ms_cert_store) ){
			BOOL const r = CertCloseStore (ms_cert_store,0);
			assert(r!=0);
		} BOOST_SCOPE_EXIT_END

			if (!CertAddCertificateContextToStore (
				ms_cert_store,
				ms_cert_ctx,
				CERT_STORE_ADD_ALWAYS,
				NULL))
				STCRYPT_UNEXPECTED1("CertAddCertificateContextToStore have failed");



	}

}
//================================================================================================================================================
#endif
//================================================================================================================================================
