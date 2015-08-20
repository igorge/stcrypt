//================================================================================================================================================
// FILE: stcrypt-exceptions.h
// (c) GIE 2009-11-02  16:26
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_EXCEPTIONS_2009_11_02_16_26
#define H_GUARD_STCRYPT_EXCEPTIONS_2009_11_02_16_26
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-debug.hpp"

#include <boost/exception/all.hpp>
#include <boost/preprocessor/stringize.hpp>

#include <wincrypt.h>
//================================================================================================================================================
#define STCRYPT_UNIMPLEMENTED_MSG_W() STCRYPT_LOG_W_STRING(L">>>>>>UNIMPLEMENTED FUNCTION CALL<<<<<<")
#define STCRYPT_THROW_EXCEPTION(x)			\
	do {									\
		try{								\
			BOOST_THROW_EXCEPTION(x);											\
			throw "DUMMY";	/* to avoid 'warning C4715: xxxx' : not all control paths return a value'*/ \
		}catch(boost::exception const& e) {										\
			std::string const& diag_info = boost::diagnostic_information(e);	\
			STCRYPT_LOG_A_STRING( diag_info );									\
			OutputDebugStringA( diag_info.c_str() ) ;							\
			throw;																\
		}																		\
	} while(false)																\
	/**/
	
#define STCRYPT_UNEXPECTED_IN_DTOR()    assert(false)

#define STCRYPT_UNIMPLEMENTED()	do {\
	STCRYPT_UNIMPLEMENTED_MSG_W();	\
	/*assert(!"UNIMPLEMENTED");*/	\
	STCRYPT_THROW_EXCEPTION(::stcrypt::exception::unimplemented()); } while(false)

#define STCRYPT_UNEXPECTED()	\
    /*assert(!"UNEXPECTED");*/	\
	STCRYPT_THROW_EXCEPTION(::stcrypt::exception::unexpected())

#define STCRYPT_UNEXPECTED1(msg)\
	/*assert(!"UNEXPECTED");*/	\
	STCRYPT_THROW_EXCEPTION(::stcrypt::exception::unexpected() << stcrypt::exception::error_str_einfo(msg))

#define STCRYPT_UNEXPECTEDW1(msg)\
	/*assert(!"UNEXPECTED");*/	\
	STCRYPT_THROW_EXCEPTION(::stcrypt::exception::unexpected() << stcrypt::exception::error_wstr_einfo(msg))

#define STCRYPT_CHECK(x) STCRYPT_CHECK_EX(x, ::stcrypt::exception::condition_check_failed() << stcrypt::exception::condition_check_einfo( BOOST_PP_STRINGIZE(x) ) )
#define STCRYPT_CHECK_EX(x,e) if(!(x)) STCRYPT_THROW_EXCEPTION(e << stcrypt::exception::condition_check_einfo( BOOST_PP_STRINGIZE(x) ) )
#define STCRYPT_CHECK_WIN(x) STCRYPT_CHECK_EX(x, ::stcrypt::exception::condition_check_failed() << stcrypt::exception::getlasterror_einfo( GetLastError() ) )

namespace stcrypt {

	 namespace exception{

		 typedef boost::error_info<struct tag_getlasteror_code, DWORD > getlasterror_einfo;
		 typedef boost::error_info<struct tag_cryptolib_errcode, DWORD > cryptolib_einfo;
		 typedef boost::error_info<struct tag_cryptoapi_errcode, DWORD > cryptoapi_einfo;
		 typedef boost::error_info<struct tag_flags, DWORD > flags_einfo;
		 typedef boost::error_info<struct tag_algid, ALG_ID > algid_einfo;
		 typedef boost::error_info<struct tag_bad_data_size, size_t > bad_data_einfo;
		 typedef boost::error_info<struct tag_error_str, std::string> error_str_einfo;
		 typedef boost::error_info<struct tag_error_str, std::string> condition_check_einfo;
		 typedef boost::error_info<struct tag_error_wstr, std::wstring> error_wstr_einfo;
		 typedef boost::error_info<struct tag_prop_name, std::wstring> cng_prop_name_einfo;
		 typedef boost::error_info<struct tag_keyset_name, std::wstring> cng_keyset_name_einfo;
		 typedef boost::error_info<struct tag_prop_name, std::wstring> prop_value_einfo;
		 typedef boost::error_info<struct tag_small_buffer, std::pair<size_t, size_t> > small_buffer_einfo;
		 typedef boost::error_info<struct tag_bcrypt_handle, void* > bcrypt_handle_einfo;
		 typedef boost::error_info<struct tag_bad_signature_size, size_t > bad_signature_size_einfo;
		 typedef boost::error_info<struct tag_blob_type_name, std::wstring> blob_type_name_einfo;

		 typedef boost::error_info<struct tag_data_size, ULONG> data_size_einfo;


		 struct root : virtual boost::exception, virtual std::exception { };

		 struct bad_data : virtual root {};

		 struct invalid_parameter : virtual root {};
		 struct invalid_handle : virtual root {};

		 struct invalid_cng_handle_op : virtual root {};

		 struct invalid_parameter_handle : virtual invalid_handle, virtual  invalid_parameter {};
		 struct invalid_prop : virtual root {};
		 struct invalid_parameter_value : virtual bad_data {};
		 struct invalid_property_value : virtual invalid_parameter_value {};
		 struct invalid_iv : virtual root {};
		 struct invalid_iv_size : virtual invalid_iv {};
		 struct small_buffer : virtual root {};
		 struct invalid_blob_type : virtual root {};

		 struct key_import_failed : virtual root {};
		 struct key_import_invalid_key_blob_magic : virtual key_import_failed {};
		 struct key_import_corrupted_key_blob : virtual key_import_failed {};

		 struct no_crypt_dll_found : root {};
		 struct badflags : root {};
		 struct badalg : root {};
		 struct badtype : root {};
		 struct bad_permissions : root {};
		 struct bad_key : root {};
		 struct no_key : root {};
		 struct bad_keyset : root {};
		 struct bad_keyset_entry : bad_keyset {};
		 struct bad_signature : virtual root {};
		 struct bad_signature_size : virtual bad_signature {};
		 struct signature_verification_failed : virtual root {};
		 struct bad_len : root {};
		 struct keyset_exists : root {};
		 struct keyset_notdef : root {};
		 struct bad_hash : root {};
		 struct hash_finilized : root {};
		 struct unexpected : virtual root {};
		 struct condition_check_failed : virtual unexpected {};
		 struct unimplemented : root {};
		 struct more_data : root {};
		 struct no_more_items : root {};
		 struct hmac_not_supported : virtual root {};

		 struct io : virtual root {};
		 struct not_found : io {};

		 struct cryptolib_error : root {};

		 struct sh_error : root {
			 sh_error(HRESULT const err_code) : m_error( err_code ) {}
			 HRESULT const get()const throw(){ return m_error; }
		 private: 
			 HRESULT const m_error;
		 };

		 struct cryptoapi_error : root {};


		 /* \brief thrown when invoked on key that does not support required data tranformation interface
		  *
		  */
		 struct bad_key_op : root {};


	 }
}
//================================================================================================================================================
#endif
//================================================================================================================================================
