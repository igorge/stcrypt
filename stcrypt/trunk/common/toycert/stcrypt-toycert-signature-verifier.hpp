//================================================================================================================================================
// FILE: stcrypt-toycert-signature-verifier.h
// (c) GIE 2010-04-02  17:46
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_TOYCERT_SIGNATURE_VERIFIER_2010_04_02_17_46
#define H_GUARD_STCRYPT_TOYCERT_SIGNATURE_VERIFIER_2010_04_02_17_46
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-toycert.hpp"

#include "../../../stcrypt/trunk/stcrypt-csp/util-raii-helpers-crypt.hpp"
//================================================================================================================================================
namespace stcrypt { namespace ca {

	bool verify_signature_via_csp(char const * const blob, size_t const size, toycert_t::signature_blob_t const& signature,   toycert_t& pub_key_from_cert);
	void export_key(HCRYPTPROV const csp, HCRYPTKEY const key, toycert_t & cert, std::vector<char>& exported_and_encrypted_session_key);
	HCRYPTKEY import_key(HCRYPTPROV const csp,  std::vector<char> const& enc_key_blob);

	inline
	void export_key(cryptprov_ptr_t const& csp, cryptkey_ptr_t const& key, toycert_t & cert, std::vector<char>& exported_and_encrypted_session_key){
		return export_key(*csp, *key, cert, exported_and_encrypted_session_key);
	}


	//TODO: move  into another hpp
	template <class T>
	std::vector<char> encrypt_final_pod(HCRYPTKEY const session_key, T const& pod){
		char tmp[sizeof(T)];
		memcpy(&tmp[0], &pod, sizeof(T));
		DWORD size = sizeof(T);
		STCRYPT_CHECK_MSCRYPTO( CryptEncrypt(session_key, 0, TRUE, 0, reinterpret_cast<BYTE*>( &tmp[0] ), &size, sizeof(T)) );
		if( size!=sizeof(T) ) STCRYPT_UNEXPECTED();

		return std::vector<char>(&tmp[0], &tmp[0]+sizeof(T));
	}

	template <class T>
	std::vector<char> encrypt_final_pod(cryptkey_ptr_t const& session_key,  T const& pod){
		return encrypt_final_pod<T>(*session_key, pod);
	}


	inline
	void inplace_encrypt_buffer_final(HCRYPTKEY const session_key, std::vector<char> & buffer){
		assert(buffer.size()!=0);

		DWORD size = buffer.size();
		STCRYPT_CHECK_MSCRYPTO( CryptEncrypt(session_key, 0, TRUE, 0, reinterpret_cast<BYTE*>( &buffer[0] ), &size, buffer.size()) );
		if( size!=buffer.size() ) STCRYPT_UNEXPECTED();
	}

	inline
	void inplace_encrypt_buffer_final(cryptkey_ptr_t const& session_key, std::vector<char> & buffer){
		return inplace_encrypt_buffer_final(*session_key, buffer);
	}

	inline
	void inplace_decrypt_buffer_final(HCRYPTKEY const session_key, std::vector<char> & buffer){
		assert(buffer.size()!=0);

		DWORD size = buffer.size();
		STCRYPT_CHECK_MSCRYPTO( CryptDecrypt(session_key, 0, TRUE, 0, reinterpret_cast<BYTE*>( &buffer[0] ), &size) );
		if( size!=buffer.size() ) STCRYPT_UNEXPECTED();
	}

	inline
	void inplace_decrypt_buffer_final(cryptkey_ptr_t const& session_key, std::vector<char> & buffer){
		return inplace_decrypt_buffer_final(*session_key, buffer);
	}


	template<class T>
	T decrypt_final_pod(HCRYPTKEY const session_key, std::vector<char>& buffer){
		if(buffer.size()!=sizeof(T)) STCRYPT_UNEXPECTED();
		DWORD size = buffer.size();
		STCRYPT_CHECK_MSCRYPTO( CryptDecrypt(session_key, 0, TRUE, 0, reinterpret_cast<BYTE*>(&buffer[0]), &size) );
		if(size!=buffer.size()) STCRYPT_UNEXPECTED();

		T tmp;
		memcpy(&tmp, &buffer[0], sizeof(tmp));

		return tmp;
	}

	template<class T>
	T decrypt_final_pod(cryptkey_ptr_t const& session_key, std::vector<char>& buffer){
		return decrypt_final_pod<T>(*session_key, buffer);
	}


	template <class T>
	void append_pod(std::vector<char>& buffer, T const& pod){
		char tmp_buffer[sizeof(T)];
		memcpy(&tmp_buffer[0], &pod, sizeof(T));

		buffer.insert(buffer.end(), &tmp_buffer[0], &tmp_buffer[0] + sizeof(T));

	}

	inline
	void append_buffer(std::vector<char> & append_to, std::vector<char> const& append_from){
		append_to.insert(append_to.end(), append_from.begin(), append_from.end());
	}

	template<class T>
	T to_pod(std::vector<char> const& buffer){
		T tmp;
		if(buffer.size()!=sizeof(tmp)) STCRYPT_UNEXPECTED();

		memcpy(&tmp, &buffer[0], sizeof(tmp));

		return tmp;
	}

} }
//================================================================================================================================================
#endif
//================================================================================================================================================
