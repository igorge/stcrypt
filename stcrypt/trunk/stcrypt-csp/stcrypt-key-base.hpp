//================================================================================================================================================
// FILE: stcrypt-key-base.h
// (c) GIE 2009-11-06  15:30
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_KEY_BASE_2009_11_06_15_30
#define H_GUARD_STCRYPT_KEY_BASE_2009_11_06_15_30
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-hash-base.hpp"
#include "util-capi-get-param-impl.hpp"
#include "stcrypt-exceptions.hpp"
#include "stcrypt-symmetric-base.hpp"
#include "util-atomic-counter.hpp"
#include "boost/intrusive_ptr.hpp"
#include "boost/noncopyable.hpp"

#include "boost/bind.hpp"
#include "boost/weak_ptr.hpp"

#include <vector>
//================================================================================================================================================
namespace stcrypt {

	struct csp_t;

	namespace key_op {
		struct derive {};
		struct generate {};
		struct load_from_blob {};
		struct init_from_other {};
	}

	/*! \brief Interface for keys that supports in-place data transformation
	 *
	 *
	 */
	struct cryptoapi_key_inplace_op_i {
		virtual size_t invoke_cipher_encrypt(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){ /*!< inplace encode*/
			STCRYPT_THROW_EXCEPTION(exception::bad_key_op());
		}
		virtual size_t invoke_cipher_decrypt(BYTE * const data, size_t const data_len, size_t const buffer_len, hash_impl_base_t * const hasher, bool const final){ /*!< inplace decode*/
			STCRYPT_THROW_EXCEPTION(exception::bad_key_op());
		}
	protected:
		~cryptoapi_key_inplace_op_i(){}
	};


	/*! \brief Interface for keys that supports key exporting
	 *
	 *
	 */
	struct export_key_op_i {
		virtual void export_key_blob(std::vector<BYTE>& key_blob){
			STCRYPT_UNIMPLEMENTED();
		}
		virtual size_t key_blob_size(){
			STCRYPT_UNIMPLEMENTED();
		}

	};


	/*! \brief Interface for private/public keys that supports key exporting
	 *
	 *
	 */
	struct export_privpub_key_op_i {
		virtual void export_public_key_blob(std::vector<BYTE>& key_blob){
			STCRYPT_UNIMPLEMENTED();
		}
		virtual size_t public_key_blob_size(){
			STCRYPT_UNIMPLEMENTED();
		}

	};

	/*! \brief Interface for keys that supports non in-place data transformation
	 *
	 *
	 */
	struct cryptoapi_key_buffer_op_i {
		virtual size_t invoke_cipher_encrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len, hash_impl_base_t * const hasher, bool const final){ /*!< inplace encode*/
			STCRYPT_THROW_EXCEPTION(exception::bad_key_op());
		}
		virtual size_t invoke_cipher_decrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len, hash_impl_base_t * const hasher, bool const final){ /*!< inplace decode*/
			STCRYPT_THROW_EXCEPTION(exception::bad_key_op());
		}
		virtual std::pair<size_t,size_t> buffers_sizes(){
			STCRYPT_THROW_EXCEPTION(exception::bad_key_op());
		}

	protected:
		~cryptoapi_key_buffer_op_i(){}
	};

	struct signature_op_i {
		virtual size_t get_signature_size(){ STCRYPT_UNIMPLEMENTED(); }
		virtual void sign(BYTE const* const data, size_t const data_size, BYTE * const sign_buffer, size_t const sign_buffer_sisze){ STCRYPT_UNIMPLEMENTED(); }
		virtual bool verify(BYTE const* const data, size_t const data_size, BYTE const * const sign_buffer, size_t const sign_buffer_sisze){ STCRYPT_UNIMPLEMENTED(); }

	};

	/*! \brief Interface for all key types
	 *
	 *
	 */
	struct cryptoapi_key_base_t
		: boost::noncopyable
		, atomic_counter_def_impl_t
		, cryptoapi_key_inplace_op_i
		, cryptoapi_key_buffer_op_i
		, export_key_op_i
		, export_privpub_key_op_i
		, signature_op_i
	{
		enum op_mode_type {op_none=0, op_encrypt, op_decrypt};

		virtual DWORD get_blocklen()=0;
		virtual ALG_ID get_alg_id()const{
			STCRYPT_UNIMPLEMENTED(); //TODO: implement for all keys
		}
		virtual void set_iv(BYTE const*const iv){ STCRYPT_UNIMPLEMENTED(); /*override only for keys that support iv init*/ }

		void set_param(DWORD const param, BYTE const * const data){
			switch(param) {
				case KP_IV:  return set_iv(data);
				default: STCRYPT_THROW_EXCEPTION(exception::badtype());
			}

		}

		void get_param(DWORD const param, BYTE* const data, DWORD * const datalen){
			assert(datalen);
			switch(param) {
				case KP_BLOCKLEN: return get_param__blocklen_(data, datalen);
				case KP_ALGID:  return get_param__alg_id_(data, datalen);
				default: STCRYPT_THROW_EXCEPTION(exception::badtype());
			}

		}

		cryptoapi_key_base_t(csp_t * const csp);
		virtual ~cryptoapi_key_base_t();
		explicit cryptoapi_key_base_t(cryptoapi_key_base_t const& other);

		boost::weak_ptr<csp_t> const& get_csp()const{
			return m_csp;
		}

		virtual boost::intrusive_ptr<cryptoapi_key_base_t> clone()=0;
	private:
		void get_param__blocklen_(BYTE* const data, DWORD * const datalen){
			DWORD const blocklen = get_blocklen();
			return capi_get_param_impl(sizeof(blocklen), data, datalen, boost::bind(memcpy, _1,&blocklen , _2));
		}
		void get_param__alg_id_(BYTE* const data, DWORD * const datalen){
			ALG_ID const alg_id = get_alg_id();
			return capi_get_param_impl(sizeof(alg_id), data, datalen, boost::bind(memcpy, _1,&alg_id , _2));
		}
	private:
		boost::weak_ptr<csp_t> m_csp;
	};
	typedef boost::intrusive_ptr<cryptoapi_key_base_t> key_base_ptr;

//================================================================================================================================================
}
//================================================================================================================================================
#endif
//================================================================================================================================================
