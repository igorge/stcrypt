//================================================================================================================================================
// FILE: stcrypt-csp-factory.cpp
// (c) GIE 2009-11-02  17:38
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "util-bittest.hpp"
#include "stcrypt-csp-factory.hpp"
#include "stcrypt-key-storage.hpp"
//================================================================================================================================================
namespace stcrypt {
//================================================================================================================================================
	boost::intrusive_ptr<stcrypt::csp_t>
	create_csp(IN  LPCSTR szContainer, IN  DWORD dwFlags, IN  PVTableProvStruc pVTable)
	{
		if( test_if_any_out_of_mask<DWORD>(dwFlags, CRYPT_NEWKEYSET|CRYPT_VERIFYCONTEXT|CRYPT_DELETEKEYSET) )
			STCRYPT_THROW_EXCEPTION(exception::badflags());

		std::string const name = szContainer ? std::string(szContainer):std::string("__DEFAULT__");
		if( test_mask<DWORD>(dwFlags, CRYPT_NEWKEYSET|CRYPT_DELETEKEYSET) ) {
			STCRYPT_THROW_EXCEPTION(exception::badflags());
		}
		if( test_mask<DWORD>(dwFlags, CRYPT_NEWKEYSET|CRYPT_VERIFYCONTEXT) ) {
			STCRYPT_THROW_EXCEPTION(exception::badflags());
		}
		if( test_mask<DWORD>(dwFlags, CRYPT_DELETEKEYSET|CRYPT_VERIFYCONTEXT) ) {
			STCRYPT_THROW_EXCEPTION(exception::badflags());
		}
		
		key_storage_manager_ptr key_storage_manager ( new nonvolatile_key_storage_manager_t());

		if( test_mask<DWORD>(dwFlags, CRYPT_DELETEKEYSET) ) {
			key_storage_manager->delete_keyset(name);
			return boost::intrusive_ptr<stcrypt::csp_t>();
		} else if( test_mask<DWORD>(dwFlags, CRYPT_VERIFYCONTEXT) ) {
			key_storage_base_ptr keyset_storage( new volatile_key_storage_t(name) );
			try{
				return boost::intrusive_ptr<stcrypt::csp_t>( new csp_t(key_storage_manager->create_keyset( name, keyset_create() ), true) );
			} catch(exception::keyset_exists const&)
			{
				return boost::intrusive_ptr<stcrypt::csp_t>( new csp_t(key_storage_manager->create_keyset( name, keyset_open() ), true) );
			}
		} else if( test_mask<DWORD>(dwFlags, CRYPT_NEWKEYSET) ) {
			return boost::intrusive_ptr<stcrypt::csp_t>( new csp_t(key_storage_manager->create_keyset( name, keyset_create() ), false) );
		} else {
			return boost::intrusive_ptr<stcrypt::csp_t>( new csp_t(key_storage_manager->create_keyset( name, keyset_open() ), false) );
		}

	}
//================================================================================================================================================

}
//================================================================================================================================================
