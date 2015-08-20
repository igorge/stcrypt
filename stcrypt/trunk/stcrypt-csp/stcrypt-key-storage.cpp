//================================================================================================================================================
// FILE: stcrypt-key-storage.cpp
// (c) GIE 2009-11-02  18:03
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "util-raii-helpers-crypt.hpp"
#include "stcrypt-key-storage.hpp"
#include "stcrypt-exceptions.hpp"

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include <shlobj.h>
//================================================================================================================================================
namespace stcrypt {

	typedef boost::error_info<struct tag_keyset_name, std::string const > keyset_name_einfo;

	//================================================================================================================================================
	nonvolatile_key_storage_manager_t::nonvolatile_key_storage_manager_t()
		: m_key_storage_root( boost::filesystem::wpath( app_data_root_() ) / TEXT("Microsoft\\Crypto\\STCRYPT") )
	{
		if( !boost::filesystem::exists(m_key_storage_root) ) {
			boost::filesystem::create_directories(m_key_storage_root);
		}

	}

	std::wstring const nonvolatile_key_storage_manager_t::app_data_root_()
	{
		TCHAR app_dir[MAX_PATH];

		ITEMIDLIST* pidl;
		HRESULT const hRes = SHGetSpecialFolderLocation( NULL, CSIDL_APPDATA|CSIDL_FLAG_CREATE , &pidl );
		if (hRes!=NOERROR) STCRYPT_THROW_EXCEPTION( exception::sh_error(hRes) );
		if( !SHGetPathFromIDList( pidl, app_dir ) ) STCRYPT_THROW_EXCEPTION( exception::sh_error(E_UNEXPECTED) );
		return std::wstring(&app_dir[0], MAX_PATH);

	}

	void nonvolatile_key_storage_manager_t::enum_containers(BYTE* const data, DWORD * const datalen, DWORD const flags){
		return get_container_enum_()->get_param__enum_impl_(data, datalen, flags);
	}

	void nonvolatile_key_storage_manager_t::delete_keyset(std::string const & keyset_name){
		boost::filesystem::wpath const keyset_root( get_key_storage_root() / create_md5_hash( keyset_name ) );
		if( !boost::filesystem::exists(keyset_root) ) STCRYPT_THROW_EXCEPTION(exception::bad_keyset());

		boost::filesystem::remove_all( keyset_root );

	}


	boost::intrusive_ptr<key_storage_base_t> nonvolatile_key_storage_manager_t::create_keyset(std::string const & keyset_name, keyset_create const& op_tag ){
		return boost::intrusive_ptr<key_storage_base_t>( new nonvolatile_key_storage_t(key_storage_manager_ptr(this),keyset_name, op_tag ) );
	}
	boost::intrusive_ptr<key_storage_base_t> nonvolatile_key_storage_manager_t::create_keyset(std::string const & keyset_name, keyset_open const& op_tag ){
		return boost::intrusive_ptr<key_storage_base_t>( new nonvolatile_key_storage_t(key_storage_manager_ptr(this),keyset_name, op_tag ) );
	}

	std::pair<nonvolatile_key_storage_manager_t::enum_containers_impl_type::iterator_type,nonvolatile_key_storage_manager_t::enum_containers_impl_type::iterator_type> 
		nonvolatile_key_storage_manager_t::init_iters_(enum_containers_impl_type::tag_type const) 
	{
		if (!boost::filesystem::exists(get_key_storage_root())){
			STCRYPT_UNEXPECTED();
		}

		return std::make_pair( enum_containers_impl_type::iterator_type(get_key_storage_root()) , enum_containers_impl_type::iterator_type() );
	}

	void nonvolatile_key_storage_manager_t::from_iter_to_item_(enum_containers_impl_type::tag_type const, enum_containers_impl_type::iterator_type& iter, std::string& item){
		keyset_props_t props(*iter);
		props.read("name", item);
	}

	void nonvolatile_key_storage_manager_t::copy_func_(enum_containers_impl_type::tag_type const, enum_containers_impl_type::item_type const& item, BYTE* const data, DWORD const datalen){
		assert(item.size()+1==datalen);
		memcpy(data, item.c_str(), datalen);
	}
	size_t nonvolatile_key_storage_manager_t::item_size_(enum_containers_impl_type::tag_type const, std::string const& item)const{
		return item.size()+1;
	}

	//================================================================================================================================================
	nonvolatile_key_storage_t::nonvolatile_key_storage_t(key_storage_manager_ptr const& key_storage_manager, std::string const & keyset_name, keyset_create const& op_tag )
		: key_storage_base_t(keyset_name)
		, keyset_props_t(key_storage_manager->get_key_storage_root() / create_md5_hash( keyset_name))
		, m_key_storage_manager(key_storage_manager)
	{
		try {
 			
			if( boost::filesystem::exists(keyset_root()) ) {
				STCRYPT_THROW_EXCEPTION(exception::keyset_exists());
			}

			boost::filesystem::create_directory( keyset_root() );

			try {
				static_cast<keyset_props_t*>(this)->store("name",keyset_name);
			} catch (exception::io const&){ 
				STCRYPT_THROW_EXCEPTION(exception::bad_keyset());
			}

		} catch (boost::exception& e) {
			e << keyset_name_einfo(keyset_name);
			throw;
		}
	}


	nonvolatile_key_storage_t::nonvolatile_key_storage_t(key_storage_manager_ptr const& key_storage_manager, std::string const & keyset_name, keyset_open const& op_tag )
		: key_storage_base_t(keyset_name)
		, keyset_props_t(key_storage_manager->get_key_storage_root() / create_md5_hash( keyset_name))
		, m_key_storage_manager(key_storage_manager)
	{
		try {

			if( !boost::filesystem::exists( keyset_root() ) ) {
				STCRYPT_THROW_EXCEPTION(exception::keyset_notdef());
			}

			std::string stored_keyset_name;

			try {
				static_cast<keyset_props_t*>(this)->read("name",stored_keyset_name);
			} catch (exception::io const&){ 
				STCRYPT_THROW_EXCEPTION(exception::bad_keyset_entry());
			}
			
			if(keyset_name!=stored_keyset_name){
				STCRYPT_THROW_EXCEPTION(exception::bad_keyset_entry());
			}


		} catch (boost::exception& e) {
			e << keyset_name_einfo(keyset_name);
			throw;
		}
	}

	key_storage_manager_base_ptr nonvolatile_key_storage_t::get_manager(){
		return m_key_storage_manager;
	}


	void nonvolatile_key_storage_t::get_sign_key_data(std::vector<BYTE> & data){
		try{
			static_cast<keyset_props_t*>(this)->read("AT_SIGNATURE",m_sign);
		}catch(exception::io const&){
			STCRYPT_THROW_EXCEPTION(exception::no_key());
		}

		data = m_sign;
	}
	void nonvolatile_key_storage_t::get_keyx_key_data(std::vector<BYTE> & data){
		try{
			static_cast<keyset_props_t*>(this)->read("AT_KEYEXCHANGE",m_keyx);
		}catch(exception::io const&){
			STCRYPT_THROW_EXCEPTION(exception::no_key());
		}

		data = m_keyx;
	}

	void nonvolatile_key_storage_t::store_sign_keyx_data(std::vector<BYTE> const& key_data){
		m_keyx = key_data ;
		static_cast<keyset_props_t*>(this)->store("AT_KEYEXCHANGE",m_keyx);
	}
	void nonvolatile_key_storage_t::store_sign_sign_data(std::vector<BYTE> const& key_data){
		m_sign = key_data ;
		static_cast<keyset_props_t*>(this)->store("AT_SIGNATURE",m_sign);
	}

}
//================================================================================================================================================
