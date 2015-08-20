//================================================================================================================================================
// FILE: stcrypt-key-storage.h
// (c) GIE 2009-11-02  18:03
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_KEY_STORAGE_2009_11_02_18_03
#define H_GUARD_STCRYPT_KEY_STORAGE_2009_11_02_18_03
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "utll-capi-get-param-enums-impl.hpp"
#include "util-atomic-counter.hpp"
#include "stcrypt-key-storage-prop.hpp"

#include "boost/intrusive_ptr.hpp"
#include "boost/noncopyable.hpp"
#include "boost/filesystem/path.hpp"

#include <string>
#include <vector>
//================================================================================================================================================
namespace stcrypt {


	struct keyset_open {};
	struct keyset_create {};

	namespace key_role {
		enum type { any=0, sign, keyx};
	}
	
	struct key_storage_base_t;
	//================================================================================================================================================
	struct key_storage_manager_base_t
		: atomic_counter_def_impl_t
		, boost::noncopyable
	{
		virtual boost::intrusive_ptr<key_storage_base_t> create_keyset(std::string const & keyset_name, keyset_create const& op_tag )=0;
		virtual boost::intrusive_ptr<key_storage_base_t> create_keyset(std::string const & keyset_name, keyset_open const& op_tag )=0;
		virtual void enum_containers(BYTE* const data, DWORD * const datalen, DWORD const flags)=0;

		virtual ~key_storage_manager_base_t(){}
	};
	typedef boost::intrusive_ptr<key_storage_manager_base_t> key_storage_manager_base_ptr;

	struct nonvolatile_key_storage_manager_t
		: key_storage_manager_base_t
		, get_param_enums_impl_t<nonvolatile_key_storage_manager_t, std::string,boost::filesystem::wdirectory_iterator>
	{
		typedef get_param_enums_impl_t<nonvolatile_key_storage_manager_t, std::string,boost::filesystem::wdirectory_iterator> enum_containers_impl_type;

		friend enum_containers_impl_type;

		virtual boost::intrusive_ptr<key_storage_base_t> create_keyset(std::string const & keyset_name, keyset_create const& op_tag );
		virtual boost::intrusive_ptr<key_storage_base_t> create_keyset(std::string const & keyset_name, keyset_open const& op_tag );

		void delete_keyset(std::string const & keyset_name);


		nonvolatile_key_storage_manager_t();

		boost::filesystem::wpath const& get_key_storage_root()const {
			return m_key_storage_root;
		}

	private:
		enum_containers_impl_type* get_container_enum_(){
			return static_cast<enum_containers_impl_type*>( this );
		}

		virtual void enum_containers(BYTE* const data, DWORD * const datalen, DWORD const flags);

		//////////////////////////////////////////////////////////////////////////
		// enum_containers_impl_type
		std::pair<enum_containers_impl_type::iterator_type,enum_containers_impl_type::iterator_type> 
			init_iters_(enum_containers_impl_type::tag_type const);
		void from_iter_to_item_(enum_containers_impl_type::tag_type const, enum_containers_impl_type::iterator_type& iter, std::string& item);
		void copy_func_(enum_containers_impl_type::tag_type const, enum_containers_impl_type::item_type const& item, BYTE* const data, DWORD const datalen);
		size_t item_size_(enum_containers_impl_type::tag_type const, std::string const& item)const;


	private:
		static std::wstring const app_data_root_();
	private:
		boost::filesystem::wpath m_key_storage_root;
	};

	typedef boost::intrusive_ptr<nonvolatile_key_storage_manager_t> key_storage_manager_ptr;

	//================================================================================================================================================
	struct key_storage_base_t
		: atomic_counter_impl_t
		, boost::noncopyable
	{
		refcnt add_ref() { return ccom_internal_inc_ref_(); }		
		refcnt dec_ref() { return ccom_internal_dec_ref_(); }

		key_storage_base_t(std::string const & keyset_name)
			: m_keyset_name( keyset_name )
		{}
		virtual ~key_storage_base_t() {}

		virtual void get_sign_key_data(std::vector<BYTE> & data)=0;
		virtual void get_keyx_key_data(std::vector<BYTE> & data)=0;
		virtual void store_sign_keyx_data(std::vector<BYTE> const& key_data)=0;
		virtual void store_sign_sign_data(std::vector<BYTE> const& key_data)=0;

		virtual key_storage_manager_base_ptr get_manager()=0;

		std::string const& name()const {
			return m_keyset_name;
		}
		
	protected:
		std::string const		 m_keyset_name;
	};
	typedef boost::intrusive_ptr<key_storage_base_t> key_storage_base_ptr;

	//================================================================================================================================================
	struct nonvolatile_key_storage_t 
		: key_storage_base_t
		, keyset_props_t
	{
		friend nonvolatile_key_storage_manager_t;

		virtual key_storage_manager_base_ptr get_manager();

		virtual void get_sign_key_data(std::vector<BYTE> & data);
		virtual void get_keyx_key_data(std::vector<BYTE> & data);
		virtual void store_sign_keyx_data(std::vector<BYTE> const& key_data);
		virtual void store_sign_sign_data(std::vector<BYTE> const& key_data);


	private:
		nonvolatile_key_storage_t(key_storage_manager_ptr const& key_storage_manager, std::string const & keyset_name, keyset_create const& op_tag );
		nonvolatile_key_storage_t(key_storage_manager_ptr const& key_storage_manager, std::string const & keyset_name, keyset_open const& op_tag );
	private:
		key_storage_manager_ptr m_key_storage_manager;
		std::vector<BYTE> m_keyx;
		std::vector<BYTE> m_sign;
	};

	//================================================================================================================================================
	struct volatile_key_storage_t 
		: key_storage_base_t
	{
		volatile_key_storage_t(std::string const & keyset_name)
			: key_storage_base_t(keyset_name)
		{}

		virtual key_storage_manager_base_ptr get_manager(){
			STCRYPT_UNEXPECTED();
		}

		virtual void get_sign_key_data(std::vector<BYTE> & data){
			STCRYPT_UNIMPLEMENTED();
		}
		virtual void get_keyx_key_data(std::vector<BYTE> & data){
			STCRYPT_UNIMPLEMENTED();
		}
		virtual void store_sign_keyx_data(std::vector<BYTE> const& key_data){
			STCRYPT_UNIMPLEMENTED();
		}
		virtual void store_sign_sign_data(std::vector<BYTE> const& key_data){
			STCRYPT_UNIMPLEMENTED();

		}

	};

//================================================================================================================================================
	inline void intrusive_ptr_add_ref(key_storage_base_t * const p)
	{
		p->add_ref();
	}
	inline void intrusive_ptr_release(key_storage_base_t * const p)throw()
	{
		if( p->dec_ref() ==0 ) delete p;
	}
//================================================================================================================================================

}
//================================================================================================================================================
#endif
//================================================================================================================================================
