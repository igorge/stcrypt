//================================================================================================================================================
// FILE: stcrypt-cng-fs-keystorage-prop.h
// (c) GIE 2010-09-06  22:35
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_FS_KEYSTORAGE_PROP_2010_09_06_22_35
#define H_GUARD_STCRYPT_CNG_FS_KEYSTORAGE_PROP_2010_09_06_22_35
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-exceptions.hpp"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/numeric/conversion/converter.hpp>
//================================================================================================================================================
namespace stcrypt { namespace stor {


	typedef std::wstring	path_element;
	typedef boost::filesystem::wpath path;

	typedef path_element	prop_name_t;
	typedef path			prop_path_t;

	namespace exception {
		typedef boost::error_info<struct tag_prop_name, std::wstring> prop_name_einfo;

		struct root : virtual stcrypt::exception::root {};
		struct io : virtual stcrypt::exception::io, virtual root {};

		struct property_not_found : virtual io {};
		struct invalid_data : virtual io {};
		struct failed_to_remove_key : virtual io {};
	}

	struct null_file_name_decorator {
		path_element const& decorate(path_element const& elem)const{
			return elem;
		}

		path_element decorate(path_element&& elem)const{
			return std::move( elem );
		}

		path_element const& decorate_root_name(path_element const& elem)const{
			return this->decorate( elem );
		}
		path_element decorate_root_name(path_element&& elem)const{
			return this->decorate( elem );
		}
	};
	
	template <class FileNameDecorator = null_file_name_decorator>
	struct fs_props_t
		: private FileNameDecorator
	{
		fs_props_t(path const& root, path_element const& name)
			: m_root( root / this->decorate_root_name(name) )
		{
		}

		bool create(){
			return boost::filesystem::create_directories(m_root);
		}

		void remove(){

			try {
				boost::filesystem::remove_all( m_root );
			} catch(boost::filesystem::basic_filesystem_error<path> const& e) {
				STCRYPT_THROW_EXCEPTION( stor::exception::failed_to_remove_key() << stor::exception::prop_name_einfo(m_root.native_file_string()) << boost::errinfo_nested_exception( boost::copy_exception(e) ) );
			}
		}

		bool is_root_exists()const{
			return this->is_fs_path_exists_( m_root );
		}

		bool is_prop_exists(prop_name_t const& name)const{
			return this->is_fs_path_exists_( m_root / this->decorate(name) );
		}

		bool is_prop_exists(prop_path_t const& prop_path)const{
			return this->is_fs_path_exists_( prop_path );
		}

		prop_path_t property_path(prop_name_t&& name)const{ return m_root / this->decorate( name ); }
		prop_path_t property_path(prop_name_t const& name)const{ return m_root / this->decorate( name ); }


		template <class U>
		void store(prop_path_t const& prop_path,  U const * data, size_t const size){
			return store_( prop_path, data, size);
		}

		template <class U>
		void store(prop_name_t const& prop_name,  U const * data, size_t const size){
			return store_(  property_path(prop_name), data, size);
		}

		template <class U>
		void store_vec(prop_path_t const& prop_path,  U const& vec){
			return store( prop_path, vec.data(), vec.size() );
		}

		template <class U>
		void store_vec(prop_name_t const& prop_name,  U const& vec){
			return store(  property_path(prop_name), vec.data(), vec.size());
		}

		template <class U>
		std::vector<U> read_vec(prop_name_t const& prop_name){
			return read_<U>( property_path(prop_name) );
		}

		void store_string(prop_name_t const& prop_name, wchar_t const*const str){
			return store( prop_name, str, wcslen(str) );
		}

		std::wstring read_string(prop_name_t const& prop_name){
			auto const& prop_data = read_<wchar_t>( property_path(prop_name) );
			return std::wstring(prop_data.data(), prop_data.size());
		}

	private:


		bool is_fs_path_exists_(path const& prop_path)const{
			return boost::filesystem::exists( prop_path );
		}

		void remove_path_(path const& p){
			if( !boost::filesystem::remove(p) ) STCRYPT_UNEXPECTED();
		}

		void remove_prop_(path const& decorated_name){
			path const& prop_path = m_root / decorated_name;

			if( !is_prop_exists_( prop_path ) ) STCRYPT_THROW_EXCEPTION( stor::exception::property_not_found() << stor::exception::prop_name_einfo(decorated_name) );
			remove_path_( prop_path );
		}



		template <class U>
		void store_(prop_path_t const& prop_path,  U const * data, size_t const size){
			boost::filesystem::ofstream key_set_prop_file( prop_path, std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
			if( key_set_prop_file.bad() ) {
				STCRYPT_THROW_EXCEPTION(stor::exception::io());
			}
			key_set_prop_file.write( reinterpret_cast<char const *>(data), static_cast<std::streamsize>(size*sizeof(U)));
			key_set_prop_file.flush();
			key_set_prop_file.close();
			if( key_set_prop_file.bad() ) {
				STCRYPT_THROW_EXCEPTION(stor::exception::io());
			}
		}

		template <class U>
		std::vector<U> read_(prop_path_t const& prop_path) {


			if( !is_prop_exists(prop_path) ) STCRYPT_THROW_EXCEPTION( stor::exception::property_not_found() << stor::exception::prop_name_einfo( prop_path.native_file_string() ) );

			boost::filesystem::ifstream key_set_prop_file(prop_path, std::ios_base::in | std::ios_base::binary);
			if( !key_set_prop_file.good() )
				STCRYPT_THROW_EXCEPTION(stor::exception::io());

			key_set_prop_file.seekg(0, std::ios::end);
			std::streamsize const prop_size = key_set_prop_file.tellg();
			key_set_prop_file.seekg(0);
			if( key_set_prop_file.bad() ) 
				STCRYPT_THROW_EXCEPTION(stor::exception::io());

			if( prop_size%sizeof(U)!=0 )
				STCRYPT_THROW_EXCEPTION(stor::exception::invalid_data());

			std::vector<U> data;

			if(prop_size!=0){
				auto const client_prop_size = boost::numeric::converter<std::size_t,std::streamsize>::convert( prop_size/sizeof(U) );
				data.resize(client_prop_size);
				key_set_prop_file.read( reinterpret_cast<char*>(&data[0]), prop_size);
				if( key_set_prop_file.bad() )
					STCRYPT_THROW_EXCEPTION(stor::exception::io());
			}

			return std::move( data );
		}


	private:
		path m_root;
	};



} }

//================================================================================================================================================
#endif
//================================================================================================================================================
