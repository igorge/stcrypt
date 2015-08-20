//================================================================================================================================================
// FILE: stcrypt-key-storage-prop.h
// (c) GIE 2009-11-11  22:52
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_KEY_STORAGE_PROP_2009_11_11_22_52
#define H_GUARD_STCRYPT_KEY_STORAGE_PROP_2009_11_11_22_52
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "util-md5.hpp"
#include "stcrypt-exceptions.hpp"
#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
//================================================================================================================================================
namespace stcrypt {

	namespace exception {
		struct prop_not_found : exception::not_found {};

		typedef boost::error_info<struct tag_prop_name, std::string> prop_name_einfo;
	}



	struct keyset_props_t
	{
		keyset_props_t(boost::filesystem::wpath const& keyset_root)
			: m_keyset_root(keyset_root)
		{}

		void remove(std::string const& name){
			boost::filesystem::wpath const prop_path ( keyset_root() / create_md5_hash(name) );
			if( !is_prop_exists_(prop_path) ) STCRYPT_THROW_EXCEPTION(exception::prop_not_found());

			if( !boost::filesystem::remove(prop_path) ) STCRYPT_UNEXPECTED();
		}


		void store(std::string const& name,std::vector<BYTE> const& data){
			return store_(name, &data[0], data.size());
		}

		void store(std::string const& name,std::vector<char> const& data){
			return store_(name, &data[0], data.size());
		}

		void store(std::string const& name, std::string const& data){
			return store_(name, data);
		}

		void store(std::string const& name, std::wstring const& data){
			return store_(name, data);
		}

		void store(std::string const& name, long const data){
			std::vector<BYTE> buff( sizeof(data) );
			memcpy(&buff[0], &data, buff.size());

			return store(name, buff);
		}

		void store(std::string const& name, unsigned int const data){
			std::vector<BYTE> buff( sizeof(data) );
			memcpy(&buff[0], &data, buff.size());

			return store(name, buff);
		}

		void read(std::string const& name, std::string& data){
			return read_(name, data);
		}

		void read(std::string const& name, std::wstring& data){
			return read_(name, data);
		}

		void read(std::string const& name, std::vector<BYTE>& data){
			return read_(name, data);
		}

		void read(std::string const& name, std::vector<char>& data){
			return read_(name, data);
		}


		void read(std::string const& name, long& data){
			std::vector<BYTE> buff( sizeof(data) );
			read(name, buff);
			if(buff.size()!=sizeof(data)){
				STCRYPT_UNEXPECTED();
			}

			memcpy(&data, &buff[0], buff.size());
		}

		void read(std::string const& name, unsigned int& data){
			std::vector<BYTE> buff( sizeof(data) );
			read(name, buff);
			if(buff.size()!=sizeof(data)){
				STCRYPT_UNEXPECTED();
			}

			memcpy(&data, &buff[0], buff.size());
		}

		boost::filesystem::wpath const& keyset_root()const {
			return m_keyset_root;
		}

		bool is_prop_exists(std::string const name){
			return is_prop_exists_(  keyset_root() / create_md5_hash(name) );
		}

	private:

		bool is_prop_exists_(boost::filesystem::wpath const& prop_path){
			return boost::filesystem::exists( prop_path );

		}

		template <class T>
		void store_(std::string const& name, T const& data){
			store_(name, data.data(), data.size());
		}

		template <class U>
		void store_(std::string const& name,  U const * data, size_t const size){
			boost::filesystem::ofstream key_set_prop_file( keyset_root() / create_md5_hash(name), std::ios_base::out | std::ios_base::trunc | std::ios_base::binary);
			if( key_set_prop_file.bad() ) {
				STCRYPT_THROW_EXCEPTION(exception::io());
			}
			key_set_prop_file.write( reinterpret_cast<char const *>(data), static_cast<std::streamsize>(size*sizeof(U)));
			key_set_prop_file.flush();
			key_set_prop_file.close();
			if( key_set_prop_file.bad() ) {
				STCRYPT_THROW_EXCEPTION(exception::io());
			}

		}

		template <class T>
		void read_(std::string const& name, T& data) {
			boost::filesystem::wpath const prop_path ( keyset_root() / create_md5_hash(name) );
			if( !is_prop_exists_(prop_path) ) STCRYPT_THROW_EXCEPTION(exception::prop_not_found() << exception::prop_name_einfo(name) );

			boost::filesystem::ifstream key_set_prop_file( prop_path, std::ios_base::in | std::ios_base::binary);
			if( !key_set_prop_file.good() ) {
				STCRYPT_THROW_EXCEPTION(exception::io());
			}

			key_set_prop_file.seekg(0, std::ios::end);
			std::streamsize const prop_size = key_set_prop_file.tellg();
			key_set_prop_file.seekg(0);
			if( key_set_prop_file.bad() ) {
				STCRYPT_THROW_EXCEPTION(exception::io());
			}
			if( (prop_size%sizeof(typename T::value_type))!=0 ){
				STCRYPT_UNEXPECTED();
			}
			std::vector<typename T::value_type> tmp_stor;
			if(prop_size!=0){
				std::size_t const client_prop_size = prop_size/sizeof(typename T::value_type);
				tmp_stor.resize(client_prop_size);
				key_set_prop_file.read(reinterpret_cast<char*>(&tmp_stor[0]), prop_size);
				if( key_set_prop_file.bad() ) {
					STCRYPT_THROW_EXCEPTION(exception::io());
				}
			}
			data.assign(tmp_stor.begin(), tmp_stor.end() );
		}

		void read_(std::string const& name, std::vector<BYTE> & data) {

			BOOST_STATIC_ASSERT( sizeof(BYTE)==sizeof(char) );

			boost::filesystem::wpath const prop_path ( keyset_root() / create_md5_hash(name) );
			if( !is_prop_exists_(prop_path) ) STCRYPT_THROW_EXCEPTION(exception::prop_not_found());

			boost::filesystem::ifstream key_set_prop_file(prop_path, std::ios_base::in | std::ios_base::binary);
			if( !key_set_prop_file.good() )
				STCRYPT_THROW_EXCEPTION(exception::io());

			key_set_prop_file.seekg(0, std::ios::end);
			std::streamsize const prop_size = key_set_prop_file.tellg();
			key_set_prop_file.seekg(0);
			if( key_set_prop_file.bad() ) 
				STCRYPT_THROW_EXCEPTION(exception::io());

			if(prop_size!=0){
				std::size_t const client_prop_size = prop_size;
				data.resize(client_prop_size);
				key_set_prop_file.read( reinterpret_cast<char*>(&data[0]), prop_size);
				if( key_set_prop_file.bad() )
					STCRYPT_THROW_EXCEPTION(exception::io());
			}
		}


	private:
		boost::filesystem::wpath m_keyset_root;
	};

}
//================================================================================================================================================
#endif
//================================================================================================================================================
