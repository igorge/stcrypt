//================================================================================================================================================
// FILE: stcrypt-cng-keystorage-provider.cpp
// (c) GIE 2010-08-26  14:02
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "stcrypt-cng-fs-keystorage-prop.hpp"
#include "stcrypt-cng-keystorage-provider.hpp"
#include "stcrypt-crypto-alg-ids.h"
#include "util-bittest.hpp"
#include "util-cng-wrap.hpp"
#include "util-cng-obj-alloc.hpp"
#include "util-sio-cng.hpp"
#include "util-cng-get-prop.hpp"

#include <shlobj.h>

#include <boost/filesystem.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
#include <boost/range.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/scope_exit.hpp>
#include <boost/array.hpp>

#include <numeric>
//================================================================================================================================================
namespace stcrypt {

	typedef stor::path				  storage_path;
	typedef stor::fs_props_t<>		  key_set_props_t;

	stor::prop_name_t const prop_alg_id=L"cng-alg-id";
	stor::prop_name_t const prop_key_blob=L"cng-key-blob";
	stor::prop_name_t const prop_key_blob_type=L"cng-key-blob-type";

	namespace { namespace tag {
		struct create_key {};
		struct open_key {};
	} }


	namespace {

		//these functions invoked in static init context, so logger is not available yet

		std::wstring app_data_root()
		{
			TCHAR app_dir[MAX_PATH];

			ITEMIDLIST* pidl;
			HRESULT const hRes = SHGetSpecialFolderLocation( NULL, CSIDL_APPDATA|CSIDL_FLAG_CREATE , &pidl );
			if (hRes!=NOERROR) return std::wstring();//STCRYPT_THROW_EXCEPTION( exception::sh_error(hRes) );
			if( !SHGetPathFromIDList( pidl, app_dir ) ) STCRYPT_THROW_EXCEPTION( exception::sh_error(E_UNEXPECTED) );
			return std::wstring(&app_dir[0], MAX_PATH);
		}

		std::wstring system_root()
		{
			TCHAR app_dir[MAX_PATH];

			ITEMIDLIST* pidl;
			HRESULT const hRes = SHGetSpecialFolderLocation( NULL, CSIDL_SYSTEM, &pidl );
			if (hRes!=NOERROR) return std::wstring(); //{ STCRYPT_THROW_EXCEPTION( exception::sh_error(hRes) ); }
			if( !SHGetPathFromIDList( pidl, app_dir ) ) return std::wstring(); //STCRYPT_THROW_EXCEPTION( exception::sh_error(E_UNEXPECTED) );
			return std::wstring(&app_dir[0], MAX_PATH);
		}

		storage_path cng_keystorage_root(){ 
			//CSP_LOG_TRACE

			try{
				return storage_path( app_data_root() ) / TEXT("Microsoft\\Crypto\\CNG-STCRYPT"); 
			}catch(exception::sh_error const&){
				//STCRYPT_LOG_A_STRING("We are working in a strange context, returning empty user keystorage root, it is ok if we do need access only to the machine wide keys.");

				return storage_path();
			}
		}

		storage_path cng_machine_keystorage_root(){
			//CSP_LOG_TRACE

			return storage_path( system_root() ) / TEXT("config\\systemprofile\\AppData\\Roaming\\Microsoft\\Crypto\\CNG-STCRYPT"); 
		}

	}

	struct cng_n_key_private_i 
		: cng_n_key_object_op_i
	{
		virtual BCRYPT_KEY_HANDLE key_handle()=0;

	};


	struct cng_keystorage_class
		: cng_keystorage_class_op_i 
	{

		cng_keystorage_class(){
			//CSP_LOG_TRACE

			//STCRYPT_LOG_PRINT_W_EX( L"Key storage root: ", this->keystorage_root() );
			
		}

		virtual void destroy_self(){delete this;}

		virtual cng_n_key_handle_op_i_ptr_t create_key(LPCWSTR const alg_id, LPCWSTR const key_name, DWORD const legacy_key_spec, bool const is_machine_key, DWORD const flags);
		virtual cng_n_key_handle_op_i_ptr_t create_ephemeral_key(LPCWSTR const alg_id, DWORD const legacy_key_spec, DWORD const flags);
		virtual cng_n_key_handle_op_i_ptr_t open_key(LPCWSTR const key_name, DWORD const legacy_key_spec, bool const is_machine_key, DWORD const flags);

		virtual cng_n_key_handle_op_i_ptr_t import_ephemeral_key(NCRYPT_KEY_HANDLE const export_key, LPCWSTR const pszBlobType, PBYTE const pbData, DWORD const cbData, DWORD const dwFlags);
		virtual DWORD export_key(cng_n_key_object_op_i * const key_to_export, NCRYPT_KEY_HANDLE const export_key, LPCWSTR const pszBlobType, NCryptBufferDesc *const pParameterList , PBYTE const pbOutput,  DWORD const cbOutput, DWORD const dwFlags);

		virtual unsigned int enumerate_algorithms(DWORD const dwAlgOperations, NCryptAlgorithmName *& ppAlgList);

		virtual stcrypt::buffer_t enum_keys_init(bool const is_machine_keys);
		virtual bool enum_keys_current(void* const state, NCryptKeyName *const key_name);

		DWORD key_blob_size(cng_n_key_object_op_i * const key_to_export, NCRYPT_KEY_HANDLE const export_key, LPCWSTR const pszBlobType, NCryptBufferDesc *const pParameterList, DWORD const dwFlags);

		DWORD version()const{
			return /*0x00010001*/ 0x00000001;
		}

		DWORD implementation_type()const{
			return NCRYPT_IMPL_SOFTWARE_FLAG;
		}

		DWORD max_key_length_name()const{
			return 250;
		}

		virtual void set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags){
			STCRYPT_UNIMPLEMENTED();
		}
		virtual void get_prop(LPCWSTR const prop_name,  PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags){
			assert(prop_name);

			if( wcscmp(NCRYPT_VERSION_PROPERTY  , prop_name)==0 ){

				prop_val_size = cng_get_prop_impl( sizeof( decltype(this->version() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
					auto const block_length = this->version();
					auto const r = memcpy_s( dest, size, &block_length, sizeof(block_length) );	assert(!r);
				});

			} else if( wcscmp(NCRYPT_IMPL_TYPE_PROPERTY, prop_name)==0 ){

				prop_val_size = cng_get_prop_impl( sizeof( decltype(this->implementation_type() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
					auto const v = this->implementation_type();
					auto const r = memcpy_s( dest, size, &v, sizeof(v) );	assert(!r);
				});

			} else if( wcscmp(NCRYPT_MAX_NAME_LENGTH_PROPERTY, prop_name)==0 ){

				prop_val_size = cng_get_prop_impl( sizeof( decltype(this->max_key_length_name() ) ), prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
					auto const v = this->max_key_length_name();
					auto const r = memcpy_s( dest, size, &v, sizeof(v) );	assert(!r);
				});

			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
			}
		}


		static storage_path const& user_keystorage_root() { return m_storage_root2; }
		static storage_path const& machine_keystorage_root() { return m_machine_storage_root; }
	private:
		cng_n_key_class_op_i_ptr_t import_key_from_blob_magic_( PBYTE const pbData, DWORD const cbData );
	private:
		static storage_path const m_storage_root2;
		static storage_path const m_machine_storage_root;
	};

	storage_path const cng_keystorage_class::m_storage_root2 = cng_keystorage_root();
	storage_path const cng_keystorage_class::m_machine_storage_root = cng_machine_keystorage_root();

	typedef boost::intrusive_ptr<cng_keystorage_class>	cng_keystorage_class_ptr_t;

	
	
	
	//
	// proxy class for keys
	//
	struct keystorage_class_for_key_t 
		: cng_obj_ref
	{
		virtual void destroy_self(){delete this;}

		keystorage_class_for_key_t(cng_keystorage_class_ptr_t const& key_storage, bool const is_machine_key)
			: m_key_storage( key_storage )
			, m_is_machine_key( is_machine_key)
		{}

		storage_path const& keystorage_root()const{
			STCRYPT_CHECK( m_key_storage );
			return m_is_machine_key?m_key_storage->machine_keystorage_root():m_key_storage->user_keystorage_root();
		}

		cng_keystorage_class_op_i* provider()const{ return m_key_storage.get(); }


	private:
		cng_keystorage_class_ptr_t	m_key_storage;
		bool						m_is_machine_key;
	};
	typedef boost::intrusive_ptr<keystorage_class_for_key_t>	keystorage_class_for_key_ptr_t;



	
	namespace {

		struct ncrypt_key_info_t {
			
			ncrypt_key_info_t(){}

			ncrypt_key_info_t(ncrypt_key_info_t&& other)
				: m_key_name( other.m_key_name )
				, m_alg_id( other.m_alg_id)
			{}

			std::wstring	m_key_name;
			std::wstring	m_alg_id;
		};



		static unsigned int const enum_state_header_t_magic = 'STCE';

		struct enum_state_header_t {
			unsigned int m_magick;
			unsigned int m_count;
			unsigned int m_current;
			NCryptKeyName*	m_first;
		};


	}

	stcrypt::buffer_t cng_keystorage_class::enum_keys_init(bool const is_machine_keys){
		// binary blob layout:
		//	enum_state_header_t
		//  NCryptKeyName data[count]
		//		wchar_t buffer

		std::vector<ncrypt_key_info_t> keys;
		keys.reserve(1024);

		auto const& key_storage_root = is_machine_keys?this->machine_keystorage_root():this->user_keystorage_root();
		size_t required_buffer_size = 0;
		unsigned int keys_count = 0;

		if( boost::filesystem::exists(key_storage_root) )/*no directory -- no keys*/{

			std::for_each(boost::filesystem::wdirectory_iterator ( key_storage_root ), boost::filesystem::wdirectory_iterator(), [&](boost::filesystem::wpath const& key_path){

				ncrypt_key_info_t tmp;

				tmp.m_key_name = key_path.leaf();

				key_set_props_t	key_set( key_storage_root, tmp.m_key_name  );
				STCRYPT_CHECK( key_set.is_root_exists() ) ;

				tmp.m_alg_id = key_set.read_string(prop_alg_id);
			
				typedef decltype(tmp.m_alg_id) string_type;
				required_buffer_size += get_buffer_size_for_obj_array<string_type::value_type>( tmp.m_alg_id.size()+1 );
				required_buffer_size += get_buffer_size_for_obj_array<string_type::value_type>( tmp.m_key_name.size()+1 );

				++keys_count;

				keys.push_back( std::move(tmp) );

			});

		}

		required_buffer_size += buffer_for_obj<enum_state_header_t>::value;
		
		required_buffer_size += get_buffer_size_for_obj_array<NCryptKeyName>( keys_count );

		stcrypt::buffer_t	buffer(required_buffer_size);
		size_t current_buffer_free = required_buffer_size;
		BYTE* buffer_cur = static_cast<BYTE*>( buffer.data() );

		enum_state_header_t	* const state_header = static_cast<enum_state_header_t*>( aligned_alloc_in_buffer<enum_state_header_t>(buffer_cur, current_buffer_free, current_buffer_free) );
		STCRYPT_CHECK(state_header);
		STCRYPT_CHECK( state_header==buffer.data() ); // should be at the start of buffer

		NCryptKeyName* const state_key_names =  static_cast<NCryptKeyName*>( aligned_alloc_in_buffer<NCryptKeyName>(buffer_cur, current_buffer_free, current_buffer_free, keys_count) );

		state_header->m_magick = enum_state_header_t_magic;
		state_header->m_count = keys_count;
		state_header->m_current = 0;
		state_header->m_first = state_key_names;

		unsigned int current = 0;
		boost::for_each( keys, [&](ncrypt_key_info_t& key){
			assert(current < state_header->m_count);

			wchar_t *const key_name = static_cast<wchar_t*>( aligned_alloc_in_buffer<wchar_t>(buffer_cur, current_buffer_free, current_buffer_free, key.m_key_name.size() +1 ) );
			wchar_t *const key_alg_id_name = static_cast<wchar_t*>( aligned_alloc_in_buffer<wchar_t>(buffer_cur, current_buffer_free, current_buffer_free, key.m_alg_id.size() +1 ) );

			memcpy( key_name, key.m_key_name.c_str(), sizeof(wchar_t)*(key.m_key_name.size()+1) );
			memcpy( key_alg_id_name, key.m_alg_id.c_str(), sizeof(wchar_t)*(key.m_alg_id.size()+1) );

			memset( &( state_header->m_first[current] ), 0, sizeof(state_header->m_first[current]) );
			state_header->m_first[current].pszName = key_name;
			state_header->m_first[current].pszAlgid = key_alg_id_name;

			++current;

		});

		
		return buffer;
	}

	bool cng_keystorage_class::enum_keys_current(void* const state, NCryptKeyName *const key_name){
		STCRYPT_CHECK(state);
		STCRYPT_CHECK(key_name);

		auto *const enum_state = static_cast<enum_state_header_t*>( state );
		STCRYPT_CHECK(enum_state->m_magick==enum_state_header_t_magic);

		if( enum_state->m_current >= enum_state->m_count ) return false;
		
		*key_name = enum_state->m_first[enum_state->m_current];
		++enum_state->m_current;

		return true;
	}



	struct dstu4145_alg_id { static wchar_t const*const alg_id; };
	wchar_t const*const dstu4145_alg_id::alg_id = NCNG_DSTU4145;



	struct dstu4145_alg_commont_t
		: dstu4145_alg_id
	{
		void key_lengths(NCRYPT_SUPPORTED_LENGTHS& info){

			info.dwMinLength = info.dwMaxLength = info.dwDefaultLength = 128 * 8; //TODO: magic numbers
			info.dwIncrement = 0;

		}

	};


	template <class SelfT>
	struct dstu4145_alg_detail_t
		: dstu4145_alg_commont_t
	{

		void construct_(tag::create_key const&, bool const overwrite){

			key_set_props_t	key_set( self_()->m_keystorage->keystorage_root(), self_()->m_key_name );

			if( key_set.is_root_exists() ) {
				if( !overwrite ) STCRYPT_THROW_EXCEPTION( exception::keyset_exists() << exception::cng_keyset_name_einfo(self_()->m_key_name) );
				key_set.remove();
			} 
		}

		void construct_(tag::open_key const&){
			key_set_props_t	key_set( self_()->m_keystorage->keystorage_root(), self_()->m_key_name );

			if( !key_set.is_root_exists() ) STCRYPT_THROW_EXCEPTION( exception::no_key() << exception::cng_keyset_name_einfo(self_()->m_key_name) );
		}

		bool is_key_exists_()const{
			key_set_props_t	key_set( self_()->m_keystorage->keystorage_root(), self_()->m_key_name );
			return key_set.is_root_exists();
		}

		cng_n_key_object_op_i_ptr_t create_(){

			auto b_key = self_()->m_alg_class.generate_key_pair(512/*16384*/);
			b_key.finalize();

			// BCRYPT_KEY_BLOB
			std::vector<UCHAR> const& rsa_key_blob = b_key.export_key_blob(BCRYPT_PRIVATE_KEY_BLOB);

			key_set_props_t	key_set( self_()->m_keystorage->keystorage_root(), self_()->m_key_name );

			if( key_set.is_root_exists() ) STCRYPT_UNEXPECTED();

			key_set.create();

			key_set.store_string( prop_alg_id, alg_id );
			key_set.store_string( prop_key_blob_type, BCRYPT_PRIVATE_KEY_BLOB );
			key_set.store_vec( prop_key_blob, rsa_key_blob);

			return cng_n_key_object_op_i_ptr_t( new cng_n_key_object_impl_t<dstu4145_alg_id>( std::move(b_key), std::wstring(self_()->m_key_name), self_()->m_keystorage.get() ) );

		}

		cng_n_key_object_op_i_ptr_t open_(){

			auto const& key_name = self_()->m_key_name;

			key_set_props_t	key_set( self_()->m_keystorage->keystorage_root(), key_name );

			if( !key_set.is_root_exists() ) STCRYPT_UNEXPECTED();

			auto const& type_and_blob = [&]()->boost::tuple<std::wstring, std::vector<BYTE> > {
				try{
					return boost::make_tuple( key_set.read_string( prop_key_blob_type ), key_set.read_vec<BYTE>(prop_key_blob) );
				} catch(stor::exception::property_not_found const& e){
					STCRYPT_THROW_EXCEPTION( exception::bad_keyset() << exception::cng_keyset_name_einfo(key_name) << boost::errinfo_nested_exception( boost::copy_exception(e) ) );
				} catch(stor::exception::io const& e){
					STCRYPT_THROW_EXCEPTION( exception::bad_keyset() << exception::cng_keyset_name_einfo(key_name) << boost::errinfo_nested_exception( boost::copy_exception(e) ) );
				}
			}();


			auto b_key = self_()->m_alg_class.import_key_pair( boost::get<0>(type_and_blob).c_str(),  boost::get<1>(type_and_blob).data(), boost::get<1>(type_and_blob).size(), 0);

			return cng_n_key_object_op_i_ptr_t( new cng_n_key_object_impl_t<dstu4145_alg_id>( std::move(b_key), std::wstring(key_name), self_()->m_keystorage.get() ) );
		}


	private:
		SelfT* self_(){ return static_cast<SelfT*>(this); }
		SelfT const* self_()const{ return static_cast<SelfT const*>(this); }
	};

	
	template <class AlgId>
	struct cng_n_key_object_impl_t
		: cng_n_key_private_i
		, AlgId
	{
		virtual void destroy_self(){delete this;}

		virtual void set_window_handle(HWND const hwnd){

		}

		virtual void set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags){
			assert(prop_name);
			assert(prop_val);

			if( wcscmp(NCRYPT_WINDOW_HANDLE_PROPERTY, prop_name)==0 ){
				if( prop_val_size!=sizeof(DWORD) ) STCRYPT_THROW_EXCEPTION( exception::invalid_parameter() );
				HWND tmp;
				if( memcpy_s(&tmp, sizeof(tmp), prop_val, prop_val_size)!=0 ) STCRYPT_UNEXPECTED();

				this->set_window_handle( tmp );

			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
			}
		}

		virtual void get_prop(LPCWSTR const prop_name, PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags){
			assert(prop_name);

			if(flags) STCRYPT_THROW_EXCEPTION( exception::badflags() << exception::flags_einfo(flags) );
			
			if( wcscmp(NCRYPT_ALGORITHM_PROPERTY, prop_name)==0 ){

				auto const prop_val_req_size = (wcslen(this->alg_id)+1)*sizeof(wchar_t);

				prop_val_size = cng_get_prop_impl( prop_val_req_size , prop_val_buffer, prop_val_buffer_size, [&](PUCHAR const dest, ULONG const size){
					auto const r = memcpy_s( dest, size, this->alg_id, prop_val_req_size );	assert(!r);
				});

			} else if( wcscmp(NCRYPT_NAME_PROPERTY, prop_name)==0 ){

				auto const prop_val_req_size = (m_name.size()+1)*sizeof(wchar_t);

				prop_val_size = cng_get_prop_impl( prop_val_req_size , prop_val_buffer, prop_val_buffer_size, [&](PUCHAR const dest, ULONG const size){
					auto const r = memcpy_s( dest, size, m_name.data(), prop_val_req_size );	assert(!r);
				});

			} else if( wcscmp(NCRYPT_EXPORT_POLICY_PROPERTY, prop_name)==0 ){

				prop_val_size = cng_get_prop_impl( sizeof(DWORD) , prop_val_buffer, prop_val_buffer_size, [&](PUCHAR const dest, ULONG const size){
					DWORD const export_policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG | NCRYPT_ALLOW_ARCHIVING_FLAG | NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG;
					auto const r = memcpy_s( dest, size, &export_policy, sizeof( export_policy ) );	assert(!r);
				});

			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
			}

		}

		virtual void sign_hash(VOID * const pPaddingInfo, PBYTE const pbHashValue, DWORD const cbHashValue, PBYTE const pbSignature, DWORD const cbSignaturee, DWORD * const pcbResult, DWORD const dwFlags){
			m_key.sign_hash(pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignaturee, pcbResult, dwFlags);
		}

		virtual bool verify_signature(VOID * const pPaddingInfo, PBYTE const pbHashValue, DWORD const cbHashValue, PBYTE const pbSignature, DWORD const cbSignaturee, DWORD const dwFlags){
			return m_key.verify_signature(pPaddingInfo, pbHashValue, cbHashValue, pbSignature, cbSignaturee, dwFlags);
		}

		virtual DWORD asym_decrypt(PBYTE const pbInput, DWORD const cbInput, VOID * const pPaddingInfo, PBYTE const pbOutput, DWORD const cbOutput, DWORD const dwFlags){
			return m_key.asym_decrypt(pbInput, cbInput, pPaddingInfo, pbOutput, cbOutput, dwFlags);
		}


		virtual cng_keystorage_class_op_i* provider(){
			STCRYPT_CHECK( m_keystorage );
			return m_keystorage->provider();
		}


		virtual BCRYPT_KEY_HANDLE key_handle(){
			assert( m_key.to_handle() );

			return m_key.to_handle();
		}


		cng_n_key_object_impl_t(cng_key&& key, std::wstring&& name, keystorage_class_for_key_ptr_t const&  keystorage)
			: m_key( std::move(key) )
			, m_name( std::move(name) )
			, m_keystorage( keystorage )
		{}

	private:
		std::wstring m_name;
		cng_key	m_key;
		keystorage_class_for_key_ptr_t m_keystorage;
	};


	template <class SelfT>
	struct cng_n_key_class_common_t 
		: cng_n_key_class_op_i
	{
		virtual void destroy_self(){delete this;}

		virtual void set_window_handle(HWND const hwnd){
			CSP_LOG_TRACE

			STCRYPT_LOG_W_STRING(L"Ignoring HWND.");
		}

		virtual void set_export_policy(DWORD const policy){
			CSP_LOG_TRACE

			STCRYPT_LOG_W_STRING(L"Ignoring policy flags.");
		}

		virtual void set_ui_policy(NCRYPT_UI_POLICY const& policy){
			CSP_LOG_TRACE

			STCRYPT_LOG_W_STRING(L"Ignoring UI policy.");
		}

		virtual void set_length(DWORD const length){
			CSP_LOG_TRACE

			STCRYPT_LOG_W_STRING(L"Ignoring key length, default used.");
		}

		virtual void set_key_usage(DWORD const key_usage){
			CSP_LOG_TRACE

			STCRYPT_LOG_W_STRING(L"Ignoring key usage, allowing all usage cases.");
		}


		virtual void set_prop(LPCWSTR const prop_name,  PUCHAR const prop_val, ULONG const prop_val_size, ULONG const flags){
			CSP_LOG_TRACE

			assert(prop_name);
			assert(prop_val);

			if( wcscmp(NCRYPT_WINDOW_HANDLE_PROPERTY, prop_name)==0 ){
				if( prop_val_size!=sizeof(DWORD) ) STCRYPT_THROW_EXCEPTION( exception::invalid_parameter() );
				HWND tmp;
				if( memcpy_s(&tmp, sizeof(tmp), prop_val, prop_val_size)!=0 ) STCRYPT_UNEXPECTED();

				this->set_window_handle( tmp );
				
			} else if( wcscmp(NCRYPT_EXPORT_POLICY_PROPERTY, prop_name)==0 ){
				if( prop_val_size!=sizeof(DWORD) ) STCRYPT_THROW_EXCEPTION( exception::invalid_parameter() );
				DWORD tmp;
				if( memcpy_s(&tmp, sizeof(tmp), prop_val, prop_val_size)!=0 ) STCRYPT_UNEXPECTED();

				this->set_export_policy( tmp );
				
			} else if( wcscmp(NCRYPT_LENGTH_PROPERTY, prop_name)==0 ){
				if( prop_val_size!=sizeof(DWORD) ) STCRYPT_THROW_EXCEPTION( exception::invalid_parameter() );
				DWORD tmp;
				if( memcpy_s(&tmp, sizeof(tmp), prop_val, prop_val_size)!=0 ) STCRYPT_UNEXPECTED();

				this->set_length( tmp );

			} else if( wcscmp(NCRYPT_KEY_USAGE_PROPERTY, prop_name)==0 ){
				if( prop_val_size!=sizeof(DWORD) ) STCRYPT_THROW_EXCEPTION( exception::invalid_parameter() );
				DWORD tmp;
				if( memcpy_s(&tmp, sizeof(tmp), prop_val, prop_val_size)!=0 ) STCRYPT_UNEXPECTED();

				this->set_key_usage( tmp );

			} else if( wcscmp(NCRYPT_UI_POLICY_PROPERTY, prop_name)==0 ){
				if( prop_val_size!=sizeof(NCRYPT_UI_POLICY) ) STCRYPT_THROW_EXCEPTION( exception::invalid_parameter() );
				auto const * tmp = reinterpret_cast<NCRYPT_UI_POLICY const*>( prop_val );

				if(tmp) this->set_ui_policy( *tmp );

			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
			}
		}

		virtual void get_prop(LPCWSTR const prop_name,  PUCHAR const prop_val_buffer, ULONG const prop_val_buffer_size, ULONG& prop_val_size, ULONG const flags){
			assert(prop_name);

			if( wcscmp(NCRYPT_LENGTHS_PROPERTY, prop_name)==0 ){

				prop_val_size = cng_get_prop_impl( sizeof( NCRYPT_SUPPORTED_LENGTHS ) , prop_val_buffer, prop_val_buffer_size, [this](PUCHAR const dest, ULONG const size){
					assert(size>=sizeof(NCRYPT_SUPPORTED_LENGTHS));
					NCRYPT_SUPPORTED_LENGTHS& key_lengths = *reinterpret_cast<NCRYPT_SUPPORTED_LENGTHS*>(dest);
					self_()->key_lengths(key_lengths);
				});

			} else {
				STCRYPT_THROW_EXCEPTION( exception::invalid_prop() << exception::cng_prop_name_einfo(prop_name) );
			}
		}

	protected:
		cng_n_key_class_common_t(keystorage_class_for_key_ptr_t const&  keystorage)
			:  m_keystorage( keystorage )
		{}

		keystorage_class_for_key_ptr_t	m_keystorage;

	private:
		SelfT* self_(){ return boost::polymorphic_downcast<SelfT*>(this); }

	};

	template < template <class> class AlgDetailT >
	struct cng_n_key_class_impl_t
		: cng_n_key_class_common_t< cng_n_key_class_impl_t<AlgDetailT> >
		, AlgDetailT< cng_n_key_class_impl_t<AlgDetailT> >
	{
		friend AlgDetailT< cng_n_key_class_impl_t<AlgDetailT> >;
		friend cng_n_key_class_common_t< cng_n_key_class_impl_t<AlgDetailT> >;


		cng_n_key_class_impl_t(tag::create_key const&, keystorage_class_for_key_ptr_t const&  keystorage, LPCWSTR const key_name, DWORD const legacy_key_spec, DWORD const flags)
			: m_alg_class( cng_alg::create(this->alg_id) )
			, cng_n_key_class_common_t( keystorage )
			, m_key_name( key_name )
			, m_flags( flags )
		{
			this->construct_( tag::create_key(), test_mask<decltype(m_flags)>(m_flags, NCRYPT_OVERWRITE_KEY_FLAG) );
		}

		cng_n_key_class_impl_t(tag::open_key const&, keystorage_class_for_key_ptr_t const& keystorage,LPCWSTR const key_name, DWORD const legacy_key_spec, DWORD const flags)
			: m_alg_class( cng_alg::create(this->alg_id) )
			, cng_n_key_class_common_t( keystorage )
			, m_key_name( key_name )
			, m_flags( flags )
		{
			this->construct_( tag::open_key() );
		}

		virtual cng_n_key_object_op_i_ptr_t	create(){
			return this->create_( );
		}

		virtual cng_n_key_object_op_i_ptr_t	open(){
			return this->open_();
		}



	private:

		cng_alg						m_alg_class;
		std::wstring				m_key_name;
		DWORD						m_flags;
	};


	template <class T>
	cng_n_key_class_op_i_ptr_t cng_n_key_class_factory_function_wrap(keystorage_class_for_key_ptr_t const& keystorage,LPCWSTR const key_name, DWORD const legacy_key_spec, DWORD const flags){
		cng_n_key_class_op_i_ptr_t n_key_class( new T(tag::open_key(), keystorage, key_name, legacy_key_spec, flags) );

		return std::move( n_key_class );
	}



	typedef cng_n_key_class_op_i_ptr_t (*cng_n_key_class_factory_function_t)(keystorage_class_for_key_ptr_t const& keystorage, LPCWSTR const key_name, DWORD const legacy_key_spec, DWORD const flags);
	struct cng_n_key_class_factory_info_t {
		WCHAR const*const						m_alg_id;
		cng_n_key_class_factory_function_t		m_factory_func;

	};

	cng_n_key_class_factory_info_t cng_n_key_class_factory_table[]={
		//{cng_n_key_class_impl_t<rsa_alg_detail_t>::alg_id,			&cng_n_key_class_factory_function_wrap< cng_n_key_class_impl_t<rsa_alg_detail_t> >		},
		{cng_n_key_class_impl_t<dstu4145_alg_detail_t>::alg_id,		&cng_n_key_class_factory_function_wrap< cng_n_key_class_impl_t<dstu4145_alg_detail_t> >	}
	};
	



#define STCRYPT_ALG_DISPATCH(on_alg_id, func)	\
	if( wcscmp(on_alg_id, alg_id)==0 ) {	\
		cng_n_key_class_op_i_ptr_t n_key_class (  (func)()  );	\
		return cng_n_key_handle_op_i_ptr_t( new cng_n_key_handle_impl_t( std::move(n_key_class) ) );	\
	}	\
	/**/

	cng_n_key_handle_op_i_ptr_t cng_keystorage_class::create_key(LPCWSTR const alg_id, LPCWSTR const key_name, DWORD const legacy_key_spec, bool const is_machine_key, DWORD const flags){

		keystorage_class_for_key_ptr_t	keystorage_for_key(  new keystorage_class_for_key_t(this, is_machine_key) );

		STCRYPT_ALG_DISPATCH(cng_n_key_class_impl_t<dstu4145_alg_detail_t>::alg_id, [&](){ return cng_n_key_class_op_i_ptr_t(new cng_n_key_class_impl_t<dstu4145_alg_detail_t>(tag::create_key(), keystorage_for_key, key_name, legacy_key_spec, flags)); });

		STCRYPT_THROW_EXCEPTION( exception::badalg() );
	}
#undef STCRYPT_ALG_DISPATCH

	cng_n_key_handle_op_i_ptr_t cng_keystorage_class::open_key(LPCWSTR const key_name, DWORD const legacy_key_spec, bool const is_machine_key, DWORD const flags){

		keystorage_class_for_key_ptr_t keystorage_for_key( new keystorage_class_for_key_t(this, is_machine_key) );

		key_set_props_t	key_set( keystorage_for_key->keystorage_root(), key_name );

		if( !key_set.is_root_exists() ) STCRYPT_THROW_EXCEPTION( exception::no_key() << exception::cng_keyset_name_einfo(key_name) );
		
		auto const& alg_id = [&]()->std::wstring {
			try{
				return key_set.read_string( prop_alg_id );
			} catch(stor::exception::property_not_found const& e){
				STCRYPT_THROW_EXCEPTION( exception::bad_keyset() << exception::cng_keyset_name_einfo(key_name) << boost::errinfo_nested_exception( boost::copy_exception(e) ) );
			} catch(stor::exception::io const& e){
				STCRYPT_THROW_EXCEPTION( exception::bad_keyset() << exception::cng_keyset_name_einfo(key_name) << boost::errinfo_nested_exception( boost::copy_exception(e) ) );
			}
		}();

		auto const& factory_to_use = std::find_if( boost::begin(cng_n_key_class_factory_table), boost::end(cng_n_key_class_factory_table), [&](cng_n_key_class_factory_info_t const& factory_item){
			return ( factory_item.m_alg_id == alg_id );
		});

		if( factory_to_use == boost::end(cng_n_key_class_factory_table) ){
			STCRYPT_THROW_EXCEPTION( exception::bad_keyset_entry() << exception::cng_keyset_name_einfo(key_name) );
		}

		auto const& n_key_class = (factory_to_use->m_factory_func)( keystorage_for_key, key_name, legacy_key_spec, flags );

		return cng_n_key_handle_op_i_ptr_t( new cng_n_key_handle_impl_t( n_key_class->open() ) );

	}


	cng_n_key_handle_op_i_ptr_t cng_keystorage_class::create_ephemeral_key(LPCWSTR const alg_id, DWORD const legacy_key_spec, DWORD const flags){
		STCRYPT_UNIMPLEMENTED();
	}

	DWORD cng_keystorage_class::export_key(cng_n_key_object_op_i *const key_to_export, NCRYPT_KEY_HANDLE const export_key, LPCWSTR const pszBlobType, NCryptBufferDesc *const pParameterList , PBYTE const pbOutput,  DWORD const cbOutput, DWORD const dwFlags){
		typedef cng_key_func_wrap_t cng_h;

		assert(key_to_export);
		assert(pszBlobType);
		assert(pbOutput);

		if(export_key) STCRYPT_UNIMPLEMENTED();

		auto key_to_export_private = boost::polymorphic_downcast<cng_n_key_private_i*>( key_to_export );
		auto const b_key_handle = key_to_export_private->key_handle();

		if( wcscmp(BCRYPT_PRIVATE_KEY_BLOB, pszBlobType)==0 || wcscmp(BCRYPT_PUBLIC_KEY_BLOB, pszBlobType)==0 ){

			auto const b_key_blob_size = cng_h::export_key_blob(b_key_handle, pszBlobType, pbOutput, cbOutput);

			return b_key_blob_size;
		} else {
			STCRYPT_UNIMPLEMENTED();
		}

	}

	DWORD cng_keystorage_class::key_blob_size(cng_n_key_object_op_i * const key_to_export, NCRYPT_KEY_HANDLE const export_key, LPCWSTR const pszBlobType, NCryptBufferDesc *const pParameterList, DWORD const dwFlags){
		typedef cng_key_func_wrap_t cng_h;

		assert(key_to_export);
		assert(pszBlobType);

		if(export_key) STCRYPT_UNIMPLEMENTED();

		auto key_to_export_private = boost::polymorphic_downcast<cng_n_key_private_i*>( key_to_export );
		auto const b_key_handle = key_to_export_private->key_handle();

		if( wcscmp(BCRYPT_PRIVATE_KEY_BLOB, pszBlobType)==0 ){

			auto const b_key_blob_size = cng_h::key_blob_size(b_key_handle, BCRYPT_PRIVATE_KEY_BLOB);

			return b_key_blob_size;
		} else if( wcscmp(BCRYPT_PUBLIC_KEY_BLOB, pszBlobType)==0 ){

			auto const b_key_blob_size = cng_h::key_blob_size(b_key_handle, BCRYPT_PUBLIC_KEY_BLOB);

			return b_key_blob_size;
		} else {
			STCRYPT_UNIMPLEMENTED();
		}

	}



	struct dstu4145_alg_import_t 
		: dstu4145_alg_commont_t
		, cng_n_key_class_common_t<dstu4145_alg_import_t>
	{
		virtual cng_n_key_object_op_i_ptr_t	create(){
			assert( m_key.to_handle() );

			return cng_n_key_object_op_i_ptr_t( new cng_n_key_object_impl_t<dstu4145_alg_id>( std::move(m_key), std::wstring(), m_keystorage ) );
		}

		virtual cng_n_key_object_op_i_ptr_t	open(){
			STCRYPT_UNEXPECTED();
		}


		dstu4145_alg_import_t(cng_key && key, keystorage_class_for_key_ptr_t const& keystorage)
			: m_key( std::move(key) )
			, cng_n_key_class_common_t( keystorage )
		{}

	private:
		cng_key m_key;
		keystorage_class_for_key_ptr_t	m_keystorage;
	};


	stcrypt::cng_n_key_class_op_i_ptr_t cng_keystorage_class::import_key_from_blob_magic_( PBYTE const pbData, DWORD const cbData )
	{
		assert(pbData);
		
		BCRYPT_KEY_BLOB blob_header;
		auto input_range = boost::make_iterator_range(pbData, pbData+cbData);


		sio::read<decltype(blob_header)>::apply(blob_header, input_range) ;
		if( blob_header.Magic == CNG_DSTU4145_BLOB_MAGIC_PRIVATE || blob_header.Magic == CNG_DSTU4145_BLOB_MAGIC_PUBLIC ){
			
			auto const alg_class = cng_alg::create(CNG_DSTU4145);
			auto key = alg_class.import_key_pair( (blob_header.Magic == CNG_DSTU4145_BLOB_MAGIC_PRIVATE)?BCRYPT_PRIVATE_KEY_BLOB:BCRYPT_PUBLIC_KEY_BLOB,  pbData, cbData);

			
			keystorage_class_for_key_ptr_t key_storage_proxy( new keystorage_class_for_key_t(this, false) );
			return cng_n_key_class_op_i_ptr_t( new dstu4145_alg_import_t( std::move(key), key_storage_proxy ) );

		} else {
			STCRYPT_UNIMPLEMENTED();
		}
	}



	cng_n_key_handle_op_i_ptr_t cng_keystorage_class::import_ephemeral_key(NCRYPT_KEY_HANDLE const export_key, LPCWSTR const pszBlobType, PBYTE const pbData, DWORD const cbData, DWORD const dwFlags){
		//cng_alg	m_alg_class;

		if( export_key ) STCRYPT_UNIMPLEMENTED();
		
		if( wcscmp(BCRYPT_PRIVATE_KEY_BLOB, pszBlobType)==0 ){
			return cng_n_key_handle_op_i_ptr_t( new cng_n_key_handle_impl_t ( this->import_key_from_blob_magic_(pbData, cbData) ) );
		} else {
			STCRYPT_UNIMPLEMENTED();
		}

		STCRYPT_UNIMPLEMENTED();
	}


	namespace {

		boost::array<NCryptAlgorithmName,3> const keystorage_supported_algs = { {

			{const_cast<LPWSTR>( dstu4145_alg_id::alg_id ),  NCRYPT_ASYMMETRIC_ENCRYPTION_INTERFACE, NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SIGNATURE_OPERATION, 0},
			{BCRYPT_DH_ALGORITHM, BCRYPT_SECRET_AGREEMENT_INTERFACE, NCRYPT_SECRET_AGREEMENT_OPERATION, 0},
			{CNG_G28147_89, BCRYPT_CIPHER_INTERFACE, NCRYPT_CIPHER_OPERATION, 0}

		} };

	}


	unsigned int cng_keystorage_class::enumerate_algorithms(DWORD const dwAlgOperations, NCryptAlgorithmName *& ppAlgList){

		STCRYPT_LOG_W_STRING(L":::::::::::::::::::::::::::::: Enum Algs");

		unsigned int alg_hit_count = 0;
		boost::array<unsigned int, keystorage_supported_algs.static_size>	alg_hit;
		boost::fill(alg_hit, keystorage_supported_algs.static_size);

		for(unsigned int cur = 0; cur<keystorage_supported_algs.size(); ++cur){

			if( test_if_any_in_mask(dwAlgOperations, keystorage_supported_algs[cur].dwAlgOperations) ){
				alg_hit[alg_hit_count] = cur;
				++alg_hit_count;
			}
		}


		//if( test_if_any_out_of_mask<decltype(dwAlgOperations)>(dwAlgOperations, NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION | NCRYPT_SIGNATURE_OPERATION | BCRYPT_SECRET_AGREEMENT_OPERATION)  ){
			//STCRYPT_UNIMPLEMENTED();
		//}

		if( alg_hit_count ){

			auto alg = static_cast<NCryptAlgorithmName*>( malloc( sizeof(NCryptAlgorithmName)*alg_hit_count ) );
			if( !alg ) throw std::bad_alloc("malloc()");
			BOOST_SCOPE_EXIT( (&alg) ){free( alg );} BOOST_SCOPE_EXIT_END;

			auto cur_alg = alg;

			for(unsigned int cur = 0; cur<alg_hit_count; ++cur){
				assert(  alg_hit[cur]< keystorage_supported_algs.static_size );
				*cur_alg = keystorage_supported_algs[ alg_hit[cur] ];
				++cur_alg;
			}

			ppAlgList = alg;
			alg = 0;
		}

		return alg_hit_count;
	}


	cng_keystorage_class_op_i_ptr create_keystorage_class(){
		return cng_keystorage_class_op_i_ptr( new cng_keystorage_class() );
	}

	bool is_keystorage_alg_valid(LPCWSTR const alg_id){
		STCRYPT_UNIMPLEMENTED();
	}


}
//================================================================================================================================================
