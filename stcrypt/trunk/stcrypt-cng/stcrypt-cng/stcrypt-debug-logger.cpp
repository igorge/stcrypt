//================================================================================================================================================
// FILE: stcrypt-debug-logger.cpp
// (c) GIE 2010-09-21  22:10
//
//================================================================================================================================================
#include "stdafx.h"
//================================================================================================================================================
#include "util-str-conv.hpp"
#include "stcrypt-debug-logger.hpp"
#include "util-scope-exit.hpp"

#include "gie/gie_fixed_storage.hpp"
#include "gie/gie_allocator.hpp"

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/date_time.hpp>
#include <boost/range/iterator_range.hpp>
//#include <boost/utility/mutexed_singleton.hpp>
#include <boost/thread/once.hpp>
#include <boost/range/algorithm.hpp>
#include <boost/format.hpp>
#include <boost/thread/recursive_mutex.hpp>
//#include <boost/range/algorithm_ext.hpp>

#include <vector>
#include <sstream>
//================================================================================================================================================

namespace stcrypt { namespace logger {


	namespace {

		struct tls_slot{

			static DWORD slot_idx; 
			static bool is_valid(){ return slot_idx!=TLS_OUT_OF_INDEXES; }

			template <class T>
			static T* get_ptr(){
				assert( is_valid() );

				return static_cast<T*>( TlsGetValue( slot_idx ) );
			}

			template <class T>
			static
			void set_ptr(T* const val){
				assert( is_valid() );

				auto const r = TlsSetValue(slot_idx, static_cast<void*>(val) );
				assert(r);
			}

			~tls_slot(){
				if(slot_idx!=TLS_OUT_OF_INDEXES){
					auto const r = TlsFree(slot_idx);
					assert(r);
				}
			}

		};

		DWORD tls_slot::slot_idx = TlsAlloc();
		tls_slot	free_tls_slot;


	} //end anon ns


	
	struct logger_shared
		//: boost::mutexed_singleton<logger_shared, 1, stcrypt_debug_subsystem_logger_tag>
	{

		logger_shared(/*boost::restricted*/)
			: m_is_alive( false )
		{
			InitializeCriticalSection(&m_this_lock);


			try {

				std::wostringstream file_name_formatter;

				auto const this_proc_id = GetCurrentProcessId();

				wchar_t module_file_name[MAX_PATH];

				auto const r = GetModuleFileNameW(0, &module_file_name[0], sizeof(module_file_name)-1);
				module_file_name[r] = 0;

				file_name_formatter  //TODO: dynamically reconfigure path from env var tmp path
					<< L"C:\\temp\\STCRYPT-LOGS\\["
					<< boost::filesystem::wpath(&module_file_name[0]).stem() 
					<< L"][" 
					<<this_proc_id
					<< L"]["
					<< to_iso_wstring( boost::posix_time::second_clock::local_time() )  
					<< L"]";

				m_log_file_path = file_name_formatter.str();

				boost::filesystem::create_directories( m_log_file_path );

			} catch(...) {
				OutputDebugStringA("STCRYPT: Logger have failed to initialize, logging to /dev/null\n");
				return;
			}

			m_is_alive = true;
		};

		~logger_shared(){

			DeleteCriticalSection(&m_this_lock);

			boost::for_each(m_gc, [](logger *& l){
				assert(l);
				delete l;
				l = 0;
			});

		};

		boost::filesystem::wpath const& log_path()const{ return m_log_file_path; }
		bool is_alive()const { return m_is_alive; }

		void add_to_gc(logger* const l){
			//boost::recursive_mutex::scoped_lock lock( m_this_lock );
			EnterCriticalSection( &m_this_lock );
			STCRYPT_SCOPE_EXIT([this](){ LeaveCriticalSection(&m_this_lock); });


			try{OutputDebugStringW( (boost::wformat(L"++++ LOG GC ADD: %1% for TID %2%\n") % l % GetCurrentThreadId() ).str().c_str() );}catch(...){}

			assert( boost::find(m_gc, l)==m_gc.end() );
			m_gc.push_back(l);
		}

		void dstroy_item_in_gc(logger* const l){
			//boost::recursive_mutex::scoped_lock lock( m_this_lock );
			EnterCriticalSection( &m_this_lock );
			STCRYPT_SCOPE_EXIT([this](){ LeaveCriticalSection(&m_this_lock); });

			try{OutputDebugStringW( (boost::wformat(L"++++ LOG GC DEL: %1% for TID %2%\n") % l % GetCurrentThreadId() ).str().c_str() );}catch(...){}
			
			auto const new_end = boost::remove(m_gc, l);
			assert( new_end!=m_gc.end() );
			assert( new_end+1==m_gc.end() );

			delete l;

			m_gc.erase( new_end, m_gc.end() );

		}

	private:
		boost::filesystem::wpath m_log_file_path;
		bool					 m_is_alive;
		std::vector<logger*>	 m_gc;
		//boost::recursive_mutex	 m_this_lock;
		CRITICAL_SECTION		 m_this_lock;
	};


	logger_shared * get_logger_shared_singleton();

	struct logger_impl 
	{
		logger_impl()
			: m_level( 0 )
			, m_spaces_per_level( 3 )
			, m_alive( false )
		{
			//logger_shared::lease logger_shared_data;

			auto logger_shared_data = get_logger_shared_singleton();

			if( !logger_shared_data || !logger_shared_data->is_alive() ) {
				return;
			}

			auto const this_thread_id = GetCurrentThreadId();
		
			std::wostringstream file_name_formatter;

			file_name_formatter << this_thread_id << L" ["<<tls_slot::slot_idx<<L"]"<< L".txt";

			auto const file_name = file_name_formatter.str();

			auto const log_file_path = logger_shared_data->log_path() / file_name;

			m_out.open( log_file_path, std::ios_base::out | std::ios_base::binary ); 

			m_alive =  true;
			
		}

		boost::filesystem::ofstream m_out;
		
		unsigned int m_level;
		unsigned int m_spaces_per_level;
		bool m_alive;

		bool is_alive()const { return m_alive; }

		template <class InIterRangeT, class OutInterT>
		void adjust_level_(InIterRangeT const& in_range, OutInterT& out){

			if ( !this->is_alive() ) return;

			assert( in_range.begin()!=in_range.end() );

			auto const& time_stamp = to_simple_wstring( boost::posix_time::microsec_clock::local_time() );

			auto const spaces_count = m_level * m_spaces_per_level;

			auto current = in_range.begin();
			while( current != in_range.end() ){

				std::copy(time_stamp.begin(), time_stamp.end(), out);
				std::fill_n( out,  spaces_count+1, L' ');

				auto new_line_pos = std::find(current, in_range.end(), L'\n');
				if( new_line_pos==in_range.end() ){
					std::copy(current, in_range.end(), out);
				} else {
					std::copy(current, new_line_pos, out);
					std::advance(new_line_pos,1);
				}

				out++ = L'\r';
				out++ = L'\n';
				current = new_line_pos;
				
			}

		}


		template <class InIterRange>
		void log_(InIterRange const& in_range){

			if ( !this->is_alive() ) return;

			auto const assume_min_string_size = 4*1024;

			typedef gie::monotonic::fixed_storage<assume_min_string_size*sizeof(wchar_t)+128>	stor_t;
			typedef gie::monotonic::allocator<wchar_t, stor_t> alloc_t;
			typedef std::vector<wchar_t, alloc_t> buffer_t;

			stor_t local_storage;
			buffer_t out_buffer((alloc_t(local_storage)));
			out_buffer.reserve(assume_min_string_size);

			this->adjust_level_(boost::make_iterator_range(in_range), std::back_inserter(out_buffer) );
			if( this->m_out.good() ){
				this->m_out.write( reinterpret_cast<char const*>( out_buffer.data() ), out_buffer.size()*sizeof(wchar_t) );
				this->m_out.flush();
			} else {
				assert(false);
			}

		}


	};

	logger::logger(/*boost::restricted*/)
		: m_impl( new logger_impl() )
	{

	}

	logger::~logger(){
		try{OutputDebugStringW( (boost::wformat(L"++++ LOG DTOR: %1% for TID %2%\n") % this % GetCurrentThreadId() ).str().c_str() );}catch(...){}
	}




	void logger::inc_level(){
		++m_impl->m_level;

	}
	void logger::dec_level(){
		--m_impl->m_level;
	}


	void logger::log(std::wstring const& msg){
		this->m_impl->log_( boost::make_iterator_range( msg.begin(), msg.end() ) );
	}

	void logger::log(std::string const& msg){

		typedef gie::monotonic::fixed_storage<1024*sizeof(wchar_t)+128>	stor_t;
		typedef gie::monotonic::allocator<wchar_t, stor_t> alloc_t;
		typedef std::vector<wchar_t, alloc_t> buffer_t;

		stor_t local_storage;

		buffer_t buffer(  (alloc_t(local_storage))  );
		buffer.reserve( 1024 );

		
		conv_str(msg.c_str(), buffer);
		this->m_impl->log_( boost::make_iterator_range( buffer.data(), buffer.data()+buffer.size()-1) );

	}




	namespace {

		boost::once_flag g_logger_shared_flag =	BOOST_ONCE_INIT;

		logger_shared * g_logger_shared = 0;

		void create_logger_shared(){
			g_logger_shared = new logger_shared();
		}


	}

	logger_shared * get_logger_shared_singleton(){
		boost::call_once(&create_logger_shared, g_logger_shared_flag);
		return g_logger_shared;
	}



	void before_unload() { 
		//boost::destroy_singletons<stcrypt_debug_subsystem_logger_tag>(); 
		if(g_logger_shared) delete g_logger_shared;
	}

	void unload_for_thread() {
		if( !tls_slot::is_valid() ) return;
		auto const this_thread_logger = tls_slot::get_ptr<logger>();
		if(!this_thread_logger) return;

		auto const shared = get_logger_shared_singleton();
		assert( shared );
		if( this_thread_logger ){
			shared->dstroy_item_in_gc(this_thread_logger);
			tls_slot::set_ptr<logger>( 0 )	;
		}
	}

	logger* get_logger(){

		try {
			if ( tls_slot::is_valid() ){
				auto const log = tls_slot::get_ptr<logger>();

				if(!log){
					std::auto_ptr<logger> new_log( new logger() );
					tls_slot::set_ptr<logger>( new_log.get() );

					try{ 
						get_logger_shared_singleton()->add_to_gc( new_log.get() ); 
					}catch(...){
						tls_slot::set_ptr<logger>( 0 );
						throw;
					}

					return new_log.release();
					
				} else {
					return log;
				}

			}

		} catch(...) { assert(false); }

		return 0;
	}


} }
//================================================================================================================================================
