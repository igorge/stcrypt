//================================================================================================================================================
// FILE: util-fun-param-printer.h
// (c) GIE 2010-04-27  14:29
//
//================================================================================================================================================
#ifndef H_GUARD_UTIL_FUN_PARAM_PRINTER_2_2010_04_27_14_29
#define H_GUARD_UTIL_FUN_PARAM_PRINTER_2_2010_04_27_14_29
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "stcrypt-debug.hpp"
#include "util-str-conv.hpp"
#include "gie/gie_fixed_storage.hpp"
#include "gie/gie_allocator.hpp"
 
#include <boost/preprocessor/wstringize.hpp>
#include <boost/io/ios_state.hpp>

#include <sstream>
//================================================================================================================================================
namespace stcrypt {

	#define STC_P_NULL_LIT L"<NULL>"

	namespace debug {

		template <class LA>
		struct scoped_la_invoker_t {
			scoped_la_invoker_t(LA const& la)
				: m_la( la )
			{
				STCRYPT_LOG_W_STRING(L"< in params");
				STCRYPT_LOG_INC_LEVEL();
				m_la(true);
				STCRYPT_LOG_DEC_LEVEL();
				STCRYPT_LOG_W_STRING(L">");
			}

			~scoped_la_invoker_t(){
				try{
					STCRYPT_LOG_W_STRING(L"< out params");
					STCRYPT_LOG_INC_LEVEL();
					m_la(false);
					STCRYPT_LOG_DEC_LEVEL();
					STCRYPT_LOG_W_STRING(L">");
				}catch(...){
					assert(false);
				}
			}
		private:
			LA const& m_la;
		};

	}

	namespace pp {
		struct string;
		struct dword;
		struct hex_auto;
		struct array_any;
		struct any;

	}

	template <class T>
	struct out_mark{

		out_mark(T const& v)
			: m_v(v)
		{}

		T const& m_v;
	};

	template <class T>
	out_mark<T> out_m(T const&v){
		return out_mark<T>(v);
	}
	

	template <class T>
	struct in_mark{

		in_mark(T const& v)
			: m_v(v)
		{}

		T const& m_v;
	};


	template <class T>
	in_mark<T> in_m(T const&v){
		return in_mark<T>(v);
	}

	template <class T, class U>
	struct array_info_t{
		T const* m_value;
		size_t m_in_count;
		U const*	   m_out_count;

		array_info_t(array_info_t const& other)
			: m_value( other.m_value )
			, m_in_count( other.m_in_count )
			, m_out_count( other.m_out_count )
		{

		}

		array_info_t( T const* const v, size_t const in_count, U const* const out_count = 0)
			: m_value( v )
			, m_in_count( in_count )
			, m_out_count( out_count )
		{}


	};

	template <class T, class U>
	array_info_t<T,U> pp_a(T const*const v, size_t const in_count, U const*const out_count){
		return array_info_t<T,U>(v, in_count, out_count);
	}

	template <class T>
	array_info_t<T,size_t> pp_a(T const*const v, size_t const in_count){
		return array_info_t<T,size_t>(v, in_count);
	}


	template <class T>
	struct pp_nv_t{
		explicit pp_nv_t(wchar_t const*const name, T const& v)
			: m_val(v)
			, m_name( name )
		{}
		T const m_val;
		wchar_t const * const  m_name;
	};

	template <class T>
	pp_nv_t<T> pp_nv(wchar_t const*const name, T const& v){  return pp_nv_t<T>(name, v); }


	template <class TagT, class T>
	struct pp_as_t{
		explicit pp_as_t(T const& v)
			: m_val(v)
		{}
		T const& m_val;
	};


	template <class TagT, class T>
	pp_as_t<TagT, T> pp_as(T const& v){  return pp_as_t<TagT, T>(v); }

	template <class TagT, class T, class U>
	struct pp_as_t<TagT, array_info_t<T,U> > {
		explicit pp_as_t(array_info_t<T,U> const& v)
			: m_val(v)
		{}
		array_info_t<T,U> m_val;
	};

	template <class TagT, class T, class U>
	pp_as_t<TagT, array_info_t<T,U> > pp_as( array_info_t<T,U> const & v){  return pp_as_t<TagT, array_info_t<T,U> >(v); }

	template <class T>
	std::wostream& operator <<(std::wostream& out, out_mark< pp_nv_t<T> > const &v ){
		out << v.m_v.m_name << L"=" << out_m( v.m_v.m_val );
		return out;
	}

	template <class T>
	std::wostream& operator <<(std::wostream& out, in_mark< pp_nv_t<T> > const &v ){
		out << v.m_v.m_name << L"=" << in_m( v.m_v.m_val );
		return out;
	}


	template <class T>
	void dump_array(std::wostream & os, T const*const v, size_t const count){
		if(!count) {
			os << "<empty>";
		} else {
			os.fill('0');
			for(unsigned int i = 0;i<count;++i){
				if(i) {
					os << " ";
					os.width(0);
				}
				os.width(std::numeric_limits<T>::digits/4);
				os<< std::hex << static_cast<unsigned int>( v[i] );
			}
		}

	}

	template <class T, class U>
	std::wostream& operator <<(std::wostream& os, out_mark<pp_as_t<pp::array_any, array_info_t<T,U> > > const & vv ){

		auto const unmarked_v = vv.m_v.m_val;
		auto const v = unmarked_v.m_value;

		size_t count = unmarked_v.m_in_count;

		if( unmarked_v.m_out_count && *unmarked_v.m_out_count<=unmarked_v.m_in_count ){
			count = *unmarked_v.m_out_count;
		}

		os << pp_as<pp::hex_auto>( static_cast<void const*>(v) ) <<L"=";
		if(v){
			dump_array(os, v, count);
		} else {
			os << STC_P_NULL_LIT;
		}
		return os;
	}

	template <class T, class U>
	std::wostream& operator <<(std::wostream& os, in_mark<pp_as_t<pp::array_any, array_info_t<T,U> > > const & vv ){
		dump_array(os,  vv.m_v.m_val.m_value, vv.m_v.m_val.m_in_count);
		return os;
	}



	template <class T>
	std::wostream& operator <<(std::wostream& out, out_mark<T> const &v ){
		return ( out << v.m_v );
	}

	template <class T>
	std::wostream& operator <<(std::wostream& out, in_mark<T> const &v ){
		return ( out << v.m_v );
	}


	inline std::wostream& operator <<(std::wostream& out, pp_as_t<pp::string, wchar_t const*> const &v ){
		if( v.m_val ){
			out << v.m_val;
		} else {
			out << STC_P_NULL_LIT;
		}
		return out;
	}

	inline std::wostream& operator <<(std::wostream& out, pp_as_t<pp::string, char const*> const &v ){
		if( v.m_val ){

			typedef gie::monotonic::fixed_storage<1024*sizeof(wchar_t)+128>	stor_t;
			typedef gie::monotonic::allocator<wchar_t, stor_t> alloc_t;
			typedef std::vector<wchar_t, alloc_t> buffer_t;

			stor_t local_storage;

			buffer_t buffer(  (alloc_t(local_storage))  );

			conv_str(v.m_val, buffer);

			out << buffer.data();
		} else {
			out << STC_P_NULL_LIT;
		}
		return out;
	}


	inline std::wostream& operator <<(std::wostream& out, pp_as_t<pp::dword, DWORD> const &v ){
		out << v.m_val;
		return out;
	}


	template <class T>
	std::wostream& operator <<(std::wostream& os, pp_as_t<pp::hex_auto, T> const &v ){

		boost::io::ios_flags_saver  ifs( os );

		os.width(std::numeric_limits<T>::digits/4);
		os.fill('0');
		os<< std::hex << v.m_val ;

		return os;
	}


	template <class T>
	std::wostream& operator <<(std::wostream& os, pp_as_t<pp::hex_auto, T **> const &v ){

		if( v.m_val ){
			os << L"@"<<pp_as<pp::hex_auto>( static_cast<void const*>(v.m_val) ) << L"=" << pp_as<pp::hex_auto>(*v.m_val);
		} else {
			os << STC_P_NULL_LIT;
		}

		return os;
	}

	inline std::wostream& operator <<(std::wostream& os, pp_as_t<pp::any, void**> const &v ){
		return ( os << pp_as<pp::hex_auto>(  v.m_val  )  );
	}


	inline std::wostream& operator <<(std::wostream& os, pp_as_t<pp::any, void*> const &v ){
		return ( os << pp_as<pp::hex_auto>(  v.m_val  )  );
	}

	inline std::wostream& operator <<(std::wostream& out, pp_as_t<pp::dword, DWORD *> const &v ){
		if( v.m_val ){
			out << L"@"<<pp_as<pp::hex_auto>( static_cast<void const*>(v.m_val) ) << L"=" << pp_as<pp::dword>(*v.m_val);
		} else {
			out << STC_P_NULL_LIT;
		}
		return out;
	}



	#define STC_PP(la) \
		auto const stcrypt__debug__pp__lambda = [&](bool const stcrypt__dbug__pp__in) la;	\
		::stcrypt::debug::scoped_la_invoker_t<decltype(stcrypt__debug__pp__lambda)> stcrypt__debug__pp( stcrypt__debug__pp__lambda )	\
		/**/

	#define STC_P(tag, x) stcrypt::pp_nv( BOOST_PP_WSTRINGIZE(x), stcrypt::pp_as<stcrypt::pp:: tag >(x) )
	#define STC_P_EX(tag, x, name) stcrypt::pp_nv( BOOST_PP_WSTRINGIZE(name), stcrypt::pp_as<stcrypt::pp:: tag >(x) )


	#define STC_INOUT_P_EX(tag, x, name) { std::wostringstream os; os<< ::stcrypt::in_m( STC_P_EX(tag, x, name) ); STCRYPT_LOG_W_STRING( os.str() ); }
	#define STC_IN_P_EX(tag, x, name) if(stcrypt__dbug__pp__in) STC_INOUT_P_EX(tag, x, name)
	#define STC_OUT_P_EX(tag, x, name) if(!stcrypt__dbug__pp__in) STC_INOUT_P_EX(tag, x, name)

	#define STC_IN_P(tag, x) STC_IN_P_EX(tag, x, x)
	#define STC_OUT_P(tag, x) STC_OUT_P_EX(tag, x, x)


// 	#define STC_PARAMS_GEN_T(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)   ( BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/) )
// 	#define STC_PARAMS_GEN_TEMPLATES(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)  "[" BOOST_PP_STRINGIZE( BOOST_PP_TUPLE_ELEM(2/*size*/, 0/*extract idx*/, oid_def /*tuple*/) ) ":%" BOOST_PP_STRINGIZE( BOOST_PP_INC(i) ) "%]"
// 	#define STC_PARAMS_GEN_CALL(r, aux/*aux data*/, i/*iter counter*/, oid_def /*data*/)  % BOOST_PP_TUPLE_ELEM(2/*size*/, 1/*extract idx*/, oid_def /*tuple*/)
// 
// 
// 
// 	#define STC_DUMP_PARAMS(params) \
// 		boost::format fun_params(BOOST_PP_SEQ_FOR_EACH_I( STC_PARAMS_GEN_TEMPLATES, 0, params ));	\
// 		STCRYPT_LOG_PRINT_EX("in", (fun_params BOOST_PP_SEQ_FOR_EACH_I( STC_PARAMS_GEN_CALL, 0, params ) ).str().c_str() );	\
// \
// 	BOOST_SCOPE_EXIT( ( &fun_params) 	BOOST_PP_SEQ_FOR_EACH_I( STC_PARAMS_GEN_T, 0, params ) ) {\
// 		STCRYPT_LOG_PRINT_EX("out", (fun_params BOOST_PP_SEQ_FOR_EACH_I( STC_PARAMS_GEN_CALL, 0, params ) ).str().c_str() );\
// 	}  BOOST_SCOPE_EXIT_END\
// 
// 	template <class T, class V>
// 	std::string param_dump_array( T const*const v, V const* const count){
// 		std::stringstream os;
// 		os<< "@"<<std::hex << static_cast<void const*>(v)<<"=";
// 		if(v){
// 			if(!count || *count==0) {
// 				os << "<empty>";
// 			} else {
// 				os.fill('0');
// 				for(unsigned int i = 0;i<*count;++i){
// 					if(i) {
// 						os << " ";
// 						os.width(0);
// 					}
// 					os.width(std::numeric_limits<T>::digits/4);
// 					os<< std::hex << static_cast<unsigned int>( v[i] );
// 				}
// 			}
// 		} else {
// 			os << "<NULL>";
// 		}
// 		return os.str();
// 	}
// 
// 	template <class T>
// 	std::string param_dump_array( T const*const v, DWORD const count){
// 		return param_dump_array(v, &count);
// 	}
// 
// 	template <class T>
// 	std::string param_dump_via_ptr(T const* const v){
// 		std::stringstream os;
// 		os<< "@"<<std::hex << static_cast<void const*>(v)<<"=";
// 		if(v){
// 			os << std::dec << *v;
// 		} else {
// 			os << "<NULL>";
// 		}
// 		
// 		return os.str();
// 	}
// 
// 	template <class T, class CountType>
// 	std::string param_dump_array_via_ptr(T const* const*const v, CountType const*const count){
// 		std::stringstream os;
// 		os<< "@"<<std::hex << static_cast<void const*>(v);
// 		if(v){
// 			os << param_dump_array(*v, count);
// 		} else {
// 			os << "<NULL>=<NULL>";
// 		}
// 
// 		return os.str();
// 	}
// 
// 	inline
// 	std::string param_dump_str(char const*const str){
// 		if(str){
// 			return str;
// 		} else {
// 			return "<NULL>";
// 		}
// 
// 	}
// 
// 	template<class T>
// 	std::string param_dump_hex(T const& v){
// 		std::stringstream os;
// 		os.width(std::numeric_limits<T>::digits/4);
// 		os.fill('0');
// 		os<< std::hex << v;
// 
// 		return os.str();
// 	}
// 
// 

}
//================================================================================================================================================
#endif
//================================================================================================================================================
