//================================================================================================================================================
// FILE: stcrypt-cng-dstu4145-impl.h
// (c) GIE 2010-09-02  12:47
//
//================================================================================================================================================
#ifndef H_GUARD_STCRYPT_CNG_DSTU4145_IMPL_2010_09_02_12_47
#define H_GUARD_STCRYPT_CNG_DSTU4145_IMPL_2010_09_02_12_47
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "../../stcrypt-csp/stcrypt-cryptolib.hpp"
#include "util-sio.hpp"

#include "CryptoLib.h"

#include <boost/optional.hpp>
#include <boost/range/begin.hpp>
#include <boost/range/end.hpp>
//================================================================================================================================================
namespace stcrypt {

	namespace sio {




		template<>
		struct io_size<TECPOINT> {

			static size_t const value 
				= io_size<TGFELEMENT>::value
				+ io_size<TGFELEMENT>::value;
		};


		template <>
		struct write<TECPOINT> {
			template <class OutputIter>
			static boost::tuple<size_t, OutputIter> apply(TECPOINT const& v, OutputIter const output){

				auto const out1 = sio::write<decltype(v.x)>::apply( v.x, output );
				auto const out2 = sio::write<decltype(v.y)>::apply( v.y, boost::get<1>( out1 ) );

				assert( sio::io_size<decltype(v)>::value == boost::get<0>(out1) + boost::get<0>(out1) );

				return boost::make_tuple( sio::io_size<decltype(v)>::value , boost::get<1>(out2) );
			}
		};



		template <> 
		struct read<TECPOINT> {
			template <class InputIterator>
			static boost::tuple< boost::iterator_range<InputIterator>, size_t >
			apply(TECPOINT& v, boost::iterator_range<InputIterator> const& input){
				

				auto const& e1r = sio::read<decltype(v.x)>::apply( v.x, input );
				auto const& e2r = sio::read<decltype(v.y)>::apply( v.y, boost::get<0>( e1r ) );

				return boost::make_tuple( boost::get<0>( e2r ),  boost::get<1>( e1r )+boost::get<1>( e2r ) );

			}

		};


	}

	struct dstu4145_t 
	{
		typedef TGFELEMENT	private_part_type;
		typedef TECPOINT	public_part_type;
		typedef TBLOCK256	sign_block_type;
		typedef TBLOCK256	plaintext_block_type;

		struct tag_generate{};
		struct tag_import{};

		explicit dstu4145_t(tag_generate const&);
		dstu4145_t(tag_import const&, boost::optional<private_part_type const &> const& private_part, boost::optional<public_part_type const&> const& public_part);
		~dstu4145_t();

		size_t signature_block_size()const{ return sizeof(sign_block_type); }
		size_t signature_size()const;
		size_t key_length()const{ return sizeof(private_part_type); /*TODO*/ }
		void sign(BYTE const* const data, size_t const data_size, BYTE * const sign_buffer, size_t const sign_buffer_size);
		bool verify(BYTE const* const data, size_t const data_size, BYTE const * const signature, size_t const signature_size);

		boost::tuple<size_t,size_t> buffers_sizes()const;
		size_t encrypt_block(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len);
		size_t decrypt_block(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len);

		size_t encrypt_blocks(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len);
		size_t decrypt_blocks(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len);

		size_t encrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len);
		size_t decrypt(BYTE const * const data, size_t const data_len, BYTE * const out_buffer, size_t const out_buffer_len);

		size_t public_part_size()const{ return sio::io_size<decltype(m_public_part)>::value; }
		size_t private_part_size()const{ return (m_private_part?sio::io_size<decltype(*m_private_part)>::value:0); }

		template <class OutputIter>
		void public_part(OutputIter const& o_iter){
			sio::write<decltype(m_public_part)>::apply( m_public_part, o_iter );
		}

 		template <class OutputIter>
 		void private_part(OutputIter const& o_iter){
 			assert(m_private_part);
			sio::write<decltype(*m_private_part)>::apply( *m_private_part, o_iter );
 		}
	private:
		unsigned int	m_std_mode;
		boost::optional<private_part_type>  m_private_part; //d
		public_part_type					m_public_part; //Q

		CL_CONTEXT m_ctx;
	};

}
//================================================================================================================================================
#endif
//================================================================================================================================================
