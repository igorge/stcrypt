//================================================================================================================================================
// FILE: utll-capi-get-param-enums-impl.h
// (c) GIE 2009-11-14  13:26
//
//================================================================================================================================================
#ifndef H_GUARD_UTLL_CAPI_GET_PARAM_ENUMS_IMPL_2009_11_14_13_26
#define H_GUARD_UTLL_CAPI_GET_PARAM_ENUMS_IMPL_2009_11_14_13_26
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "util-capi-get-param-impl.hpp"
#include "util-bittest.hpp"

#include "boost/utility/in_place_factory.hpp"
#include "boost/optional.hpp"
#include "boost/bind.hpp"
#include <utility>
//================================================================================================================================================
namespace stcrypt {

	template <class T, unsigned int ID> struct tag {typedef T type;};

	template <
		class Self,
		class ItemType,
		class IterType,
		unsigned int ID=0
	>
	struct get_param_enums_impl_t // mixin
	{
		typedef Self self_type;
		typedef ItemType item_type;
		typedef IterType iterator_type;

		typedef get_param_enums_impl_t<Self, ItemType, IterType> mixin_type;
		typedef tag<mixin_type, ID> tag_type;

	private:
		struct state_t_ {
			state_t_(std::pair<iterator_type, iterator_type> const& iters)
				: m_current(iters.first)
				, m_end(iters.second)
				, m_consumed(true)
				, m_first(false)
			{}

			bool consumed()const{
				return m_consumed;
			}

			void consume(bool const status=true){
				m_consumed=status;
			}

			bool eof()const{
				return m_current==m_end;
			}

			bool feed_next(self_type* parent){
				assert(consumed());
				if( eof() ) return false;

				parent->from_iter_to_item_(tag_type(), m_current, m_item);

				consume(false);
				++m_current;
				return true;
			}

			bool is_first()const throw() {
				return m_first;
			}
			void set_first(bool const v){
				m_first = v;
			}

			iterator_type  m_current;
			iterator_type  const m_end;
			item_type m_item;
			bool m_consumed;
			bool m_first;
		}; // state_t_

		bool feed_next(){
			assert(m_state);
			return m_state->feed_next( get_self_() );
		}

		item_type const& item()const{
			assert(m_state);
			if(!m_state){
				STCRYPT_UNEXPECTED();
			}
			return m_state->m_item;
		}

		void do_copy__enum_item_(BYTE* const data, DWORD const datalen){
			assert( get_self_()->item_size_(tag_type(), item() )==datalen);
			get_self_()->copy_func_(tag_type(), item(), data, datalen);  
			m_state->consume();
		}

	public:
		get_param_enums_impl_t()
		{}

		void get_param__enum_impl_(BYTE* const data, DWORD * const datalen, DWORD const flags){
			if( test_if_any_in_mask<DWORD>(flags,  ~static_cast<DWORD>(CRYPT_FIRST | CRYPT_NEXT) ) ) {
				STCRYPT_THROW_EXCEPTION(exception::badflags() << exception::flags_einfo(flags));
			}
			if( test_mask<DWORD>(flags, CRYPT_FIRST) ) {
				if( ! (m_state && m_state->is_first() && !m_state->consumed()) ) {
					m_state.reset();
					m_state = boost::in_place( get_self_()->init_iters_(tag_type()) );
					if( !feed_next() ) {
						m_state.reset(); 
						STCRYPT_THROW_EXCEPTION(exception::no_more_items());
					}
					m_state->set_first(true);
				}
			} else /*if( test_mask<DWORD>(flags, CRYPT_NEXT) )*/ {
				if(!m_state) {
					STCRYPT_THROW_EXCEPTION(exception::no_more_items());
				}
				if(m_state->consumed()) {
					if( !feed_next() ) {
						m_state.reset(); 
						STCRYPT_THROW_EXCEPTION(exception::no_more_items());
					}
					if( m_state->is_first() ) m_state->set_first(false);
				}
				// if not consumed - reuse the same item
				//} else {
				//	STCRYPT_THROW_EXCEPTION(exception::badflags() << exception::flags_einfo(flags) );
			}

			assert(!m_state->consumed());

			capi_get_param_impl(get_self_()->item_size_(tag_type(), item() ), 
				data, 
				datalen, 
				boost::bind( &mixin_type::do_copy__enum_item_, this, _1, _2));
		}



	private:
		boost::optional<state_t_ > m_state;

		self_type* get_self_() {
			return static_cast<self_type*>(this);
		}
		self_type const * get_self_()const {
			return static_cast<self_type const*>(this);
		}

	};
}
//================================================================================================================================================
#endif
//================================================================================================================================================
