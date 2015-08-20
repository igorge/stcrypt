//================================================================================================================================================
// FILE: gie_auto_vector.h
// (c) GIE 2010-09-25  22:00
//
//================================================================================================================================================
#ifndef H_GUARD_GIE_AUTO_VECTOR_2010_09_25_22_00
#define H_GUARD_GIE_AUTO_VECTOR_2010_09_25_22_00
//================================================================================================================================================
#pragma once
//================================================================================================================================================
#include "gie_fixed_storage.hpp"
#include "gie_allocator.hpp"


#include <boost/noncopyable.hpp>
#include <boost/static_assert.hpp>

#include <vector>
//================================================================================================================================================
namespace gie {

    namespace monotonic {

        template <class T, size_t InlineSizeInChars=4*1024>
        struct vector : boost::noncopyable
        {
            typedef vector this_type;

            static size_t const inline_size_in_value_types = InlineSizeInChars/sizeof(T);
            static size_t const exta_memory_for_vector_internal = 128;

            typedef gie::monotonic::fixed_storage<InlineSizeInChars + exta_memory_for_vector_internal>        storage_type;
            typedef gie::monotonic::allocator<T, storage_type>              allocator_type;

            typedef std::vector<T, allocator_type > intern_vector_type;

            typedef typename intern_vector_type::reference   reference;
            typedef typename intern_vector_type::reference   const_reference;
            typedef typename intern_vector_type::iterator   iterator;
            typedef typename intern_vector_type::const_iterator   const_iterator;
            typedef typename intern_vector_type::size_type   size_type;
            typedef typename intern_vector_type::difference_type   difference_type;
            typedef typename intern_vector_type::value_type   value_type;
            typedef typename intern_vector_type::pointer   pointer;
            typedef typename intern_vector_type::const_pointer   const_pointer;
            typedef typename intern_vector_type::reverse_iterator   reverse_iterator;
            typedef typename intern_vector_type::const_reverse_iterator   const_reverse_iterator;

            allocator_type get_allocator() const{ return m_intern_vector.get_allocator(); }

            iterator begin (){ return m_intern_vector.begin(); }
            const_iterator begin () const{ return m_intern_vector.begin(); }
            iterator end (){ return m_intern_vector.end(); }
            const_iterator end () const{ return m_intern_vector.end(); }
            reverse_iterator rbegin(){ return m_intern_vector.rbegin(); }
            const_reverse_iterator rbegin() const{ return m_intern_vector.rbegin(); }
            reverse_iterator rend(){ return m_intern_vector.rend(); }
            const_reverse_iterator rend() const{ return m_intern_vector.rend(); }

            reference operator[] ( size_type n ){ return m_intern_vector[n]; }
            const_reference operator[] ( size_type n ) const{ return m_intern_vector[n]; }
            const_reference at ( size_type n ) const{ return m_intern_vector.at(n); }
            reference at ( size_type n ){ return m_intern_vector.at(n); }

            reference front ( ) { return m_intern_vector.front(); };
            const_reference front ( ) const{ return m_intern_vector.front(); };
            reference back ( ) { return m_intern_vector.back(); };
            const_reference back ( ) const{ return m_intern_vector.back(); };

            pointer data(){ return m_intern_vector.data(); }
            const_pointer data()const{ return m_intern_vector.data(); }

            size_type size() const {return m_intern_vector.size(); };
            void reserve ( size_type n ) { return m_intern_vector.reserve(n); };
            bool empty () const { return m_intern_vector.empty(); };
            size_type capacity () const{ return m_intern_vector.capacity(); };
            void resize ( size_type sz, T c = T() ) { return m_intern_vector.resize(sz); };
            size_type max_size () const{ return m_intern_vector.max_size(); };

            void clear ( ){ return m_intern_vector.clear(); }

            iterator erase ( iterator position ) { return m_intern_vector.erase(position); };
            iterator erase ( iterator first, iterator last ){ return m_intern_vector.erase(first, last); };

            iterator insert ( iterator position, const T& x ){ return m_intern_vector.insert(position, x); }
            void insert ( iterator position, size_type n, const T& x ){ return m_intern_vector.insert(position, n, x); }
            template <class InputIterator>
            void insert ( iterator position, InputIterator first, InputIterator last ){ return m_intern_vector.insert(position, first, last); }

            void pop_back ( ){ return m_intern_vector.pop_back(); }
            void push_back ( const T& x ){ return m_intern_vector.push_back(x); }

            template <class InputIterator>
            void assign ( InputIterator first, InputIterator last ){ return m_intern_vector.assign(first, last); }
            void assign ( size_type n, const T& u ){ return m_intern_vector.assign(n, u); }


            vector()
                : m_intern_vector( allocator_type(m_storage) )
            {
                BOOST_STATIC_ASSERT( inline_size_in_value_types!=0 );

                m_intern_vector.reserve( inline_size_in_value_types );

                assert( m_storage.num_failed_allocs()==0 );
            }


        private:
            storage_type    m_storage;
            intern_vector_type  m_intern_vector;
        };

    } // end ns monotonic

}
//================================================================================================================================================
#endif
//================================================================================================================================================
