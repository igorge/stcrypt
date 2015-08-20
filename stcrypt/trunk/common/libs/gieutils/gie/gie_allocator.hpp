// Copyright (C) 2009 Christian Schladetsch
// (c) 2010 GIE
//
//  Distributed under the Boost Software License, Version 1.0. (See accompanying 
//  file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)

#ifndef BOOST_MONOTONIC_ALLOCATOR_HPP_GIE347564785
#define BOOST_MONOTONIC_ALLOCATOR_HPP_GIE347564785


#include <boost/type_traits/has_trivial_constructor.hpp>
#include <boost/type_traits/has_trivial_destructor.hpp>
#include <boost/integer.hpp>


namespace gie
{
    namespace monotonic
    {


        /// common to other monotonic allocators for type T of type Derived
        template 
		<
			class T, 
			class StorageT, 
			size_t MinAlignment,
			class Derived
		>
        struct allocator_base
        {
            typedef size_t size_type;
            typedef ptrdiff_t difference_type;
            typedef T *pointer;
            typedef const T *const_pointer;
            typedef T &reference;
            typedef const T &const_reference;
            typedef T value_type;


            //BOOST_STATIC_CONSTANT(size_t, alignment = boost::aligned_storage<sizeof(T)>::alignment);
			BOOST_STATIC_CONSTANT(size_t, alignment = (MinAlignment>boost::alignment_of<T>::value?MinAlignment:boost::alignment_of<T>::value) );

        //private:
            StorageT *storage;

        public:
            allocator_base(StorageT &store) throw()
                : storage(&store) { }

            allocator_base(const allocator_base& alloc) throw()
                : storage(alloc.storage) { }

            template <class U, class OtherStorageT, size_t OtherMinAlignment, class D>
            allocator_base(const allocator_base<U,OtherStorageT, OtherMinAlignment, D> &alloc) throw()
                : storage(alloc.storage) { }

            pointer address(reference x) const
            {
                return &x;
            }

            const_pointer address(const_reference x) const
            {
                return &x;
            }

            pointer allocate(size_type num, const void * /*hint*/ = 0)
            {
				BOOST_STATIC_ASSERT(alignment%MinAlignment==0);

                BOOST_ASSERT(num > 0);
                BOOST_ASSERT(storage != 0);

                size_t const objs_size = num*sizeof(T);

                T * tmp = reinterpret_cast<T*>(storage->allocate( objs_size, alignment));

                if( !tmp ){
                    tmp = reinterpret_cast<T*>( new char[ objs_size ] );
                }
                
                return tmp;
            }

            void deallocate(pointer ptr, size_type num)
            {
                if( ptr >= static_cast<void const*>( storage->begin() )
                    && ptr < static_cast<void const*>(storage->end()) )
                {
                    storage->deallocate(ptr);//, num);
                } else {
                    delete[] reinterpret_cast<char*>( ptr );
                }
            }

            size_type max_size() const throw()
            {
                if (!storage) return 0;

                return boost::integer_traits<size_t>::const_max / sizeof(value_type);
            }

            void construct(pointer ptr)
            {
                 new (ptr) T();
            }

            void construct(pointer ptr, const T& val)
            {
                 new (ptr) T(val);
            }

            void construct(pointer ptr, T&& val)
            {
                 new (ptr) T( std::move(val) );
            }

            Derived *DerivedPtr()
            {
                return static_cast<Derived *>(this);
            }

            void destroy(pointer ptr)
            {
                if (!ptr)
                    return;
                destroy(ptr, boost::has_trivial_destructor<value_type>());
            }

            void destroy(pointer ptr, const boost::false_type& )
            {
                (*ptr).~value_type();
            }

            void destroy(pointer, const boost::true_type& )
            {
            }

            void swap(Derived &other)
            {
                std::swap(storage, other.storage);
            }

            StorageT *get_storage() const
            {
                return storage;
            }

            friend bool operator==(allocator_base<T, StorageT, MinAlignment, Derived> const &A, allocator_base<T, StorageT, MinAlignment, Derived> const &B)
            {
                return A.storage == B.storage;
            }

            friend bool operator!=(allocator_base<T, StorageT, MinAlignment, Derived> const &A, allocator_base<T,StorageT, MinAlignment, Derived> const &B)
            {
                return A.storage != B.storage;
            }
        };



        template 
		<
			class T, 
			class StorageT,
			size_t MinAlignment = boost::alignment_of<T>::value
		>
        struct allocator 
            : allocator_base<T, StorageT, MinAlignment, allocator<T, StorageT, MinAlignment> >
        {
            typedef allocator_base<T, StorageT, MinAlignment, allocator<T, StorageT, MinAlignment> > Parent;
            using typename Parent::size_type;
            using typename Parent::difference_type;
            using typename Parent::pointer;
            using typename Parent::const_pointer;
            using typename Parent::reference;
            using typename Parent::const_reference;
            using typename Parent::value_type;

            template <class U> 
            struct rebind 
            { 
                typedef allocator<U, StorageT, MinAlignment> other;
            };


        public:
            allocator(StorageT &store) throw()
                : Parent(store) { }

        public:
            allocator(const allocator& alloc) throw() 
                : Parent(alloc) { }

            template <class U, size_t OtherMinAlignment> 
            allocator(const allocator<U, StorageT, OtherMinAlignment> &alloc) throw()
                : Parent(alloc) { }

            friend bool operator==(allocator<T,StorageT, MinAlignment> const &A, allocator<T,StorageT, MinAlignment> const &B)
            { 
                return static_cast<Parent const &>(A) == static_cast<Parent const &>(B);
            }

            friend bool operator!=(allocator<T,StorageT, MinAlignment> const &A, allocator<T,StorageT, MinAlignment> const &B)
            { 
                return static_cast<Parent const &>(A) != static_cast<Parent const &>(B);
            }
        };
    
    } // namespace monotonic

} // namespace boost

#endif // BOOST_MONOTONIC_ALLOCATOR_HPP

//EOF
