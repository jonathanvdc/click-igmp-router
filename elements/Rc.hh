#pragma once

#include <click/config.h>

CLICK_DECLS

/// A reference-counted non-null pointer to a shared value that resides in the heap.
template <typename T>
class Rc final
{
  public:
    template <typename... TArgs>
    Rc(const TArgs &... values)
        : val(new T(values...)), ref_count(new size_t(1))
    {
    }

    Rc(const Rc<T> &other)
        : val(other.val), ref_count(other.ref_count)
    {
        inc_ref_count();
    }

    Rc<T> &operator=(const Rc<T> &other)
    {
        if (this != &other)
        {
            dec_ref_count();
            val = other.val;
            ref_count = other.ref_count;
            inc_ref_count();
        }
    }

    ~Rc()
    {
        dec_ref_count();
    }

    T *get() const { return val; }
    T &operator*() const { return *val; }
    T *operator->() const { return val; }

  private:
    void inc_ref_count()
    {
        (*ref_count)++;
    }

    void dec_ref_count()
    {
        (*ref_count)--;
        if (*ref_count == 0)
        {
            delete val;
            delete ref_count;
        }
    }

    /// The value that is managed.
    T *val;
    /// The value's reference count.
    size_t *ref_count;
};

CLICK_ENDDECLS