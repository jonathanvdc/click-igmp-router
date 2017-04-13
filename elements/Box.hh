#pragma once

#include <click/config.h>

CLICK_DECLS

/// A non-null pointer to a value that resides in the heap. Whenever the box is
/// assigned a value, its previous value is deleted and a copy of the new value
/// is created.
template <typename T>
class Box final
{
  public:
    template <typename... TArgs>
    Box(const TArgs &... values)
        : val(new T(values...))
    {
    }

    Box(const Box<T> &other)
        : Box(*other.val)
    {
    }

    Box<T> &operator=(const Box<T> &other)
    {
        if (this != &other)
        {
            delete val;
            val = new T(*other.val);
        }
    }

    ~Box()
    {
        delete val;
    }

    T *get() const { return val; }
    T &operator*() const { return *val; }
    T *operator->() const { return val; }

  private:
    /// The value that is managed.
    T *val;
};

CLICK_ENDDECLS