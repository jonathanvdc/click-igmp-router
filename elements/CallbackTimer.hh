#pragma once

#include <click/config.h>
#include "Box.hh"
#include "Rc.hh"

CLICK_DECLS

/// A timer that with a strongly-typed callback. Both the timer and
/// the callback's resources are reclaimed once they are no longer
/// necessary.
template <typename TCallback>
class CallbackTimer final
{
  public:
    template <typename... TArgs>
    CallbackTimer(const TArgs &... args)
        : callback(args...)
    {
        timer = Box<Timer>(&callback_thunk, callback.get());
    }

    /// Initializes this timer by assigning it to an owner.
    void initialize(Element *owner)
    {
        timer->initialize(owner);
    }

    /// Schedules the timer to fire after the given amount of time.
    void schedule_after_sec(uint32_t delta_sec)
    {
        if (timer->initialized())
        {
            timer->schedule_after_sec(delta_sec);
        }
    }

  private:
    static void callback_thunk(Timer *, void *data)
    {
        TCallback *func = (TCallback *)data;
        (*func)();
    }

    Box<Timer> timer;
    Rc<TCallback> callback;
};

CLICK_ENDDECLS