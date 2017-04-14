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
        timer = make_rc<Timer>(&callback_thunk, callback.get());
    }

    /// Initializes this timer by assigning it to an owner.
    void initialize(Element *owner)
    {
        timer->initialize(owner);
    }

    /// Schedules the timer to fire after the given amount of seconds.
    void schedule_after_sec(uint32_t delta_sec)
    {
        if (timer->initialized())
        {
            timer->schedule_after_sec(delta_sec);
        }
    }

    /// Schedules the timer to fire after the given amount of centiseconds.
    void schedule_after_csec(uint32_t delta_csec)
    {
        schedule_after_msec(delta_csec * 100);
    }

    /// Schedules the timer to fire after the given amount of milliseconds.
    void schedule_after_msec(uint32_t delta_msec)
    {
        if (timer->initialized())
        {
            timer->schedule_after_msec(delta_msec);
        }
    }

  private:
    static void callback_thunk(Timer *, void *data)
    {
        TCallback *func = (TCallback *)data;
        (*func)();
    }

    Rc<Timer> timer;
    Rc<TCallback> callback;
};

CLICK_ENDDECLS