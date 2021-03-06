#pragma once

#include <click/config.h>
#include <click/timer.hh>
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

    /// Tests if this timer has been initialized yet.
    bool initialized() const
    {
        return timer->initialized();
    }

    /// Tests if this timer is scheduled to expire at some point.
    bool scheduled() const
    {
        return timer->scheduled();
    }

    /// Schedules the timer to fire after the given amount of seconds.
    void schedule_after_sec(uint32_t delta_sec)
    {
        if (timer->initialized())
        {
            timer->schedule_after_sec(delta_sec);
        }
    }

    /// Schedules the timer to fire after the given amount of deciseconds.
    void schedule_after_dsec(uint32_t delta_dsec)
    {
        schedule_after_msec(delta_dsec * 100);
    }

    /// Schedules the timer to fire after the given amount of milliseconds.
    void schedule_after_msec(uint32_t delta_msec)
    {
        if (timer->initialized())
        {
            timer->schedule_after_msec(delta_msec);
        }
    }

    /// Reschedules the timer to fire after the given amount of deciseconds
    /// past the previous expiration time.
    void reschedule_after_dsec(uint32_t delta_dsec)
    {
        reschedule_after_msec(delta_dsec * 100);
    }

    /// Reschedules the timer to fire after the given amount of milliseconds
    /// past the previous expiration time.
    void reschedule_after_msec(uint32_t delta_msec)
    {
        if (timer->initialized())
        {
            timer->reschedule_after_msec(delta_msec);
        }
    }

    /// Unschedules this timer.
    void unschedule()
    {
        if (timer->initialized())
        {
            timer->unschedule();
        }
    }

    /// Gets the amount of time remaining until this timer fires, in milliseconds.
    uint32_t remaining_time_msec() const
    {
        return (timer->expiry_steady() - Timestamp::recent_steady()).msec();
    }

    /// Gets the amount of time remaining until this timer fires, in deciseconds.
    uint32_t remaining_time_dsec() const
    {
        return remaining_time_msec() / 100;
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