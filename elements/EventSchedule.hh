#pragma once

#include <click/config.h>
#include <click/hashmap.hh>
#include <click/element.hh>
#include "CallbackTimer.hh"

CLICK_DECLS

/// Represents a schedule of events which have yet to fire.
template <typename TEvent>
class EventSchedule final
{
  public:
    EventSchedule(Element *owner)
        : owner(owner), id_counter(0), events()
    {
    }

    /// Makes the given event fire after the given number of milliseconds.
    void schedule_after_msec(uint32_t delta_msec, const TEvent &event)
    {
        // First, get rid of all expired events.
        for (const auto &item : expired_events)
        {
            events.erase(item);
        }
        expired_events.clear();

        // Generate an id.
        auto id = id_counter++;
        // Create a timer with a callback.
        CallbackTimer<EventCallback> timer{id, event, this};
        // Initialize the timer and schedule its expiry.
        timer.initialize(owner);
        timer.schedule_after_msec(delta_msec);

        // Add the timer to the list of scheduled events.
        // (to keep it alive)
        events.insert(id, timer);
    }

    /// Makes the given event fire after the given number of centiseconds.
    void schedule_after_csec(uint32_t delta_csec, const TEvent &event)
    {
        schedule_after_msec(delta_csec * 100, event);
    }

  private:
    struct EventCallback
    {
        EventCallback()
            : id(), event(), schedule(nullptr)
        {
        }
        EventCallback(uint64_t id, const TEvent &event, EventSchedule *schedule)
            : id(id), event(event), schedule(schedule)
        {
        }

        uint64_t id;
        TEvent event;
        EventSchedule *schedule;

        void operator()()
        {
            if (schedule == nullptr)
            {
                return;
            }

            // Run the event.
            event();

            // Mark the event as expired.
            schedule->expired_events.push_back(id);

            // NOTE: the event's timer is not removed directly here
            // because that could have funny consequences.
            //
            // Suppose that we did this:
            //
            //     events.erase(id);
            //
            // Then the callback for that event would be deleted by the hashmap,
            // i.e., its destructor would be called and the memory would be recycled.
            // Now keep in mind that this method _is part of_ that callback.
            // I might be wrong, but I think that destroying an object that still has
            // an active call frame on the stack is undefined behavior, so not a good
            // idea.
            //
            // To work around this, schedule_after_msec erases expired events afterward.
        }
    };

    Element *owner;
    uint64_t id_counter;
    HashMap<uint64_t, CallbackTimer<EventCallback>> events;
    Vector<uint64_t> expired_events;
};

CLICK_ENDDECLS