#pragma once

#include <click/config.h>
#include "IgmpMessage.hh"

CLICK_DECLS

/// A data structure that contains core variables used by IGMP routers.
struct IgmpRouterCoreVariables
{
    /// The Robustness Variable allows tuning for the expected packet loss on
    /// a network. If a network is expected to be lossy, the Robustness
    /// Variable may be increased. IGMP is robust to (Robustness Variable -
    /// 1) packet losses. The Robustness Variable MUST NOT be zero, and
    /// SHOULD NOT be one. Default: 2
    unsigned int robustness_variable = 2;

    /// The Query Interval is the interval between General Queries sent by
    /// the Querier. Default: 125 seconds.
    ///
    /// By varying the [Query Interval], an administrator may tune the number
    /// of IGMP messages on the network; larger values cause IGMP Queries to
    /// be sent less often.
    unsigned int query_interval = 1250;

    /// The Max Response Time used to calculate the Max Resp Code inserted
    /// into the periodic General Queries. Default: 100 (10 seconds)
    ///
    /// By varying the [Query Response Interval], an administrator may tune
    /// the burstiness of IGMP messages on the network; larger values make
    /// the traffic less bursty, as host responses are spread out over a
    /// larger interval. The number of seconds represented by the [Query
    /// Response Interval] must be less than the [Query Interval].
    unsigned int query_response_interval = 100;

    /// The Last Member Query Interval is the Max Response Time used to
    /// calculate the Max Resp Code inserted into Group-Specific Queries sent
    /// in response to Leave Group messages. It is also the Max Response
    /// Time used in calculating the Max Resp Code for Group-and-Source-
    /// Specific Query messages. Default: 10 (1 second)
    ///
    /// Note that for values of LMQI greater than 12.8 seconds, a limited set
    /// of values can be represented, corresponding to sequential values of
    /// Max Resp Code. When converting a configured time to a Max Resp Code
    /// value, it is recommended to use the exact value if possible, or the
    /// next lower value if the requested value is not exactly representable.
    ///
    /// This value may be tuned to modify the "leave latency" of the network.
    /// A reduced value results in reduced time to detect the loss of the
    /// last member of a group or source.
    unsigned int last_member_query_interval = 10;
};

/// A data structure that contains derived variables used by IGMP routers.
struct IgmpRouterDerivedVariables
{
    IgmpRouterDerivedVariables(const IgmpRouterCoreVariables &core_variables)
        : startup_query_count(core_variables.robustness_variable),
          startup_query_interval(core_variables.query_interval / 4),
          last_member_query_count(core_variables.robustness_variable)
    {
    }

    /// The Startup Query Count is the number of Queries sent out on startup,
    /// separated by the Startup Query Interval. Default: the Robustness
    /// Variable.
    unsigned int startup_query_count;

    /// The Startup Query Interval is the interval between General Queries
    /// sent by a Querier on startup. Default: 1/4 the Query Interval.
    unsigned int startup_query_interval;

    /// The Last Member Query Count is the number of Group-Specific Queries
    /// sent before the router assumes there are no local members. The Last
    /// Member Query Count is also the number of Group-and-Source-Specific
    /// Queries sent before the router assumes there are no listeners for a
    /// particular source. Default: the Robustness Variable.
    unsigned int last_member_query_count;
};

/// A data structure that contains both core and derived variables used by IGMP routers.
struct IgmpRouterVariables
{
    IgmpRouterVariables()
        : core_variables(), derived_variables(IgmpRouterCoreVariables())
    {
    }

    IgmpRouterVariables(
        const IgmpRouterCoreVariables &core_variables,
        const IgmpRouterDerivedVariables &derived_variables)
        : core_variables(core_variables), derived_variables(derived_variables)
    {
    }

    /// The Robustness Variable allows tuning for the expected packet loss on
    /// a network. If a network is expected to be lossy, the Robustness
    /// Variable may be increased. IGMP is robust to (Robustness Variable -
    /// 1) packet losses. The Robustness Variable MUST NOT be zero, and
    /// SHOULD NOT be one. Default: 2
    unsigned int get_robustness_variable() const
    {
        return core_variables.robustness_variable;
    }

    /// The Robustness Variable allows tuning for the expected packet loss on
    /// a network. If a network is expected to be lossy, the Robustness
    /// Variable may be increased. IGMP is robust to (Robustness Variable -
    /// 1) packet losses. The Robustness Variable MUST NOT be zero, and
    /// SHOULD NOT be one. Default: 2
    unsigned int &get_robustness_variable()
    {
        return core_variables.robustness_variable;
    }

    /// The Query Interval is the interval between General Queries sent by
    /// the Querier. Default: 125 seconds.
    ///
    /// By varying the [Query Interval], an administrator may tune the number
    /// of IGMP messages on the network; larger values cause IGMP Queries to
    /// be sent less often.
    unsigned int get_query_interval() const
    {
        return core_variables.query_interval;
    }

    /// The Query Interval is the interval between General Queries sent by
    /// the Querier. Default: 125 seconds.
    ///
    /// By varying the [Query Interval], an administrator may tune the number
    /// of IGMP messages on the network; larger values cause IGMP Queries to
    /// be sent less often.
    unsigned int &get_query_interval()
    {
        return core_variables.query_interval;
    }

    /// The Max Response Time used to calculate the Max Resp Code inserted
    /// into the periodic General Queries. Default: 100 (10 seconds)
    ///
    /// By varying the [Query Response Interval], an administrator may tune
    /// the burstiness of IGMP messages on the network; larger values make
    /// the traffic less bursty, as host responses are spread out over a
    /// larger interval. The number of seconds represented by the [Query
    /// Response Interval] must be less than the [Query Interval].
    unsigned int get_query_response_interval() const
    {
        return core_variables.query_response_interval;
    }

    /// The Max Response Time used to calculate the Max Resp Code inserted
    /// into the periodic General Queries. Default: 100 (10 seconds)
    ///
    /// By varying the [Query Response Interval], an administrator may tune
    /// the burstiness of IGMP messages on the network; larger values make
    /// the traffic less bursty, as host responses are spread out over a
    /// larger interval. The number of seconds represented by the [Query
    /// Response Interval] must be less than the [Query Interval].
    unsigned int &get_query_response_interval()
    {
        return core_variables.query_response_interval;
    }

    /// The Last Member Query Interval is the Max Response Time used to
    /// calculate the Max Resp Code inserted into Group-Specific Queries sent
    /// in response to Leave Group messages. It is also the Max Response
    /// Time used in calculating the Max Resp Code for Group-and-Source-
    /// Specific Query messages. Default: 10 (1 second)
    ///
    /// Note that for values of LMQI greater than 12.8 seconds, a limited set
    /// of values can be represented, corresponding to sequential values of
    /// Max Resp Code. When converting a configured time to a Max Resp Code
    /// value, it is recommended to use the exact value if possible, or the
    /// next lower value if the requested value is not exactly representable.
    ///
    /// This value may be tuned to modify the "leave latency" of the network.
    /// A reduced value results in reduced time to detect the loss of the
    /// last member of a group or source.
    unsigned int get_last_member_query_interval() const
    {
        return core_variables.last_member_query_interval;
    }

    /// The Last Member Query Interval is the Max Response Time used to
    /// calculate the Max Resp Code inserted into Group-Specific Queries sent
    /// in response to Leave Group messages. It is also the Max Response
    /// Time used in calculating the Max Resp Code for Group-and-Source-
    /// Specific Query messages. Default: 10 (1 second)
    ///
    /// Note that for values of LMQI greater than 12.8 seconds, a limited set
    /// of values can be represented, corresponding to sequential values of
    /// Max Resp Code. When converting a configured time to a Max Resp Code
    /// value, it is recommended to use the exact value if possible, or the
    /// next lower value if the requested value is not exactly representable.
    ///
    /// This value may be tuned to modify the "leave latency" of the network.
    /// A reduced value results in reduced time to detect the loss of the
    /// last member of a group or source.
    unsigned int &get_last_member_query_interval()
    {
        return core_variables.last_member_query_interval;
    }

    /// The Startup Query Count is the number of Queries sent out on startup,
    /// separated by the Startup Query Interval. Default: the Robustness
    /// Variable.
    unsigned int get_startup_query_count() const
    {
        return derived_variables.startup_query_count;
    }

    /// The Startup Query Count is the number of Queries sent out on startup,
    /// separated by the Startup Query Interval. Default: the Robustness
    /// Variable.
    unsigned int &get_startup_query_count()
    {
        return derived_variables.startup_query_count;
    }

    /// The Startup Query Interval is the interval between General Queries
    /// sent by a Querier on startup. Default: 1/4 the Query Interval.
    unsigned int get_startup_query_interval() const
    {
        return derived_variables.startup_query_interval;
    }

    /// The Startup Query Interval is the interval between General Queries
    /// sent by a Querier on startup. Default: 1/4 the Query Interval.
    unsigned int &get_startup_query_interval()
    {
        return derived_variables.startup_query_interval;
    }

    /// The Last Member Query Count is the number of Group-Specific Queries
    /// sent before the router assumes there are no local members. The Last
    /// Member Query Count is also the number of Group-and-Source-Specific
    /// Queries sent before the router assumes there are no listeners for a
    /// particular source. Default: the Robustness Variable.
    unsigned int get_last_member_query_count() const
    {
        return derived_variables.last_member_query_count;
    }

    /// The Last Member Query Count is the number of Group-Specific Queries
    /// sent before the router assumes there are no local members. The Last
    /// Member Query Count is also the number of Group-and-Source-Specific
    /// Queries sent before the router assumes there are no listeners for a
    /// particular source. Default: the Robustness Variable.
    unsigned int &get_last_member_query_count()
    {
        return derived_variables.last_member_query_count;
    }

    /// The Group Membership Interval is the amount of time that must pass
    /// before a multicast router decides there are no more members of a
    /// group or a particular source on a network.
    /// This value MUST be ((the Robustness Variable) times (the Query
    /// Interval)) plus (one Query Response Interval).
    unsigned int get_group_membership_interval() const
    {
        return get_robustness_variable() * get_query_interval() + get_query_response_interval();
    }

    /// The Last Member Query Time is the time value represented by the Last
    /// Member Query Interval, multiplied by the Last Member Query Count. It
    /// is not a tunable value, but may be tuned by changing its components.
    unsigned int get_last_member_query_time() const
    {
        return get_last_member_query_interval() * get_last_member_query_count();
    }

    /// The Other Querier Present Interval is the length of time that must
    /// pass before a multicast router decides that there is no longer
    /// another multicast router which should be the querier. This value
    /// MUST be ((the Robustness Variable) times (the Query Interval)) plus
    /// (one half of one Query Response Interval).
    unsigned int get_other_querier_present_interval() const
    {
        return get_robustness_variable() * get_query_interval() + get_query_response_interval() / 2;
    }

  private:
    IgmpRouterCoreVariables core_variables;
    IgmpRouterDerivedVariables derived_variables;
};

CLICK_ENDDECLS