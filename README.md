
# Click IGMPv3 protocol implementation

[![Build Status](https://travis-ci.org/jonathanvdc/click-igmp-router.svg?branch=master)](https://travis-ci.org/jonathanvdc/click-igmp-router)

This (partial) IGMPv3 protocol implementation is my project for the Telecommunication Systems course at the University of Antwerp. It implements both router and client elements, which are also used in the `scripts/*` scripts.

## Building the protocol implementation

The following sequence of commands will download Click, untar it, build it with appropriate C++ compiler flags, copy my `elements/` to `click-2.0.1/elements/local` and build those too.

```bash
$ ./download-click.sh
$ make -C click-2.0.1
$ make
```

## Testing the protocol implementation

The `test-run.sh` script runs the `scripts/ipnetwork.click` script and then calls every handler at least once.

> **Note:** `test-run.sh` is kind of hard to kill. (A naive Ctrl-C won't work.) So, um, try not to *accidentally* run this script.

If you want manual control, fire up Click yourself and run some handlers of your choice. You may want to consult the next section for a description of the utility scripts in this project. For example, spelling the commands below will make `client21` join the multicast network and then leave it.

```bash
# You've got to specify '-p 10000' for the utility scripts to work.
terminal_one$ ./click-2.0.1/userlevel/click -p 10000 scripts/ipnetwork.click
# Meanwhile, in another terminal.
terminal_two$ ./shell/join.sh client21
terminal_two$ ./shell/leave.sh client21
# You're free to terminate the process running in terminal one at this point.
```



## Useful shell scripts

You can make the router and clients in `scripts/ipnetwork.click` do all kinds of fun stuff by calling their handlers. The following utility shell scripts have been included (along with their usage) to save you the trouble of manually calling `telnet` every time you want to prod something.

  * `download-click.sh`: Downloads Click, untars it to `click-2.0.1/` and builds it with appropriate C++ compiler flags.
  * `Makefile`: this isn't a shell script, but it copies the contents of the `elements/` folder into the `click-2.0.1/elements/local/` directory and then builds a modified version of Click.
  * `shell/join.sh client_name`: makes the client with the given name join the multicast group.
  * `shell/leave.sh client_name`: makes the client with the given name leave the multicast group.
  * `shell/set-client-robustness.sh client_name robustness`: sets the robustness variable of the client with the given name.
  * `shell/set-client-uri.sh client_name duration_in_dsec`: sets the unsolicited report interval of the client with the given name to the given duration in deciseconds.
  * `shell/set-router-lmqc.sh count`: sets the last member query count of the router to the given amount.
  * `shell/set-router-lmqi.sh duration_in_dsec`: sets the last member query interval of the router to the given duration in deciseconds.
  * `shell/set-router-qi.sh duration_in_dsec`: sets the query interval of the router to the given duration in deciseconds.
  * `shell/set-router-qri.sh duration_in_dsec`: sets the query response interval of the router to the given duration in deciseconds.
  * `shell/set-router-robustness.sh robustness`: sets the robustness variable of the router to the given value.
  * `shell/set-router-sqc.sh count`: sets the startup query count of the router to the given amount.
  * `shell/set-router-sqc.sh duration_in_dsec`: sets the startup query interval of the router to the given duration in deciseconds.

> **Note:** these scripts all assume that Click is running on port 10000, i.e., Click was started by running `./click-2.0.1/userlevel/click -p 10000 scripts/ipnetwork.click`.