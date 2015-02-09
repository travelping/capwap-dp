capwap-dp
=========

CAPWAP Datapath element

Version 1.0.6 - xx Feb 2015
---------------------------

* add function to retrieve station values
* account traffic to a WTP initiated by the control channel

Version 1.0.5 - 02 Feb 2015
---------------------------

* replace legacy erl_interface with ei

Version 1.0.4 - 21 Jan 2015
---------------------------

* fix another station releated memleak found by valgrind

Version 1.0.3 - 21 Jan 2015
---------------------------

* fix memleaks found by valgrind

Version 1.0.2 - 21 Jan 2015
---------------------------

* fix Station release on WTP removal
* add list_stations status functions
* fix uninitialize bits in sockaddr
* fix detection of libev
* add profiling switch to configure, this compiles the code with -O0 which eases debugging

Version 1.0.1 - 19 Jan 2015
---------------------------

* fix del_wtp and del_station functions

Version 1.0.0 - 14 Jan 2015
---------------------------

* initial release

