A way to stop forwarding mode and quit
-------------------------------------

Entering forwarding mode from the client end should not prevent st to continue
reading stdin, just without forwarding to the pseudo terminal obviously. Then
it would still display the menu (possibly all the time).

An entry in that menu should then allow to return to digging mode, or exit.


Make it work not only for localhost
-----------------------------------

Similarly to ssh, we should be able to specify where to bind the local
listening socket to, and what host to connect to on the other end of the
tunnel.


Compression
-----------

Tunnel traffic may benefit from some compression.


Crypto
------

If the destination machine is safe then a pre-shared secret could be used and
given on the command line of the server end. Otherwise there is again the
possibility to tunnel to ssh and then reconnect.


Stats
-----

While the port forwarding is going on it would be nice to use the now useless
terminal to display some stats about number of connections, volume...


Configuration
-------------

Buffer size should be configurable from the command line.
