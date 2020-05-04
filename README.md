Uutunnel - port forwarding like it's 1980
=========================================

Uutunnel is a tool that forward a local port to a remote server using only the
terminal. Meaning: no need for the server to have a reachable network interface
at all, as long as you can have a shell, you can connect!

Wait! How would I get a shell if the server has no network device?

It could be that the server you are trying to reach is jailed/containerized in
such a way that your service cannot bind any network interface visible from the
outside, yet you can execute a shell to that VM (think docker container with
no published ports).

Or it could be that to access your server you need to hop from one location to
another, each requiring a manual (interactive) authentication process.

In those cases, uutunnel can help. Here is what it does:

```shell
# Run uutunnel locally, specifying that it's the tunnel _in_put
# and that you want to forward port 8080:
laptop $ uutunnel in 8080

# uutunnel will create a pseudo-terminal, and fork /bin/sh in it:
$ echo 'hello?'
hello!

# Then you can start digging toward your remote service:
$ ssh john.doe@remote-server1.net
server1 $ ssh john.doe@remote-server2.net
server2 $ docker exec -ti container /bin/bash
container # echo 'Haha there I am eventually!'
Haha there you are eventually!

# Now uutunnel is almost ready to accept local connections and
# forward the traffic (uuencoded) to the terminal up to here.
# But we need some program running here to read them from stdin
# and connect to localhost for the final leg of the journey.
# To operate the exhaust of the tunnel you need to run uutunnel
# in _out_put mode. But...
$ uutunnel
uutunnel: command not found

# Here is the trick: uutunnel can send itself (uuencoded) if you
# press the magic key sequence. But wait, first disable terminal echo:
$ stty -echo; uudecode; stty echo
# uudecode is waiting; now press the magic sequence: !!>
Done.
$ ls
uutunnel

# Magic! Now run uutunnel, specifying that it is now the _out_put,
# and which port from localhost to connect to:
$ ./uutunnel out 80
Peered! Forwarding port...

# Done! You can now connect from your laptop into "localhost:8080" to
# reach this server (as if you had done ssh -L 8080:localhost:80).
```
