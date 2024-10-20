# Nydus

Receive and decode [PROXY
protocol](https://github.com/haproxy/haproxy/blob/master/doc/proxy-protocol.txt) headers off of
`:gen_tcp` sockets.

Nydus is easy to use so long as you can access sockets at the right time, however, friction may be
felt when using frameworks that constrain access to connection information.
