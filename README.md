pdns-receiver
=============

A tcp server that listens on port 4242 for PowerDNS recursor streams, and collect RPZ statistics about the incoming stream.

Point your pdns-recursor to it with this recursor.conf setting:

```conf
lua-config-file=/etc/powerdns/recursor.lua
```

And with this lua configuration in recursor.lua:

```lua
protobufServer("127.0.0.1:4242" , 2, 100, 1, 16, 32)
rpzMaster("1.2.3.4", "drop.rpz.something", {refresh=30, policyName="dontrouteorpeer", defpol=Policy.Custom, defconfent="dropinfo.example.com"})
rpzMaster("1.2.3.4", "dbl.rpz.something", {refresh=30, policyName="dbl", defpol=Policy.Custom, defconfent="dblinfo.example.com"})
```

This config enables:

* A protobuf stream that anonymizes clients (v4 to /16, v6 to /32)
* An RPZ config that rewrites answers that contain IP's from the DROP list
* An RPZ config that answers questions to blacklisted domains (malware, mostly)


