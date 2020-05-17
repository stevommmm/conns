# conns

`conns` provides a tcpdump like utility to capture unique IP hits based on an active pcap filter. Currently only TCP & UDP protocols are potentially counted.

Essentially a less awkward `tcpdump | awk | sort | uniq`.

```
Usage:
  conns [-r] [filter command]
```

`-r` enables name resolution of IPs on collection

`filter command` is currently required to be a single string


to-do:

* move to new dns resolution funcs
* concat all unparsed args into the pcap filter string
