# conns

`conns` provides a tcpdump like utility to capture unique IP hits based on an active pcap filter. Currently only TCP & UDP protocols are potentially counted.

Essentially a less awkward `tcpdump | awk | sort | uniq`.

```
Usage:
  conns [filter command]
```

to-do:

* move to new dns resolution funcs
