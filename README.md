# oni_dns
A simple DNS server with a whitelist that reads a 'white_list.txt' file at startup as the whitelist and a 'dns_cache.txt' file as the cache for DNS. If a DNS query matches an entry in the whitelist, the server returns the corresponding IP address directly. Otherwise, it forwards the query to an upstream DNS server for resolution and returns the result.
