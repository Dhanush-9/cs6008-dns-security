$TTL 600

@   IN  SOA tld-ns.com. admin.com. (
        1          ; serial
        3600       ; refresh
        900        ; retry
        604800     ; expire
        300        ; negative cache TTL
)

@                       IN  NS  tld-ns.com.
tld-ns                  IN  A   172.16.3.20

example.com.            IN  NS  domain-ns.example.com.
domain-ns.example.com.  IN  A   172.16.3.30
example.com.		IN DS 26984 8 2 CD0119573E419C915019DF60590F80A8D5F647B486A9C36F90310923 C4587803
; This is a key-signing key, keyid 39362, for com.
; Created: 20261023154903 (Fri Oct 23 15:49:03 2026)
; Publish: 20261023154903 (Fri Oct 23 15:49:03 2026)
; Activate: 20261023154903 (Fri Oct 23 15:49:03 2026)
com. IN DNSKEY 257 3 8 AwEAAdWvwYVd0aiKjHUT0KrD7lNELsyskM1J7ler1L084LnGSDlp8RKE oNiDzWXAmKDSxCj2gbRoxtftb7U7H89a/h6yI4rWj9saf1LE0PLdPvrj O2BC9LimZ3UvbD9dVb0NrazkZT/LuOwMno298VuLgekLGk8kPjKji0/Z 2LfiUXr3a2xRlWGIytZ+Z0gOTENlUSjCqs9mrCAL2gMbOHpK7bMJV09f DAe/I6GEdiZ/h1Hj5DVGQWvc2gvGbZmzNGHolBwNNboMubShk6zCxkUB 6Yaya+ulLhF0gbYe+c1SZq7g1fdR76XXdad+7ZFIEJneTOgCq7huxvHk XXN0+ZdrN10=
; This is a zone-signing key, keyid 64431, for com.
; Created: 20261023154903 (Fri Oct 23 15:49:03 2026)
; Publish: 20261023154903 (Fri Oct 23 15:49:03 2026)
; Activate: 20261023154903 (Fri Oct 23 15:49:03 2026)
com. IN DNSKEY 256 3 8 AwEAAasjYrRs8zY1IUfa8MmKCKAc6StiYkL5Ppxvu9iPS3xI5xkuY6k8 1H35jVpV+W18LHiebwBV7IijJqDa97RcuUaeMQ19DKA81S4pjFxYOzqg 4I419kCnkvo24o75jw8H2W+ur1Rex2BXARhW+LthFRJylYsUwwkEH9LD 8EGsxRbF
