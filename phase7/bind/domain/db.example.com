$TTL 600

@   IN  SOA domain-ns.example.com. admin.example.com. (
        1          ; serial
        3600       ; refresh
        900        ; retry
        604800     ; expire
        300        ; negative cache TTL
)

@           IN  NS  domain-ns.example.com.
domain-ns   IN  A   172.16.3.30

@           IN  A   172.16.1.20
www         IN  A   172.16.1.20
; This is a key-signing key, keyid 26984, for example.com.
; Created: 20261023154903 (Fri Oct 23 15:49:03 2026)
; Publish: 20261023154903 (Fri Oct 23 15:49:03 2026)
; Activate: 20261023154903 (Fri Oct 23 15:49:03 2026)
example.com. IN DNSKEY 257 3 8 AwEAAZQyIBD1vusC3bnxeQqpI48sbkx35B9zKU6zoQOqOA6iqtZJBBjJ gdHkhDE3BJP1LMX8+XSQkmlwxtKF7S/29356iXXsKiQ0D20rvNri64Bx aeaBIWi8K7qYyvl2zRzNKDsBZo7nY+Za0en4gEbngjQAJiH94XK7Eyq4 qTIjvJCTWEdQwrJnFks/MQMa9dZpdoLEgedxWDqef63UcdfSXqmetjX6 adBvwhXnHpm61m/NbHKKklwPuxhT9QWVd8ZE+qw64uRU7G/vcja7iB+E 1PW9HZiSqFJU4xQFLoFCVBwuY0iTwl2ALrQrZlyVOdIU+qJqt5V8ngeN fVFl1pHhIfE=
; This is a zone-signing key, keyid 5290, for example.com.
; Created: 20261023154903 (Fri Oct 23 15:49:03 2026)
; Publish: 20261023154903 (Fri Oct 23 15:49:03 2026)
; Activate: 20261023154903 (Fri Oct 23 15:49:03 2026)
example.com. IN DNSKEY 256 3 8 AwEAAbE5F0CLw/C+yfEIg2GoxE+67q+QSwi2Q5Ef4gxXwUQr3JCbOsNF DdVF8HvjiAPeDU5/xbjnLjL1/rzm1ORZOyFUe/Pr9F3j56gmPnxRkRsY p2gOse7a+9OSKCFbGtycfnN/Uroe7BCY2DsjyETji0m6M1GLu17FdVHE AmbY5rXp
