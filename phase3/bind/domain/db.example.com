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
; This is a key-signing key, keyid 55685, for example.com.
; Created: 20261019180826 (Mon Oct 19 18:08:26 2026)
; Publish: 20261019180826 (Mon Oct 19 18:08:26 2026)
; Activate: 20261019180826 (Mon Oct 19 18:08:26 2026)
example.com. IN DNSKEY 257 3 8 AwEAAYvsy2LVAjafUyHSAcGBBcVqYUP5JH23QLdMv/519mGlMza/xlJ0 VdrSjMApPayXT1O/p/8StDqIz8X1LAGP70QB/EoDBk1cP4R0eCYCFQLx vHNSJwt80BxAYx7NK4AG9sPo3xufdph3TiuQDUEXqmRO2YTfVLH6+KXO PwmJ2cXIAVxeYm1mqKa2up9j6TVvPaZBMuZ8HbGZhqRE7r3lj34oiEU3 zh9X7xa76MSgvopAfpb/RIUk7jGg9b68YEZqUbp/UNzKNK9S6RScfkDu t+rNzwX1ZocnKud5kbhAuEZm4sqYEyExCfcGcHseglUqzK0ENTHR4xqM v/dMjlqK8lE=
; This is a zone-signing key, keyid 20739, for example.com.
; Created: 20261019180826 (Mon Oct 19 18:08:26 2026)
; Publish: 20261019180826 (Mon Oct 19 18:08:26 2026)
; Activate: 20261019180826 (Mon Oct 19 18:08:26 2026)
example.com. IN DNSKEY 256 3 8 AwEAAa7nc+mHA5e+qbWJRduB9bHbXiGGINanWWtKkhQIuaGBf8E/TWRQ hJboVOTqYGK/VrXBK3mT9Bi24xUndHMfL4h01hHUckjUL3oSog3r54V0 4UK4t6pryee2nwtkL186V2fThd/dfY8nJ44kBxL06sHPRBowUGG31M5y Wh5+LfbN
