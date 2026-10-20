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
example.com.		IN DS 55685 8 2 FAD76A23A98AD67941186C69E965A1BD5383F6837FF41B08E5A5DB00 8D1DF469
; This is a key-signing key, keyid 16904, for com.
; Created: 20261019180826 (Mon Oct 19 18:08:26 2026)
; Publish: 20261019180826 (Mon Oct 19 18:08:26 2026)
; Activate: 20261019180826 (Mon Oct 19 18:08:26 2026)
com. IN DNSKEY 257 3 8 AwEAAdXkqnpjxofojRpMREaOfLXIuzh8t3zjXaIxOYMJ/arXZsFY2MIn HwEhsmeHtFGtRlZSaA5RXAwB18yUGAoQK0VQiTF5Vhk2fjGM2YvocEaE xQjgNmnaezjCVT/Gr8j2HIFFXtGQDn3CudXbELpVgj9m1l7g1zoa22sA vW8YHhJikz7R9ZGqPGRn3bBLd9tmV6YkdaQiGsju7wTeOIuYZv+6wKrh RC7uODfyayvBUKC0YiioFAgkwSFzH3uI1mIccwDacYepiqAJ+QiahZ68 +V+X+BSoZJ4BuneypEd9EaCYAcUeOSRBc6r8GSvHFXJ6oJ+CgO7rGFL4 EB8PiyeC68c=
; This is a zone-signing key, keyid 22801, for com.
; Created: 20261019180826 (Mon Oct 19 18:08:26 2026)
; Publish: 20261019180826 (Mon Oct 19 18:08:26 2026)
; Activate: 20261019180826 (Mon Oct 19 18:08:26 2026)
com. IN DNSKEY 256 3 8 AwEAAex9efs3r9j9sQVuPkAylKVjWAz0EFuQVfrrPFEaf5Ih8dqbQifc 3UUCwaL16M7jusvwAOLZAnsCKH5SPiTXeAMcPD3mzA0djwjpUzFKYaXg bWaukx09WN3AZOn/FZC5jEuRhJe+EMBsmJ73F4OsrxcHs7tPK/xbiRFb cfjofFHP
