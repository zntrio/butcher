# go-butcher

Butcher for progressive hashing password

Status: POC (aka Not Production Ready)

Algorithms supported :

  * Argon2i
  * Scrypt+Blake2b-512
  * PBKDF2+Blake2b-512 (default)
  * PBKDF2+SHA512
  * PBKDF2+Keccak-512

## Output samples

```sh
"argon2i$v=19$m=4096,t=3,p=1$ogzBAhKqTQzqKb0RrcH/oXpJWAAdUYkvxi56helLZZwDkPPzJzrWlkjPLDvl7KOQ4xwfJUl6lThE/mCBAvdJKg$5FG9SXMmRtr6WmucA0FvTaUrlcTytPr9YcRdzUFgS5M"
"pbkdf2+blake2b-512$$i=50000,l=64$BVs5yEUcf16+aUuQ0OceX2vnGyr6gJ+V9GfBM5abreDoTNvjdbjjKvE+ITrUJW+ePER6Nd6Xx+gkK0f4eMRUtQ$tAmYg+4mHEcs1jY1x/QduqKiILbO6oT1rxpzjMCqVO1xSmrnQTc1ApzT0XrX8nBfzYwE8amKKWz6+qaRNjw70A"
"pbkdf2+sha3-512$$i=50000,l=64$ozRBsjR9SAcM1wlOUJlgXCLB8c1SK1JMo1geDhPHzQrgZ7QS4SU99IASOcqCgMZQi4WRxBIcMT0/XPNnDlh+AQ$2Rdn9csLROjPwCDdV2gKLvdSNdYu9ZuDuTKztMETPsMnblz+UEUO3Se+StxwkH604OgyOsg7AO3WOIlrP9S1NA"
"pbkdf2+sha512$$i=50000,l=64$AgwnOOpIsc+35GVqoE8i32KeAyRK1c4GMLLMbyoOc6jMPLgFL14ZWujTYG0MxxIUN9svqc67ve/+qkCIgpxBGA$99WISIpNRSABtfMolDcSe27PqSfzBSuAEyvgEzcx2iVOQFGHfNMUNMp4b6l9Bi4dBkwXSVtg02sI+gFvvOViCw"
```
