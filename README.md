# go-butcher

Butcher for progressive hashing password

Status: Prod ready

Follow compliance from [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) requirements.

Algorithms supported :

  * Argon2id (default)
  * Scrypt 
  * PBKDF2+SHA512

## Output samples

```sh
'hAETWCB5IAJc8618VI9POngh6g0+rkEbUj/7pxZaAKuxPoRfilhA5+q1E+wifRoxLpEX7acA48KMmD/7OPJb5cTjxGP91Hv9z3vEBNOb095WPBo5yLn1w9mPnkfgKSv6MWKJRG0mGg'
'hAMBWCBD/40V1xzT/Kt0/40y0aeg60eHOyJFROiHuWkMvBIehlhA5U1h9I9fMSASOAcz4JpEQHEhwJGUlg8WpvqRnSG5gjruaa7LvNa7bMEHi1Qk5aVfpsisJBMlfxO5UaoLe1BC+A'
'hAIBWCBosL5P+aF/j2PmrIcE8W1Gxq+I2tMic0ON4xz1ZJkgr1hAUhaZ/2tI02iwD1H2DqTafepgdYfCHauWOzwkgTQsIcwvTTs1M8puQ5+UXl2cUA9f10EtjzM7vwaAHWU71Rrwhw'
```

## Advices

  * Try to use client side hash function before sending credentials to the server (Blake2b-512 / SHA3-512);
  * use a 32 byte or 64 byte salt (actual size dependent on protection function);
  * You should encrypt these results in your database to add hash privacy;
  * Store pepper and encryption key in a HSM or Software Vault;
  * For Paranoid (like me) => Implement perfect secrecy using NaCL box on top of HTTPS;