# go-butcher

Butcher for progressive hashing password

Status: Prod ready

Algorithms supported :

  * Argon2id
  * Argon2i
  * Scrypt+Blake2b-512 (default)
  * PBKDF2+SHA512

## Output samples

```sh
'argon2id$v=19$m=131072,t=40,p=4$2n9BPk6oCzuWZBg8ltSLTxGSyvkPTW0gVI10Fn6TBYE$xK0LQ6cGdDZD7stQUzl+NjKfk6caYiZoFwL7Dot/AUEESRYkKzuLJFT/j/tSIhE6Gzus1IOo/RgijvcPWE9G8A'
'argon2i$v=19$m=131072,t=40,p=4$IlB2zl1fUTzZizr8FUgDubbl5yF0dB/zC2RchXovOXQ$mNcv8RmwXzIJmgxveTEMaGiAZj5DGfn/HDr+BmbPW6dbKDNC49nm18wTfOl73Yte+v4/nC95QM8bB2800lwC3Q'
'scrypt+blake2b-512$$n=17,r=8,p=1$GS8+Iyg3Qd7SWn+b2fuabHIHRScvxHo5eAAhtmX358Q$GH+XENsAQX6Pl4ga9zR1L31zcKZ4utOCierkBA1XTRPSUaPDisR6xGBYSqoqW8JADVtzOQb0u5J8ynlYLpsChg'
'pbkdf2+hmac-sha512$$i=100000,l=64$qPzwCau0nzCGGw+T+o0Y+D6CVCCkwnZ0LT7S7xc87y4$tOfeS2h+Xw63P/61gBKpPyeLgQ+1aQZTkYb12DbT4FB/zIppE7my+NVlm4L2OwHaUj+oq3tTmbmHK1+TXqsKGg'
```

## Advices

  * Try to use client side hash function before sending credentials to the server (Blake2b-512 / SHA3-512);
  * use a 32 byte or 64 byte salt (actual size dependent on protection function);
  * You should encrypt these results in your database to add hash privacy;
  * Store pepper and encryption key in a HSM or Software Vault;
  * For Paranoid (like me) => Implement perfect secrecy using NaCL box on top of HTTPS;