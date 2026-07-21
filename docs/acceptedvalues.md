## `ngx_http_jwt` module docs `v1.0.0`

## Accepted Values

- All JWT must be signed.
- Claim names must be `.*{0, 2048}`.
- Claim values must be `.*{0, 2048}` after stringified (including quotes, braces, etc.).
- Custom header names must be `[0-9a-zA-Z-_]{1, 2047}`.

> [!CAUTION]
> Custom header names that collide with standard / well known headers are supported but strongly discouraged (might have unexpected side effects).
