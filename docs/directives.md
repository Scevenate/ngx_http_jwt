# `ngx_http_jwt` module docs `v1.0.0`

# Directives

Similar to most nginx http directives, all directives introduced in the JWT module can be placed in either `http`, `server` or `location` context blocks.

Directives at higher levels are applied to all their locations; The behaviour of multiple directive presence is directive-specific.

## `jwt (off | bearer | header <custom_header_name> | cookie <key> | query <key>)`

Enables / explicitly disables the JWT module on the location. It also sets where the JWT is fetched from request.'

- `off`: Module is turned off. Default value.
- `bearer`: JWT is fetched from http bearer authorization. (`Authorization: Bearer ey...` header)
- `header <custom_header_name>`: JWT is fetched from a custom header by name.
- `cookie <key>`: JWT is fetched from a cookie by key.
- `query <key>`: JWT is fetched from a query parameter by key.

The most specific directive overwrites this setting.

## `jwt_load_jwks (string <string> | file <path>)`

Load a JWKS to a location. One location may load multiple JWKSs. Local JWKSs are cached per cycle by path.

## `jwt_validate <claim_name> (== <json_value> | in <json_array_value> | nbf [<leeway>] | exp [<leeway>])`

Validates the value of a claim. One location may validate multiple claims.

- `==`: The claim value must equal to the given value.
- `in`: The claim value must be equal to some value in the array.
- `nbf`: The claim value must be a JSON number, and must be smaller than the current runtime timestamp. Leeway must be a positive JSON number value; Default is `0`.
- `exp`: The claim value must be a JSON number, and must be bigger than the current runtime timestamp. Leeway must be a positive JSON number value; Default is `0`.

> [!IMPORTANT]
> The JSON values are parsed after nginx configuration parsing. This means the value is parsed twice; You should quote the strings twice, like `'"This is a string"'`, and `'null'` is JSON null value without quote.
> The recommended practice is to always quote JSON value with single quotes, which is allowed for nginx configuration quoting but not JSON quoting.

## `jwt_extract <claim_name> <custom_header_name> [optional]`

Extract the value of a claim to a new header value (base64 encoded JSON value), when proxing request. One location may extract multiple claims.

The custom header is always stripped away before extraction, if the client attempts to forge an extracted header. Absence, or invalid value of claim is reckoned as validation failure if the extraction is not optional.

## `jwt_error_code <code>`

Specify the HTTP response code for JWT authorization failure. The default value is `403`.

> [!NOTE]
> The module returns `500` on error. This response code is only applied to validation failures.
