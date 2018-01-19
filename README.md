# mail.ru OAuth2 Strategy for Überauth.

### Note
Mail.ru responding with incorrect `content-type` header, so you should handle unregistered content-type for JSON response encoding in [OAuth2 Library](https://github.com/scrogson/oauth2). Add serializer to your config file like:
```elixir
config :oauth2, serializers: %{
  "text/javascript" => Poison,
  "application/json" => Poison
}
```
