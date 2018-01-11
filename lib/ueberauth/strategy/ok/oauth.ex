defmodule Ueberauth.Strategy.MailRu.OAuth do
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "http://www.appsmail.ru/platform/api",
    authorize_url: "https://connect.mail.ru/oauth/authorize",
    token_url: "https://connect.mail.ru/oauth/token"
  ]

  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.MailRu.OAuth)
    opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)
    OAuth2.Client.new(opts)
  end

  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end
  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token!(params \\ [], opts \\ []) do
    client =
      opts
      |> client
      |> OAuth2.Client.get_token!(params)
    client.token
  end
  def get_token(client, params, headers) do
    client
    |> put_param("client_secret", client.client_secret)
    |> put_param("grant_type", "authorization_code")
    |> put_header("Accept", "application/json")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end

  def get(conn, token) do
    OAuth2.Client.get(client, "http://www.appsmail.ru/platform/api?#{user_query(conn, token)}")
  end

  defp user_query(conn, token) do
    access_token = Map.fetch!(token, :access_token)
    config = Application.get_env(:ueberauth, Ueberauth.Strategy.MailRu.OAuth)
    %{
      app_id: Keyword.get(config, :client_id),
      format: "json",
      method: "users.getInfo",
      secure: 1,
      session_key: access_token
    } |> sig(Keyword.get(config, :client_secret)) |> URI.encode_query
  end

  defp sig(params, client_secret) do
    params_string = params |> URI.encode_query |> String.replace("&", "")
    Map.put_new(params, :sig, md5(params_string <> client_secret))
  end

  defp md5(str), do: :crypto.hash(:md5, str) |> Base.encode16(case: :lower)
end
