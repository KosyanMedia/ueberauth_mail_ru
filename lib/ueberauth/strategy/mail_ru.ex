defmodule Ueberauth.Strategy.MailRu do
  @moduledoc """
  mail.ru Strategy for Überauth.
  """

  use Ueberauth.Strategy, default_scope: "", uid_field: :uid

  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Auth.Info

  def handle_request!(conn) do
    scopes = conn.params["scope"] || option(conn, :default_scope)
    opts =
      [scope: scopes]
      |> Keyword.put(:response_type, "code")
      |> Keyword.put(:redirect_uri, callback_url(conn))
    redirect!(conn, Ueberauth.Strategy.MailRu.OAuth.authorize_url!(opts))
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    opts = [redirect_uri: callback_url(conn)]
    token = Ueberauth.Strategy.MailRu.OAuth.get_token!([code: code], opts)

    if token.access_token == nil do
      set_errors!(conn, [error(token.other_params["error"], token.other_params["error_description"])])
    else
      fetch_user(conn, token)
    end
  end
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  def info(conn) do
    user = conn.private.mail_ru_user
    city = if user["location"]["city"]["name"], do: user["location"]["city"]["name"] <> ", "
    %Info{
      email: user["email"],
      first_name: user["first_name"],
      image: user["pic_big"] || user["pic"],
      last_name: user["last_name"],
      name: user["name"],
      location: "#{city}#{user["location"]["country"]["name"]}",
      urls: %{
        mail_ru: user["link"]
      }
    }
  end

  def uid(conn) do
    uid_field =
      conn
      |> option(:uid_field)
      |> to_string
    conn.private.mail_ru_user[uid_field]
  end

  def extra(conn) do
    %Extra{
      raw_info: %{
        token: conn.private.mail_ru_token,
        user: conn.private.mail_ru_user
      }
    }
  end

  def credentials(conn) do
    token = conn.private.mail_ru_token
    %Credentials{
      expires: !!token.expires_at,
      expires_at: token.expires_at,
      token: token.access_token,
      refresh_token: token.refresh_token,
      token_type: token.token_type
    }
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :mail_ru_token, token)
    case Ueberauth.Strategy.MailRu.OAuth.get(conn, token) do
      {:ok, %OAuth2.Response{status_code: 401, body: _body}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:ok, %OAuth2.Response{status_code: status_code, body: user}} when status_code in 200..399 ->
        put_private(conn, :mail_ru_user, List.first(user))
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end
end
