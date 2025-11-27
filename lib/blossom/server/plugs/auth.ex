defmodule Blossom.Server.Plugs.Auth do
  @moduledoc """
  Authentication plug for parsing and validating Nostr authorization events.
  
  Parses the Authorization header and validates the event structure.
  Note: Signature verification will be added when nostr_ex is available.
  """

  @behaviour Plug

  import Plug.Conn
  alias Blossom.Protocol.AuthEvent

  require Logger

  def init(opts), do: opts

  def call(conn, _opts) do
    case get_req_header(conn, "authorization") do
      ["Nostr " <> encoded_event] ->
        parse_and_validate_auth(conn, encoded_event)
      
      [_other_auth] ->
        conn
        |> put_error("Invalid authorization scheme. Expected 'Nostr <base64_event>'")
        |> send_unauthorized()
        |> halt()
      
      [] ->
        # No authorization header - store as nil for optional auth endpoints
        assign(conn, :auth_event, nil)
      
      _multiple ->
        conn
        |> put_error("Multiple authorization headers not allowed")
        |> send_unauthorized()
        |> halt()
    end
  end

  defp parse_and_validate_auth(conn, encoded_event) do
    case AuthEvent.from_auth_header(encoded_event) do
      {:ok, auth_event} ->
        case AuthEvent.validate(auth_event) do
          :ok ->
            assign(conn, :auth_event, auth_event)
          
          {:error, reason} ->
            Logger.warning("Invalid authorization event: #{inspect(reason)}")
            conn
            |> put_error("Invalid authorization event: #{reason}")
            |> send_unauthorized()
            |> halt()
        end
      
      {:error, reason} ->
        Logger.warning("Failed to parse authorization event: #{inspect(reason)}")
        conn
        |> put_error("Failed to parse authorization event")
        |> send_unauthorized()
        |> halt()
    end
  end

  defp send_unauthorized(conn) do
    send_resp(conn, 401, "Unauthorized")
  end

  defp put_error(conn, message) do
    put_resp_header(conn, "x-reason", message)
  end
end