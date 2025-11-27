defmodule Blossom.Server.Plugs.CORS do
  @moduledoc """
  CORS plug for Blossom servers as required by BUD-01.
  
  Sets the necessary CORS headers to ensure compatibility with applications
  hosted on other domains.
  """
  
  @behaviour Plug

  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    conn
    |> put_resp_header("access-control-allow-origin", "*")
    |> put_resp_header("access-control-allow-headers", "authorization, *")
    |> put_resp_header("access-control-allow-methods", "get, head, put, delete, options")
    |> put_resp_header("access-control-max-age", "86400")
    |> handle_preflight()
  end

  # Handle OPTIONS preflight requests
  defp handle_preflight(%{method: "OPTIONS"} = conn) do
    conn
    |> send_resp(200, "")
    |> halt()
  end

  defp handle_preflight(conn), do: conn
end