defmodule Blossom.Server.Plugs.Pipeline do
  @moduledoc """
  Main plug pipeline for Blossom server.
  
  Combines CORS, authentication, and blob handling plugs into a single pipeline
  that can be easily mounted in Phoenix applications or used with Bandit.
  """

  @behaviour Plug

  alias Blossom.Server.Plugs.{CORS, Auth, BlobHandler}

  @doc """
  Plug pipeline configuration.
  
  ## Options
  
    * `:storage_backend` - Storage backend module (default: Blossom.Storage.ETS)
    * `:base_url` - Base URL for blob descriptors (default: "http://localhost:4000")
    * `:require_auth` - Whether to require authentication for all endpoints (default: false)
  """
  def init(opts \\ []) do
    storage_backend = Keyword.get(opts, :storage_backend, Blossom.Storage.ETS)
    base_url = Keyword.get(opts, :base_url, "http://localhost:4000")
    require_auth = Keyword.get(opts, :require_auth, false)

    blob_handler_opts = BlobHandler.init(
      storage_backend: storage_backend,
      base_url: base_url
    )

    %{
      cors_opts: CORS.init([]),
      auth_opts: Auth.init([]),
      blob_handler_opts: blob_handler_opts,
      require_auth: require_auth
    }
  end

  def call(conn, opts) do
    conn
    |> CORS.call(opts.cors_opts)
    |> case do
      %{halted: true} = conn -> conn
      conn -> 
        conn
        |> Auth.call(opts.auth_opts)
        |> case do
          %{halted: true} = conn -> conn
          conn -> BlobHandler.call(conn, opts.blob_handler_opts)
        end
    end
  end
end