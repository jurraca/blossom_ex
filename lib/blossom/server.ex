defmodule Blossom.Server do
  @moduledoc """
  Optional standalone Blossom server using Bandit.
  
  This module provides a convenient way to start a standalone Blossom server.
  It requires the optional `:bandit` dependency to be included.
  """

  alias Blossom.Server.Plugs.Pipeline

  @doc """
  Starts a standalone Blossom server.
  
  ## Options
  
    * `:port` - Port to listen on (default: 4000)
    * `:storage_backend` - Storage backend to use (default: Blossom.Storage.ETS)
    * `:storage_path` - Path for file storage (only used with FileSystem backend)
    * `:base_url` - Base URL for blob descriptors (auto-detected if not provided)
    * `:require_auth` - Whether to require authentication (default: false)
  
  ## Examples
  
      # Start with default settings
      {:ok, pid} = Blossom.Server.start_link()
      
      # Start with custom port and file storage
      {:ok, pid} = Blossom.Server.start_link(
        port: 8080,
        storage_backend: Blossom.Storage.FileSystem,
        storage_path: "/var/lib/blossom"
      )
  """
  @spec start_link(keyword()) :: {:ok, pid()} | {:error, term()}
  def start_link(opts \\ []) do
    if Code.ensure_loaded?(Bandit) do
      do_start_link(opts)
    else
      {:error, :bandit_not_available}
    end
  end

  @doc """
  Child spec for use in supervision trees.
  """
  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 5000
    }
  end

  # Private implementation

  defp do_start_link(opts) do
    port = Keyword.get(opts, :port, 4000)
    storage_backend = Keyword.get(opts, :storage_backend, Blossom.Storage.ETS)
    storage_path = Keyword.get(opts, :storage_path)
    base_url = Keyword.get(opts, :base_url, build_base_url(port))
    require_auth = Keyword.get(opts, :require_auth, false)

    # Initialize storage backend
    storage_opts = if storage_path, do: [storage_path: storage_path], else: []
    case storage_backend.init(storage_opts) do
      :ok -> :ok
      {:error, reason} -> 
        raise "Failed to initialize storage backend: #{inspect(reason)}"
    end

    # Configure the pipeline
    pipeline_opts = [
      storage_backend: storage_backend,
      base_url: base_url,
      require_auth: require_auth
    ]

    # Start Bandit server
    bandit_opts = [
      port: port,
      plug: {Pipeline, pipeline_opts}
    ]

    case Bandit.start_link(bandit_opts) do
      {:ok, pid} ->
        require Logger
        Logger.info("Blossom server started on port #{port}")
        Logger.info("Base URL: #{base_url}")
        Logger.info("Storage backend: #{inspect(storage_backend)}")
        {:ok, pid}
      
      error ->
        error
    end
  end

  defp build_base_url(port) do
    "http://localhost:#{port}"
  end
end