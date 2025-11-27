defmodule Blossom.Server.Plugs.BlobHandler do
  @moduledoc """
  Main blob handling plug for Blossom server endpoints.
  
  Implements BUD-01 endpoints:
  - GET /:sha256[.:ext] - Get blob
  - HEAD /:sha256[.:ext] - Check blob existence
  - PUT /upload - Upload blob
  - GET /list/:pubkey - List blobs 
  - DELETE /:sha256 - Delete blob
  """

  @behaviour Plug

  import Plug.Conn
  alias Blossom.Protocol.{Blob, BlobDescriptor}

  require Logger

  def init(opts) do
    storage_backend = Keyword.get(opts, :storage_backend, Blossom.Storage.ETS)
    base_url = Keyword.get(opts, :base_url, "http://localhost:4000")
    
    # Initialize storage backend
    storage_backend.init()
    
    %{
      storage_backend: storage_backend,
      base_url: base_url
    }
  end

  def call(conn, opts) do
    conn = assign(conn, :storage_backend, opts.storage_backend)
    conn = assign(conn, :base_url, opts.base_url)
    
    route(conn, conn.method, conn.path_info)
  end

  # GET /:sha256[.:ext] - Get blob
  defp route(conn, "GET", [sha256_with_ext]) do
    sha256 = extract_sha256(sha256_with_ext)
    
    if valid_sha256?(sha256) do
      get_blob(conn, sha256)
    else
      send_error(conn, 400, "Invalid SHA256 hash format")
    end
  end

  # HEAD /:sha256[.:ext] - Check blob existence  
  defp route(conn, "HEAD", [sha256_with_ext]) do
    sha256 = extract_sha256(sha256_with_ext)
    
    if valid_sha256?(sha256) do
      has_blob(conn, sha256)
    else
      send_error(conn, 400, "Invalid SHA256 hash format")
    end
  end

  # PUT /upload - Upload blob
  defp route(conn, "PUT", ["upload"]) do
    upload_blob(conn)
  end

  # GET /list/:pubkey - List blobs
  defp route(conn, "GET", ["list", pubkey]) do
    list_blobs(conn, pubkey)
  end

  # DELETE /:sha256 - Delete blob
  defp route(conn, "DELETE", [sha256]) do
    if valid_sha256?(sha256) do
      delete_blob(conn, sha256)
    else
      send_error(conn, 400, "Invalid SHA256 hash format")
    end
  end

  # Catch-all for unmatched routes
  defp route(conn, _method, _path) do
    send_error(conn, 404, "Endpoint not found")
  end

  # BUD-01 GET /:sha256 implementation
  defp get_blob(conn, sha256) do
    storage_backend = conn.assigns.storage_backend
    
    case storage_backend.get_blob(sha256) do
      {:ok, blob} ->
        conn
        |> put_resp_content_type(blob.content_type)
        |> put_resp_header("content-length", to_string(blob.content_length))
        |> put_resp_header("accept-ranges", "bytes")
        |> send_resp(200, blob.content)
      
      {:error, :not_found} ->
        send_error(conn, 404, "Blob not found")
      
      {:error, reason} ->
        Logger.error("Failed to retrieve blob #{sha256}: #{inspect(reason)}")
        send_error(conn, 500, "Internal server error")
    end
  end

  # BUD-01 HEAD /:sha256 implementation
  defp has_blob(conn, sha256) do
    storage_backend = conn.assigns.storage_backend
    
    case storage_backend.get_blob(sha256) do
      {:ok, blob} ->
        conn
        |> put_resp_content_type(blob.content_type)
        |> put_resp_header("content-length", to_string(blob.content_length))
        |> put_resp_header("accept-ranges", "bytes")
        |> send_resp(200, "")
      
      {:error, :not_found} ->
        send_error(conn, 404, "Blob not found")
      
      {:error, reason} ->
        Logger.error("Failed to check blob #{sha256}: #{inspect(reason)}")
        send_error(conn, 500, "Internal server error")
    end
  end

  # BUD-02 PUT /upload implementation
  defp upload_blob(conn) do
    storage_backend = conn.assigns.storage_backend
    base_url = conn.assigns.base_url
    
    # Read request body
    case read_body(conn, length: 100_000_000) do  # 100MB limit
      {:ok, content, conn} ->
        content_type = get_content_type(conn)
        blob = Blob.new(content, content_type)
        
        case storage_backend.put_blob(blob, base_url) do
          {:ok, descriptor} ->
            json_response(conn, 200, BlobDescriptor.to_json(descriptor))
          
          {:error, reason} ->
            Logger.error("Failed to store blob: #{inspect(reason)}")
            send_error(conn, 500, "Failed to store blob")
        end
      
      {:error, :timeout} ->
        send_error(conn, 408, "Request timeout")
      
      {:error, reason} ->
        Logger.error("Failed to read request body: #{inspect(reason)}")
        send_error(conn, 400, "Failed to read request body")
    end
  end

  # BUD-02 GET /list/:pubkey implementation
  defp list_blobs(conn, pubkey) do
    storage_backend = conn.assigns.storage_backend
    
    # Parse query parameters
    query_params = fetch_query_params(conn).params
    since = parse_timestamp(query_params["since"])
    until = parse_timestamp(query_params["until"])
    
    opts = [since: since, until: until] |> Enum.reject(fn {_, v} -> is_nil(v) end)
    
    case storage_backend.list_blobs(pubkey, opts) do
      {:ok, descriptors} ->
        json_list = Enum.map(descriptors, &BlobDescriptor.to_json/1)
        json_response(conn, 200, json_list)
      
      {:error, reason} ->
        Logger.error("Failed to list blobs for #{pubkey}: #{inspect(reason)}")
        send_error(conn, 500, "Failed to list blobs")
    end
  end

  # BUD-02 DELETE /:sha256 implementation
  defp delete_blob(conn, sha256) do
    storage_backend = conn.assigns.storage_backend
    
    # TODO: Add proper authorization checking when nostr_ex is available
    # For now, accept any delete request
    
    case storage_backend.delete_blob(sha256) do
      :ok ->
        send_resp(conn, 200, "")
      
      {:error, :not_found} ->
        send_error(conn, 404, "Blob not found")
      
      {:error, reason} ->
        Logger.error("Failed to delete blob #{sha256}: #{inspect(reason)}")
        send_error(conn, 500, "Failed to delete blob")
    end
  end

  # Helper functions

  defp extract_sha256(sha256_with_ext) do
    case String.split(sha256_with_ext, ".", parts: 2) do
      [sha256] -> sha256
      [sha256, _ext] -> sha256
    end
  end

  defp valid_sha256?(sha256) do
    String.match?(sha256, ~r/^[a-fA-F0-9]{64}$/)
  end

  defp get_content_type(conn) do
    case get_req_header(conn, "content-type") do
      [content_type] -> content_type
      [] -> "application/octet-stream"
    end
  end

  defp parse_timestamp(nil), do: nil
  defp parse_timestamp(str) when is_binary(str) do
    case Integer.parse(str) do
      {timestamp, ""} -> timestamp
      _ -> nil
    end
  end

  defp send_error(conn, status, message) do
    conn
    |> put_resp_header("x-reason", message)
    |> send_resp(status, message)
  end

  defp json_response(conn, status, data) do
    json = Jason.encode!(data)
    
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, json)
  end
end