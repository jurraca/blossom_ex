defmodule Blossom.Client do
  @moduledoc """
  HTTP client for interacting with Blossom servers.
  
  Uses Req for HTTP operations and provides a simple API for Blossom protocol operations.
  Note: Cryptographic signing functionality will be added when nostr_ex is available.
  """

  alias Blossom.Protocol.{Blob, BlobDescriptor, AuthEvent}

  require Logger

  @doc """
  Gets a blob from a Blossom server by its SHA256 hash.
  
  ## Options
  
    * `:auth` - Authorization event for authenticated requests
    * `:timeout` - Request timeout in milliseconds (default: 30_000)
    * `:file_extension` - Optional file extension to append to URL
  
  ## Examples
  
      {:ok, blob} = Blossom.Client.get_blob("https://blossom.example.com", "abc123...")
      
      # With file extension
      {:ok, blob} = Blossom.Client.get_blob(
        "https://blossom.example.com", 
        "abc123...", 
        file_extension: ".pdf"
      )
  """
  @spec get_blob(String.t(), binary(), keyword()) :: {:ok, Blob.t()} | {:error, term()}
  def get_blob(server_url, sha256, opts \\ []) when is_binary(sha256) do
    url = build_blob_url(server_url, sha256, opts[:file_extension])
    headers = build_headers(opts[:auth])
    timeout = Keyword.get(opts, :timeout, 30_000)

    case Req.get(url, headers: headers, receive_timeout: timeout) do
      {:ok, %{status: 200, body: content, headers: response_headers}} ->
        content_type = get_content_type(response_headers)
        blob = Blob.new(content, content_type)
        
        # Verify the SHA256 matches what we requested
        if blob.sha256 == sha256 do
          {:ok, blob}
        else
          Logger.error("SHA256 mismatch: expected #{sha256}, got #{blob.sha256}")
          {:error, :sha256_mismatch}
        end

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: status} = response} ->
        reason = get_error_reason(response.headers)
        Logger.error("HTTP #{status}: #{reason}")
        {:error, {:http_error, status, reason}}

      {:error, exception} ->
        Logger.error("Request failed: #{inspect(exception)}")
        {:error, {:request_failed, exception}}
    end
  end

  @doc """
  Checks if a blob exists on a Blossom server.
  
  Uses HEAD request for efficiency.
  """
  @spec has_blob(String.t(), binary(), keyword()) :: {:ok, boolean()} | {:error, term()}
  def has_blob(server_url, sha256, opts \\ []) when is_binary(sha256) do
    url = build_blob_url(server_url, sha256, opts[:file_extension])
    headers = build_headers(opts[:auth])
    timeout = Keyword.get(opts, :timeout, 30_000)

    case Req.head(url, headers: headers, receive_timeout: timeout) do
      {:ok, %{status: 200}} ->
        {:ok, true}

      {:ok, %{status: 404}} ->
        {:ok, false}

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: status} = response} ->
        reason = get_error_reason(response.headers)
        {:error, {:http_error, status, reason}}

      {:error, exception} ->
        {:error, {:request_failed, exception}}
    end
  end

  @doc """
  Uploads a blob to a Blossom server.
  
  Note: This is a placeholder implementation. Proper authentication 
  will be added when nostr_ex is available.
  
  ## Options
  
    * `:private_key` - Nostr private key for signing authorization event
    * `:description` - Human-readable description for the upload
    * `:timeout` - Request timeout in milliseconds (default: 60_000)
  
  ## Examples
  
      {:ok, descriptor} = Blossom.Client.upload_blob(
        "https://blossom.example.com",
        file_content,
        private_key: "your_private_key",
        description: "Upload my document"
      )
  """
  @spec upload_blob(String.t(), binary(), keyword()) :: {:ok, BlobDescriptor.t()} | {:error, term()}
  def upload_blob(server_url, content, opts \\ []) when is_binary(content) do
    url = build_upload_url(server_url)
    timeout = Keyword.get(opts, :timeout, 60_000)
    
    # TODO: Add proper Nostr signing when nostr_ex is available
    auth_event = create_upload_auth(content, opts)
    headers = [
      {"content-type", "application/octet-stream"},
      {"authorization", "Nostr #{AuthEvent.to_auth_header(auth_event)}"}
    ]

    case Req.put(url, body: content, headers: headers, receive_timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, json} ->
            case BlobDescriptor.from_json(json) do
              {:ok, descriptor} -> {:ok, descriptor}
              error -> error
            end
          {:error, _} -> {:error, :invalid_response}
        end

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 413}} ->
        {:error, :blob_too_large}

      {:ok, %{status: status} = response} ->
        reason = get_error_reason(response.headers)
        {:error, {:http_error, status, reason}}

      {:error, exception} ->
        {:error, {:request_failed, exception}}
    end
  end

  @doc """
  Lists blobs uploaded by a specific public key.
  
  ## Options
  
    * `:since` - Unix timestamp to filter blobs uploaded since
    * `:until` - Unix timestamp to filter blobs uploaded until
    * `:auth` - Authorization event for authenticated requests
    * `:timeout` - Request timeout in milliseconds (default: 30_000)
  """
  @spec list_blobs(String.t(), binary(), keyword()) :: {:ok, [BlobDescriptor.t()]} | {:error, term()}
  def list_blobs(server_url, pubkey, opts \\ []) when is_binary(pubkey) do
    url = build_list_url(server_url, pubkey, opts)
    headers = build_headers(opts[:auth])
    timeout = Keyword.get(opts, :timeout, 30_000)

    case Req.get(url, headers: headers, receive_timeout: timeout) do
      {:ok, %{status: 200, body: body}} ->
        case Jason.decode(body) do
          {:ok, json_list} when is_list(json_list) ->
            descriptors = 
              json_list
              |> Enum.map(&BlobDescriptor.from_json/1)
              |> Enum.filter(&match?({:ok, _}, &1))
              |> Enum.map(fn {:ok, descriptor} -> descriptor end)
            
            {:ok, descriptors}

          {:ok, _} -> {:error, :invalid_response_format}
          {:error, _} -> {:error, :invalid_response}
        end

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 404}} ->
        {:ok, []}

      {:ok, %{status: status} = response} ->
        reason = get_error_reason(response.headers)
        {:error, {:http_error, status, reason}}

      {:error, exception} ->
        {:error, {:request_failed, exception}}
    end
  end

  @doc """
  Deletes a blob from a Blossom server.
  
  Note: This is a placeholder implementation. Proper authentication 
  will be added when nostr_ex is available.
  """
  @spec delete_blob(String.t(), binary(), keyword()) :: :ok | {:error, term()}
  def delete_blob(server_url, sha256, opts \\ []) when is_binary(sha256) do
    url = build_blob_url(server_url, sha256)
    timeout = Keyword.get(opts, :timeout, 30_000)
    
    # TODO: Add proper Nostr signing when nostr_ex is available
    auth_event = create_delete_auth(sha256, opts)
    headers = [{"authorization", "Nostr #{AuthEvent.to_auth_header(auth_event)}"}]

    case Req.delete(url, headers: headers, receive_timeout: timeout) do
      {:ok, %{status: 200}} ->
        :ok

      {:ok, %{status: 401}} ->
        {:error, :unauthorized}

      {:ok, %{status: 404}} ->
        {:error, :not_found}

      {:ok, %{status: status} = response} ->
        reason = get_error_reason(response.headers)
        {:error, {:http_error, status, reason}}

      {:error, exception} ->
        {:error, {:request_failed, exception}}
    end
  end

  # Private helper functions

  defp build_blob_url(server_url, sha256, file_extension \\ nil) do
    base_url = String.trim_trailing(server_url, "/")
    path = if file_extension, do: sha256 <> file_extension, else: sha256
    "#{base_url}/#{path}"
  end

  defp build_upload_url(server_url) do
    server_url |> String.trim_trailing("/") |> Kernel.<>("/upload")
  end

  defp build_list_url(server_url, pubkey, opts) do
    base_url = server_url |> String.trim_trailing("/") |> Kernel.<>("/list/#{pubkey}")
    
    query_params = 
      opts
      |> Keyword.take([:since, :until])
      |> Enum.reject(fn {_, v} -> is_nil(v) end)
      |> Enum.map(fn {k, v} -> "#{k}=#{v}" end)
    
    if query_params == [] do
      base_url
    else
      base_url <> "?" <> Enum.join(query_params, "&")
    end
  end

  defp build_headers(nil), do: []
  defp build_headers(auth_event) do
    [{"authorization", "Nostr #{AuthEvent.to_auth_header(auth_event)}"}]
  end

  defp get_content_type(headers) do
    headers
    |> Enum.find(fn {key, _} -> String.downcase(key) == "content-type" end)
    |> case do
      {_, content_type} -> content_type
      nil -> "application/octet-stream"
    end
  end

  defp get_error_reason(headers) do
    headers
    |> Enum.find(fn {key, _} -> String.downcase(key) == "x-reason" end)
    |> case do
      {_, reason} -> reason
      nil -> "Unknown error"
    end
  end

  # TODO: Replace with proper nostr_ex signing when available
  defp create_upload_auth(content, opts) do
    description = Keyword.get(opts, :description, "Upload blob")
    AuthEvent.upload_auth(content, description)
  end

  defp create_delete_auth(sha256, opts) do
    description = Keyword.get(opts, :description, "Delete blob")
    AuthEvent.delete_auth(sha256, description)
  end
end