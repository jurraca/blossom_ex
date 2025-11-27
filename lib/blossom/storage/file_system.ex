defmodule Blossom.Storage.FileSystem do
  @moduledoc """
  File system-based storage backend for Blossom.
  
  Stores blobs as files on the local filesystem with metadata in JSON files.
  """

  @behaviour Blossom.Storage.Behaviour

  alias Blossom.Protocol.{Blob, BlobDescriptor}

  require Logger

  @default_storage_path "priv/blossom_storage"
  @metadata_extension ".meta.json"

  @impl true
  def init(opts \\ []) do
    storage_path = Keyword.get(opts, :storage_path, @default_storage_path)
    
    with :ok <- File.mkdir_p(storage_path),
         :ok <- File.mkdir_p(Path.join(storage_path, "blobs")),
         :ok <- File.mkdir_p(Path.join(storage_path, "metadata")) do
      Application.put_env(:blossom, :storage_path, storage_path)
      Logger.info("Initialized FileSystem storage at #{storage_path}")
      :ok
    else
      {:error, reason} -> 
        Logger.error("Failed to initialize FileSystem storage: #{inspect(reason)}")
        {:error, reason}
    end
  end

  @impl true
  def put_blob(%Blob{} = blob, base_url) do
    storage_path = get_storage_path()
    blob_path = blob_file_path(storage_path, blob.sha256)
    metadata_path = metadata_file_path(storage_path, blob.sha256)

    descriptor = BlobDescriptor.from_blob(blob, base_url)

    with :ok <- write_blob_file(blob_path, blob.content),
         :ok <- write_metadata_file(metadata_path, descriptor) do
      Logger.debug("Stored blob #{blob.sha256}")
      {:ok, descriptor}
    else
      {:error, reason} -> 
        Logger.error("Failed to store blob #{blob.sha256}: #{inspect(reason)}")
        cleanup_failed_write(blob_path, metadata_path)
        {:error, reason}
    end
  end

  @impl true
  def get_blob(sha256) when is_binary(sha256) do
    storage_path = get_storage_path()
    blob_path = blob_file_path(storage_path, sha256)
    metadata_path = metadata_file_path(storage_path, sha256)

    with {:ok, content} <- File.read(blob_path),
         {:ok, metadata_json} <- File.read(metadata_path),
         {:ok, metadata} <- Jason.decode(metadata_json),
         {:ok, descriptor} <- BlobDescriptor.from_json(metadata) do
      
      blob = Blob.from_data(
        sha256,
        content,
        descriptor.type,
        descriptor.size,
        DateTime.from_unix!(descriptor.uploaded)
      )

      # Verify integrity
      if Blob.verify_hash(blob) do
        {:ok, blob}
      else
        Logger.error("Hash verification failed for blob #{sha256}")
        {:error, :corrupted_blob}
      end
    else
      {:error, :enoent} -> {:error, :not_found}
      {:error, reason} -> {:error, reason}
    end
  end

  @impl true
  def has_blob(sha256) when is_binary(sha256) do
    storage_path = get_storage_path()
    blob_path = blob_file_path(storage_path, sha256)
    File.exists?(blob_path)
  end

  @impl true
  def delete_blob(sha256) when is_binary(sha256) do
    storage_path = get_storage_path()
    blob_path = blob_file_path(storage_path, sha256)
    metadata_path = metadata_file_path(storage_path, sha256)

    if File.exists?(blob_path) do
      with :ok <- File.rm(blob_path),
           :ok <- safe_delete_file(metadata_path) do
        Logger.debug("Deleted blob #{sha256}")
        :ok
      else
        {:error, reason} -> 
          Logger.error("Failed to delete blob #{sha256}: #{inspect(reason)}")
          {:error, reason}
      end
    else
      {:error, :not_found}
    end
  end

  @impl true
  def list_blobs(pubkey, opts \\ []) when is_binary(pubkey) do
    storage_path = get_storage_path()
    metadata_dir = Path.join(storage_path, "metadata")
    
    since = Keyword.get(opts, :since)
    until = Keyword.get(opts, :until)

    try do
      metadata_files = File.ls!(metadata_dir)
      descriptors = 
        metadata_files
        |> Enum.filter(&String.ends_with?(&1, @metadata_extension))
        |> Enum.map(&Path.join(metadata_dir, &1))
        |> Enum.filter(&File.exists?/1)
        |> Enum.map(&read_metadata_file/1)
        |> Enum.filter(&match?({:ok, _}, &1))
        |> Enum.map(fn {:ok, descriptor} -> descriptor end)
        |> filter_by_time_range(since, until)

      {:ok, descriptors}
    rescue
      File.Error -> {:error, :storage_unavailable}
      _ -> {:error, :unknown_error}
    end
  end

  @impl true
  def get_stats() do
    storage_path = get_storage_path()
    blobs_dir = Path.join(storage_path, "blobs")

    try do
      files = File.ls!(blobs_dir)
      total_files = length(files)
      
      total_size = 
        files
        |> Enum.map(&Path.join(blobs_dir, &1))
        |> Enum.map(&File.stat!/1)
        |> Enum.map(& &1.size)
        |> Enum.sum()

      stats = %{
        total_blobs: total_files,
        total_size_bytes: total_size,
        storage_path: storage_path
      }

      {:ok, stats}
    rescue
      File.Error -> {:error, :storage_unavailable}
      _ -> {:error, :unknown_error}
    end
  end

  @impl true
  def cleanup() do
    Logger.info("FileSystem storage cleanup completed")
    :ok
  end

  # Private helper functions

  defp get_storage_path() do
    Application.get_env(:blossom, :storage_path, @default_storage_path)
  end

  defp blob_file_path(storage_path, sha256) do
    Path.join([storage_path, "blobs", sha256])
  end

  defp metadata_file_path(storage_path, sha256) do
    Path.join([storage_path, "metadata", sha256 <> @metadata_extension])
  end

  defp write_blob_file(path, content) do
    File.write(path, content)
  end

  defp write_metadata_file(path, descriptor) do
    json = descriptor |> BlobDescriptor.to_json() |> Jason.encode!()
    File.write(path, json)
  end

  defp read_metadata_file(path) do
    with {:ok, json} <- File.read(path),
         {:ok, data} <- Jason.decode(json),
         {:ok, descriptor} <- BlobDescriptor.from_json(data) do
      {:ok, descriptor}
    else
      error -> error
    end
  end

  defp cleanup_failed_write(blob_path, metadata_path) do
    safe_delete_file(blob_path)
    safe_delete_file(metadata_path)
  end

  defp safe_delete_file(path) do
    if File.exists?(path) do
      File.rm(path)
    else
      :ok
    end
  end

  defp filter_by_time_range(descriptors, nil, nil), do: descriptors

  defp filter_by_time_range(descriptors, since, until) do
    Enum.filter(descriptors, fn descriptor ->
      timestamp = descriptor.uploaded
      
      since_ok = is_nil(since) or timestamp >= since
      until_ok = is_nil(until) or timestamp <= until
      
      since_ok and until_ok
    end)
  end
end