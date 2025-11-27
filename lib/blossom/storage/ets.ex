defmodule Blossom.Storage.ETS do
  @moduledoc """
  ETS-based in-memory storage backend for Blossom.
  
  Useful for development and testing. Data is not persisted between restarts.
  """

  @behaviour Blossom.Storage.Behaviour
  
  alias Blossom.Protocol.{Blob, BlobDescriptor}
  
  require Logger

  @table_name :blossom_storage
  @stats_table :blossom_stats

  @impl true
  def init(_opts \\ []) do
    # Create ETS tables if they don't exist
    unless :ets.whereis(@table_name) != :undefined do
      :ets.new(@table_name, [:set, :public, :named_table])
    end
    
    unless :ets.whereis(@stats_table) != :undefined do
      :ets.new(@stats_table, [:set, :public, :named_table])
      :ets.insert(@stats_table, {:total_blobs, 0})
      :ets.insert(@stats_table, {:total_size_bytes, 0})
    end

    Logger.info("Initialized ETS storage")
    :ok
  end

  @impl true
  def put_blob(%Blob{} = blob, base_url) do
    descriptor = BlobDescriptor.from_blob(blob, base_url)
    
    # Store blob data
    blob_data = %{
      content: blob.content,
      content_type: blob.content_type,
      content_length: blob.content_length,
      uploaded_at: blob.uploaded_at,
      descriptor: descriptor
    }
    
    case :ets.insert(@table_name, {blob.sha256, blob_data}) do
      true ->
        update_stats(:increment, blob.content_length)
        Logger.debug("Stored blob #{blob.sha256} in ETS")
        {:ok, descriptor}
      false ->
        Logger.error("Failed to store blob #{blob.sha256} in ETS")
        {:error, :storage_error}
    end
  end

  @impl true
  def get_blob(sha256) when is_binary(sha256) do
    case :ets.lookup(@table_name, sha256) do
      [{^sha256, blob_data}] ->
        blob = Blob.from_data(
          sha256,
          blob_data.content,
          blob_data.content_type,
          blob_data.content_length,
          blob_data.uploaded_at
        )
        
        # Verify integrity
        if Blob.verify_hash(blob) do
          {:ok, blob}
        else
          Logger.error("Hash verification failed for blob #{sha256}")
          {:error, :corrupted_blob}
        end
        
      [] ->
        {:error, :not_found}
    end
  end

  @impl true
  def has_blob(sha256) when is_binary(sha256) do
    case :ets.lookup(@table_name, sha256) do
      [{^sha256, _}] -> true
      [] -> false
    end
  end

  @impl true
  def delete_blob(sha256) when is_binary(sha256) do
    case :ets.lookup(@table_name, sha256) do
      [{^sha256, blob_data}] ->
        case :ets.delete(@table_name, sha256) do
          true ->
            update_stats(:decrement, blob_data.content_length)
            Logger.debug("Deleted blob #{sha256} from ETS")
            :ok
          false ->
            Logger.error("Failed to delete blob #{sha256} from ETS")
            {:error, :storage_error}
        end
        
      [] ->
        {:error, :not_found}
    end
  end

  @impl true
  def list_blobs(pubkey, opts \\ []) when is_binary(pubkey) do
    since = Keyword.get(opts, :since)
    until = Keyword.get(opts, :until)
    
    try do
      descriptors = 
        @table_name
        |> :ets.tab2list()
        |> Enum.map(fn {_sha256, blob_data} -> blob_data.descriptor end)
        |> filter_by_time_range(since, until)

      {:ok, descriptors}
    rescue
      ArgumentError -> {:error, :table_not_found}
      _ -> {:error, :unknown_error}
    end
  end

  @impl true
  def get_stats() do
    try do
      total_blobs = get_stat(:total_blobs)
      total_size = get_stat(:total_size_bytes)
      
      stats = %{
        total_blobs: total_blobs,
        total_size_bytes: total_size,
        storage_type: :ets
      }

      {:ok, stats}
    rescue
      ArgumentError -> {:error, :table_not_found}
      _ -> {:error, :unknown_error}
    end
  end

  @impl true
  def cleanup() do
    try do
      if :ets.whereis(@table_name) != :undefined do
        :ets.delete(@table_name)
      end
      
      if :ets.whereis(@stats_table) != :undefined do
        :ets.delete(@stats_table)
      end
      
      Logger.info("ETS storage cleanup completed")
      :ok
    rescue
      _ -> {:error, :cleanup_failed}
    end
  end

  # Private helper functions

  defp update_stats(:increment, size) do
    :ets.update_counter(@stats_table, :total_blobs, 1)
    :ets.update_counter(@stats_table, :total_size_bytes, size)
  end

  defp update_stats(:decrement, size) do
    :ets.update_counter(@stats_table, :total_blobs, -1)
    :ets.update_counter(@stats_table, :total_size_bytes, -size)
  end

  defp get_stat(key) do
    case :ets.lookup(@stats_table, key) do
      [{^key, value}] -> value
      [] -> 0
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