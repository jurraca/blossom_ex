defmodule Blossom.Storage.Behaviour do
  @moduledoc """
  Behaviour for Blossom storage backends.
  
  Storage backends are responsible for persisting and retrieving blobs
  and their associated metadata.
  """

  alias Blossom.Protocol.{Blob, BlobDescriptor}

  @doc """
  Stores a blob and returns its descriptor.
  """
  @callback put_blob(Blob.t(), String.t()) :: {:ok, BlobDescriptor.t()} | {:error, term()}

  @doc """
  Retrieves a blob by its SHA256 hash.
  """
  @callback get_blob(binary()) :: {:ok, Blob.t()} | {:error, :not_found} | {:error, term()}

  @doc """
  Checks if a blob exists by its SHA256 hash.
  """
  @callback has_blob(binary()) :: boolean()

  @doc """
  Deletes a blob by its SHA256 hash.
  """
  @callback delete_blob(binary()) :: :ok | {:error, :not_found} | {:error, term()}

  @doc """
  Lists all blobs uploaded by a specific public key.
  
  Returns a list of blob descriptors, optionally filtered by time range.
  """
  @callback list_blobs(binary(), keyword()) :: {:ok, [BlobDescriptor.t()]} | {:error, term()}

  @doc """
  Returns storage statistics.
  """
  @callback get_stats() :: {:ok, map()} | {:error, term()}

  @doc """
  Initializes the storage backend.
  """
  @callback init(keyword()) :: :ok | {:error, term()}

  @doc """
  Cleans up the storage backend.
  """
  @callback cleanup() :: :ok | {:error, term()}
end