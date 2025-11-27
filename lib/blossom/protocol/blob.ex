defmodule Blossom.Protocol.Blob do
  @moduledoc """
  Represents a blob of data in the Blossom protocol.
  
  Blobs are binary data addressed by their SHA256 hash.
  """

  @type t :: %__MODULE__{
          sha256: binary(),
          content: binary(),
          content_type: String.t(),
          content_length: non_neg_integer(),
          uploaded_at: DateTime.t() | nil
        }

  defstruct [:sha256, :content, :content_type, :content_length, :uploaded_at]

  @doc """
  Creates a new blob from binary content.
  
  Automatically calculates the SHA256 hash and content length.
  """
  @spec new(binary(), String.t()) :: t()
  def new(content, content_type \\ "application/octet-stream") when is_binary(content) do
    sha256 = :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)

    %__MODULE__{
      sha256: sha256,
      content: content,
      content_type: content_type,
      content_length: byte_size(content),
      uploaded_at: DateTime.utc_now()
    }
  end

  @doc """
  Verifies that the content matches the expected SHA256 hash.
  """
  @spec verify_hash(t()) :: boolean()
  def verify_hash(%__MODULE__{sha256: expected_hash, content: content}) do
    actual_hash = :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)
    expected_hash == actual_hash
  end

  @doc """
  Creates a blob from existing data without recalculating hash.
  Used when loading from storage.
  """
  @spec from_data(binary(), binary(), String.t(), non_neg_integer(), DateTime.t() | nil) :: t()
  def from_data(sha256, content, content_type, content_length, uploaded_at \\ nil) do
    %__MODULE__{
      sha256: sha256,
      content: content,
      content_type: content_type,
      content_length: content_length,
      uploaded_at: uploaded_at
    }
  end
end