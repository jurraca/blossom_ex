defmodule Blossom.Protocol.BlobDescriptor do
  @moduledoc """
  Blob descriptor as defined in BUD-02.
  
  A blob descriptor is a JSON object containing metadata about a blob
  stored on a Blossom server.
  """

  @type t :: %__MODULE__{
          url: String.t(),
          sha256: binary(),
          size: non_neg_integer(),
          type: String.t(),
          uploaded: non_neg_integer()
        }

  defstruct [:url, :sha256, :size, :type, :uploaded]

  @doc """
  Creates a new blob descriptor.
  """
  @spec new(String.t(), binary(), non_neg_integer(), String.t(), DateTime.t()) :: t()
  def new(base_url, sha256, size, content_type, uploaded_at) do
    # Determine file extension from content type
    extension = extension_from_content_type(content_type)
    url = build_url(base_url, sha256, extension)

    %__MODULE__{
      url: url,
      sha256: sha256,
      size: size,
      type: content_type,
      uploaded: DateTime.to_unix(uploaded_at)
    }
  end

  @doc """
  Creates a blob descriptor from a Blob struct.
  """
  @spec from_blob(Blossom.Protocol.Blob.t(), String.t()) :: t()
  def from_blob(%Blossom.Protocol.Blob{} = blob, base_url) do
    new(base_url, blob.sha256, blob.content_length, blob.content_type, blob.uploaded_at)
  end

  @doc """
  Converts blob descriptor to JSON-encodable map.
  """
  @spec to_json(t()) :: map()
  def to_json(%__MODULE__{} = descriptor) do
    %{
      "url" => descriptor.url,
      "sha256" => descriptor.sha256,
      "size" => descriptor.size,
      "type" => descriptor.type,
      "uploaded" => descriptor.uploaded
    }
  end

  @doc """
  Creates blob descriptor from JSON data.
  """
  @spec from_json(map()) :: {:ok, t()} | {:error, term()}
  def from_json(json) when is_map(json) do
    try do
      descriptor = %__MODULE__{
        url: Map.fetch!(json, "url"),
        sha256: Map.fetch!(json, "sha256"),
        size: Map.fetch!(json, "size"),
        type: Map.fetch!(json, "type"),
        uploaded: Map.fetch!(json, "uploaded")
      }

      {:ok, descriptor}
    rescue
      KeyError -> {:error, :missing_required_field}
      _ -> {:error, :invalid_json}
    end
  end

  # Private helper functions

  defp build_url(base_url, sha256, extension) do
    base_url
    |> String.trim_trailing("/")
    |> Kernel.<>("/" <> sha256 <> extension)
  end

  defp extension_from_content_type(content_type) do
    case content_type do
      "application/pdf" -> ".pdf"
      "image/png" -> ".png"
      "image/jpeg" -> ".jpg"
      "image/gif" -> ".gif"
      "image/webp" -> ".webp"
      "video/mp4" -> ".mp4"
      "video/webm" -> ".webm"
      "audio/mpeg" -> ".mp3"
      "audio/wav" -> ".wav"
      "text/plain" -> ".txt"
      "text/html" -> ".html"
      "application/json" -> ".json"
      "application/xml" -> ".xml"
      _ -> ".bin"
    end
  end
end