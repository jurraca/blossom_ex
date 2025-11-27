defmodule Blossom.Protocol.AuthEvent do
  @moduledoc """
  Nostr authorization event for Blossom protocol (kind 24242).
  
  Authorization events are used to authenticate users to Blossom servers.
  This is a placeholder implementation until nostr_ex is available.
  """

  @type t :: %__MODULE__{
          id: binary() | nil,
          pubkey: binary() | nil,
          kind: 24242,
          content: String.t(),
          created_at: non_neg_integer(),
          tags: [[String.t()]],
          sig: binary() | nil
        }

  defstruct [:id, :pubkey, :content, :created_at, :tags, :sig, kind: 24242]

  @doc """
  Creates a new authorization event for the given action.
  
  Actions: "get", "upload", "list", "delete"
  """
  @spec new(String.t(), String.t(), keyword()) :: t()
  def new(action, content, opts \\ []) when action in ["get", "upload", "list", "delete"] do
    now = System.system_time(:second)
    expiration = now + Keyword.get(opts, :expires_in, 3600)
    sha256_hashes = Keyword.get(opts, :sha256_hashes, [])
    server_url = Keyword.get(opts, :server_url)

    tags = 
      [["t", action], ["expiration", to_string(expiration)]]
      |> maybe_add_sha256_tags(sha256_hashes)
      |> maybe_add_server_tag(server_url)

    %__MODULE__{
      content: content,
      created_at: now,
      tags: tags
    }
  end

  @doc """
  Creates an upload authorization event.
  """
  @spec upload_auth(binary(), String.t()) :: t()
  def upload_auth(content, description \\ "Upload blob") do
    sha256 = :crypto.hash(:sha256, content) |> Base.encode16(case: :lower)
    new("upload", description, sha256_hashes: [sha256])
  end

  @doc """
  Creates a get authorization event for specific blobs.
  """
  @spec get_auth([binary()], String.t()) :: t()
  def get_auth(sha256_hashes, description \\ "Get blobs") when is_list(sha256_hashes) do
    new("get", description, sha256_hashes: sha256_hashes)
  end

  @doc """
  Creates a delete authorization event.
  """
  @spec delete_auth(binary(), String.t()) :: t()
  def delete_auth(sha256, description \\ "Delete blob") do
    new("delete", description, sha256_hashes: [sha256])
  end

  @doc """
  Creates a list authorization event.
  """
  @spec list_auth(String.t()) :: t()
  def list_auth(description \\ "List blobs") do
    new("list", description)
  end

  @doc """
  Validates the structure of an authorization event.
  """
  @spec validate(t()) :: :ok | {:error, term()}
  def validate(%__MODULE__{} = event) do
    with :ok <- validate_kind(event.kind),
         :ok <- validate_created_at(event.created_at),
         :ok <- validate_tags(event.tags),
         :ok <- validate_expiration(event.tags) do
      :ok
    end
  end

  @doc """
  Converts event to base64-encoded string for HTTP Authorization header.
  """
  @spec to_auth_header(t()) :: String.t()
  def to_auth_header(%__MODULE__{} = event) do
    event
    |> to_json()
    |> Jason.encode!()
    |> Base.encode64()
  end

  @doc """
  Converts event to JSON-encodable map.
  """
  @spec to_json(t()) :: map()
  def to_json(%__MODULE__{} = event) do
    %{
      "id" => event.id,
      "pubkey" => event.pubkey,
      "kind" => event.kind,
      "content" => event.content,
      "created_at" => event.created_at,
      "tags" => event.tags,
      "sig" => event.sig
    }
  end

  @doc """
  Parses event from base64-encoded authorization header.
  """
  @spec from_auth_header(String.t()) :: {:ok, t()} | {:error, term()}
  def from_auth_header("Nostr " <> encoded) do
    from_auth_header(encoded)
  end

  def from_auth_header(encoded) when is_binary(encoded) do
    with {:ok, json_string} <- Base.decode64(encoded),
         {:ok, json} <- Jason.decode(json_string),
         {:ok, event} <- from_json(json) do
      {:ok, event}
    else
      :error -> {:error, :invalid_base64}
      {:error, _} = error -> error
    end
  end

  @doc """
  Creates event from JSON data.
  """
  @spec from_json(map()) :: {:ok, t()} | {:error, term()}
  def from_json(json) when is_map(json) do
    try do
      event = %__MODULE__{
        id: json["id"],
        pubkey: json["pubkey"],
        kind: json["kind"] || 24242,
        content: json["content"],
        created_at: json["created_at"],
        tags: json["tags"] || [],
        sig: json["sig"]
      }

      {:ok, event}
    rescue
      _ -> {:error, :invalid_json}
    end
  end

  # Private helper functions

  defp maybe_add_sha256_tags(tags, []), do: tags
  defp maybe_add_sha256_tags(tags, sha256_hashes) do
    sha256_tags = Enum.map(sha256_hashes, &["x", &1])
    tags ++ sha256_tags
  end

  defp maybe_add_server_tag(tags, nil), do: tags
  defp maybe_add_server_tag(tags, server_url) do
    tags ++ [["server", server_url]]
  end

  defp validate_kind(24242), do: :ok
  defp validate_kind(_), do: {:error, :invalid_kind}

  defp validate_created_at(created_at) when is_integer(created_at) and created_at > 0 do
    now = System.system_time(:second)
    if created_at <= now do
      :ok
    else
      {:error, :future_timestamp}
    end
  end

  defp validate_created_at(_), do: {:error, :invalid_created_at}

  defp validate_tags(tags) when is_list(tags) do
    if Enum.all?(tags, &is_list/1) do
      :ok
    else
      {:error, :invalid_tags}
    end
  end

  defp validate_tags(_), do: {:error, :invalid_tags}

  defp validate_expiration(tags) do
    case find_expiration_tag(tags) do
      nil -> {:error, :missing_expiration}
      expiration_str ->
        case Integer.parse(expiration_str) do
          {expiration, ""} ->
            now = System.system_time(:second)
            if expiration > now do
              :ok
            else
              {:error, :expired}
            end
          _ -> {:error, :invalid_expiration_format}
        end
    end
  end

  defp find_expiration_tag(tags) do
    Enum.find_value(tags, fn
      ["expiration", value] -> value
      _ -> nil
    end)
  end
end