defmodule Blossom do
  @moduledoc """
  Blossom - A client and server library for the Blossom protocol.

  Blossom is a specification for HTTP endpoints that allow users to store 
  blobs of data on publicly accessible servers using Nostr identities.

  This library provides:
  - HTTP client for interacting with Blossom servers
  - Plug-based server implementation 
  - Optional standalone server using Bandit
  - Pluggable storage backends

  ## Usage

  ### Client Usage

      # Get a blob from a server
      {:ok, blob} = Blossom.Client.get_blob("https://blossom.example.com", "sha256_hash")
      
      # Upload a blob (requires private key)
      {:ok, descriptor} = Blossom.Client.upload_blob(
        "https://blossom.example.com", 
        file_content,
        private_key: "your_nostr_private_key"
      )

  ### Server Usage (with Phoenix)

      # In your router
      forward "/blossom", Blossom.Plug.Pipeline
      
  ### Standalone Server

      # Start a standalone Blossom server
      {:ok, _pid} = Blossom.Server.start_link(port: 4000)
  """

  alias Blossom.Protocol.{Blob, BlobDescriptor, AuthEvent}

  @doc """
  Creates a new blob from binary content.
  """
  @spec create_blob(binary(), String.t()) :: Blob.t()
  def create_blob(content, content_type \\ "application/octet-stream") do
    Blob.new(content, content_type)
  end

  @doc """
  Creates a blob descriptor from a blob and server URL.
  """
  @spec create_descriptor(Blob.t(), String.t()) :: BlobDescriptor.t()
  def create_descriptor(%Blob{} = blob, base_url) do
    BlobDescriptor.from_blob(blob, base_url)
  end

  @doc """
  Creates an upload authorization event.
  """
  @spec create_upload_auth(binary(), String.t()) :: AuthEvent.t()
  def create_upload_auth(content, description \\ "Upload blob") do
    AuthEvent.upload_auth(content, description)
  end
end
