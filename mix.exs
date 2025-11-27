defmodule Blossom.MixProject do
  use Mix.Project

  def project do
    [
      app: :blossom,
      version: "0.1.0",
      elixir: "~> 1.18",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # Core dependencies
      {:req, "~> 0.5"},
      {:plug, "~> 1.15"},
      {:jason, "~> 1.4"},
      {:nostr_ex, "~> 0.1.0"},

      # Optional server dependency
      {:bandit, "~> 1.7", optional: true},

      # Development and testing
      {:ex_doc, "~> 0.34", only: :dev, runtime: false},
      {:deps_nix, "~> 2.6.0"}
    ]
  end
end
