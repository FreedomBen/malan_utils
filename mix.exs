defmodule MalanUtils.MixProject do
  use Mix.Project

  def project do
    [
      app: :malan_utils,
      name: "malan_utils",
      version: "0.1.0",
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      app: :postgrex,
      version: "0.1.0",
      elixir: "~> 1.0",
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      description: description(),
      package: package(),
      source_url: "https://github.com/FreedomBen/malan_utils"
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
      {:pbkdf2_elixir, "~> 1.2"}
    ]
  end

  defp description() do
    "Set of utility functions initially written for the Malan project, but now independent."
  end

  defp package() do
    [
      licenses: ["MIT", "Apache-2.0"],
      links: %{"GitHub" => "https://github.com/FreedomBen/malan_utils"}
    ]
  end
end
