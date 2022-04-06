defmodule MalanUtils.MixProject do
  use Mix.Project

  @source_url "https://github.com/freedomben/malan_utils"
  @version "0.1.0"

  def project do
    [
      app: :malan_utils,
      version: @version,
      elixir: "~> 1.13",
      start_permanent: Mix.env() == :prod,
      description: "Set of utility functions initially written for the Malan project, but now independent.",
      package: package(),
      deps: deps(),
      docs: docs()
    ]
  end

  def package do
    [
      name: "malan_utils",
      maintainers: ["Benjmain Porter"],
      licenses: ["MIT", "Apache-2.0"],
      links: %{"GitHub" => @source_url}
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
      {:ex_doc, "~> 0.28.0"},
      {:pbkdf2_elixir, "~> 1.2"},
    ]
  end

  defp docs do
    [
      main: "MalanUtils",
      source_url: @source_url,
      extra_section: [],
      api_reference: false
    ]
  end
end
