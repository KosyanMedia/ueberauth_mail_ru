defmodule UeberauthMailRu.Mixfile do
  use Mix.Project

  @version "0.1.0"
  @url "https://github.com/KosyanMedia/ueberauth_mail_ru"

  def project do
    [
      app: :ueberauth_mail_ru,
      version: @version,
      name: "Ueberauth Mail.ru Strategy",
      elixir: "~> 1.3",
      source_url: @url,
      package: package(),
      homepage_url: @url,
      build_embedded: Mix.env == :prod,
      start_permanent: Mix.env == :prod,
      description: description(),
      deps: deps(),
      docs: docs()
   ]
  end

  def application do
    [applications: [:logger, :oauth2, :ueberauth]]
  end

  defp deps do
    [
      {:ueberauth, "~> 0.4"},
      {:oauth2, "~> 0.8.0"}
    ]
  end

  defp docs do
    [extras: ["README.md"]]
  end

  defp description do
    "An Uberauth strategy for Mail.ru authentication."
  end

  defp package do
    [
      files: ["lib", "mix.exs", "README.md", "LICENSE"],
      maintainers: ["KosyanMedia", "Nikita Bulatov"],
      licenses: ["MIT"],
      links: %{"GitHub": @url}
    ]
  end
end
