defmodule SigilGuard.BenchCorpus do
  @moduledoc false

  @seed {1763, 8785, 9162}
  @dir Path.expand("corpus", __DIR__)
  @secret "AKIAIOSFODNN7EXAMPLE"
  @sizes [{"1k", 1024}, {"64k", 65_536}, {"1m", 1_048_576}]

  @doc false
  def generate!(dir \\ @dir) do
    :rand.seed(:exsss, @seed)
    File.mkdir_p!(dir)

    for {label, bytes} <- @sizes do
      write!(dir, "clean_#{label}.txt", clean_payload(bytes))
      write!(dir, "hits_#{label}.txt", hits_payload(bytes))
    end

    copy_fixture!("trust_bundle_minimal.json", dir)
    :ok
  end

  @doc false
  def files(dir \\ @dir) do
    for {label, _bytes} <- @sizes,
        kind <- ["clean", "hits"] do
      Path.join(dir, "#{kind}_#{label}.txt")
    end ++ [Path.join(dir, "trust_bundle_minimal.json")]
  end

  defp clean_payload(bytes), do: payload(bytes, false)
  defp hits_payload(bytes), do: payload(bytes, true)

  defp payload(bytes, with_hits?) do
    chunks = div(bytes, 4096)

    base =
      1..max(chunks, 1)
      |> Enum.map(fn index ->
        marker =
          if with_hits? and index <= chunks do
            " #{@secret} "
          else
            " documented synthetic benchmark text #{index} "
          end

        fill = random_ascii(max(4096 - byte_size(marker), 0))
        marker <> fill
      end)
      |> IO.iodata_to_binary()

    binary_part(base <> random_ascii(bytes), 0, bytes)
  end

  defp random_ascii(0), do: ""

  defp random_ascii(count) do
    for _ <- 1..count, into: <<>> do
      <<Enum.random(?a..?z)>>
    end
  end

  defp write!(dir, name, payload), do: File.write!(Path.join(dir, name), payload)

  defp copy_fixture!(name, dir) do
    source =
      __DIR__
      |> Path.join("../test/fixtures/trust_bundle/minimal/envelope.json")
      |> Path.expand()

    File.cp!(source, Path.join(dir, name))
  end
end

unless function_exported?(Mix, :env, 0) and Mix.env() == :test do
  SigilGuard.BenchCorpus.generate!()
end
