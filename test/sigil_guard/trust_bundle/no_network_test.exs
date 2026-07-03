defmodule SigilGuard.TrustBundle.NoNetworkTest do
  use ExUnit.Case, async: false

  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Quarantine

  @fixtures Path.expand("../../fixtures/trust_bundle", __DIR__)
  @now ~U[2026-07-03 12:00:00.000Z]
  @network_references [":httpc", ":gen_tcp", ":ssl", "SigilGuard.HTTPClient"]

  setup do
    Cache.clear()
    Quarantine.clear()

    on_exit(fn ->
      Cache.clear()
      Quarantine.clear()
    end)
  end

  test "load and verify do not open ports for every source class" do
    envelope = read_json(["minimal", "envelope.json"])
    encoded = Jason.encode!(envelope)

    file_path =
      Path.join(System.tmp_dir!(), "sigil_guard-no-network-#{System.unique_integer()}.json")

    priv_rel = "test_trust_bundle/no-network-#{System.unique_integer()}/bundle.json"
    priv_path = Application.app_dir(:sigil_guard, Path.join("priv", priv_rel))

    on_exit(fn ->
      File.rm(file_path)
      File.rm_rf(Path.dirname(priv_path))
    end)

    File.write!(file_path, encoded)
    File.mkdir_p!(Path.dirname(priv_path))
    File.write!(priv_path, encoded)

    assert_unchanged_ports(fn ->
      assert {:ok, %TrustBundle{source: {:map, ^envelope}}} =
               TrustBundle.load({:map, envelope}, now: @now, cache: false, quarantine: false)
    end)

    assert_unchanged_ports(fn ->
      assert {:ok, %TrustBundle{source: {:binary, ^encoded}}} =
               TrustBundle.load({:binary, encoded}, now: @now, cache: false, quarantine: false)
    end)

    assert_unchanged_ports(fn ->
      assert {:ok, %TrustBundle{source: {:file, ^file_path}}} =
               TrustBundle.load({:file, file_path}, now: @now, cache: false, quarantine: false)
    end)

    assert_unchanged_ports(fn ->
      assert {:ok, %TrustBundle{source: {:priv, :sigil_guard, ^priv_rel}}} =
               TrustBundle.load({:priv, :sigil_guard, priv_rel},
                 now: @now,
                 cache: false,
                 quarantine: false
               )
    end)

    assert_unchanged_ports(fn ->
      assert {:ok, %TrustBundle{source: :none}} =
               TrustBundle.verify(envelope, now: @now, quarantine: false)
    end)
  end

  test "dev_bundle does not open ports" do
    seed = :binary.copy(<<0x45>>, 32)

    assert_unchanged_ports(fn ->
      assert {:ok, %TrustBundle{dev?: true, source: :dev}} =
               TrustBundle.dev_bundle(seed: seed, now: @now, cache: false)
    end)
  end

  test "trust-bundle code path has no network client references" do
    contents =
      "lib/sigil_guard/trust_bundle*.ex"
      |> Path.wildcard()
      |> Enum.map_join("\n", &File.read!/1)

    for reference <- @network_references do
      refute contents =~ reference
    end
  end

  defp assert_unchanged_ports(fun) do
    before_ports = MapSet.new(Port.list())
    fun.()
    assert MapSet.new(Port.list()) == before_ports
  end

  defp read_json(path) do
    path
    |> then(&Path.join([@fixtures | &1]))
    |> File.read!()
    |> Jason.decode!()
  end
end
