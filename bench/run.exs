defmodule SigilGuard.BenchSigner do
  @moduledoc """
  Deterministic signer for benchmark runs.

  Uses a fixed Ed25519 seed derived from a SHA-256 hash so that benchmark
  results are reproducible. This module mirrors `SigilGuard.TestSigner` but
  lives in `bench/` since test support modules are not compiled in the `:dev`
  environment where benchmarks execute.
  """
  @behaviour SigilGuard.Signer

  @seed :crypto.hash(:sha256, "sigil_guard_bench_seed")

  def keypair, do: :crypto.generate_key(:eddsa, :ed25519, @seed)

  @impl true
  def sign(message) do
    {_pub, priv} = keypair()
    :crypto.sign(:eddsa, :none, message, [priv, :ed25519])
  end

  @impl true
  def public_key do
    {pub, _priv} = keypair()
    pub
  end

  def public_key_b64u, do: Base.url_encode64(public_key(), padding: false)
end

defmodule SigilGuard.Bench do
  @moduledoc """
  Performance benchmark suite for SigilGuard.

  Measures throughput and latency of core operations across backends.
  When the NIF backend is available, benchmarks compare Elixir vs NIF
  performance side-by-side.

  ## Running

      mix bench

  ## Interpreting Results

    - **ips** (iterations per second) — higher is better
    - **average** — mean execution time per operation
    - **memory** — memory allocated per operation
  """

  @output_file "bench/output/benchmarks.md"

  @doc "Run the complete benchmark suite."
  def run do
    IO.puts("SigilGuard Benchmark Suite")
    IO.puts("=========================\n")

    nif? = nif_available?()

    if nif? do
      IO.puts("NIF backend: available (comparing both backends)")
    else
      IO.puts("NIF backend: not available (Elixir only)")
    end

    IO.puts("")

    scenarios =
      %{}
      |> Map.merge(scanner_scenarios(nif?))
      |> Map.merge(envelope_scenarios(nif?))
      |> Map.merge(policy_scenarios(nif?))
      |> Map.merge(audit_scenarios())

    Benchee.run(
      scenarios,
      warmup: 2,
      time: 5,
      memory_time: 2,
      formatters: [
        Benchee.Formatters.Console,
        {Benchee.Formatters.Markdown,
         file: @output_file,
         description: """
         # SigilGuard Performance Benchmarks

         Run on: #{DateTime.utc_now() |> DateTime.to_string()}
         Backend: #{if nif?, do: "Elixir + NIF", else: "Elixir only"}
         """}
      ]
    )
  end

  defp scanner_scenarios(nif?) do
    clean = "This is a completely safe text with no secrets or credentials."
    secret = "My key is AKIAIOSFODNN7EXAMPLE and it should be redacted."

    mixed = """
    Config file:
    DB_URL=postgres://admin:s3cret@db.prod.example.com:5432/myapp
    API_KEY=sk_live_abc123def456ghi789jkl012mno345pqr
    Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.test.signature
    """

    large = String.duplicate(clean <> " ", 100)

    base = %{
      "scanner / elixir scan clean" => fn -> SigilGuard.Backend.Elixir.scan(clean, []) end,
      "scanner / elixir scan secret" => fn -> SigilGuard.Backend.Elixir.scan(secret, []) end,
      "scanner / elixir scan mixed" => fn -> SigilGuard.Backend.Elixir.scan(mixed, []) end,
      "scanner / elixir scan large" => fn -> SigilGuard.Backend.Elixir.scan(large, []) end,
      "scanner / elixir scan_and_redact" => fn ->
        SigilGuard.Backend.Elixir.scan_and_redact(mixed, [])
      end
    }

    if nif? do
      Map.merge(base, %{
        "scanner / nif scan clean" => fn -> SigilGuard.Backend.NIF.scan(clean, []) end,
        "scanner / nif scan secret" => fn -> SigilGuard.Backend.NIF.scan(secret, []) end,
        "scanner / nif scan mixed" => fn -> SigilGuard.Backend.NIF.scan(mixed, []) end,
        "scanner / nif scan large" => fn -> SigilGuard.Backend.NIF.scan(large, []) end,
        "scanner / nif scan_and_redact" => fn ->
          SigilGuard.Backend.NIF.scan_and_redact(mixed, [])
        end
      })
    else
      base
    end
  end

  defp envelope_scenarios(nif?) do
    identity = "did:sigil:bench"
    verdict = :allowed
    ts = "2024-01-01T00:00:00.000Z"
    nonce = "abcdef1234567890abcdef1234567890"

    envelope =
      SigilGuard.Backend.Elixir.envelope_sign(identity, verdict,
        signer: SigilGuard.BenchSigner,
        timestamp: ts,
        nonce: nonce
      )

    pub_key = SigilGuard.BenchSigner.public_key_b64u()

    base = %{
      "envelope / elixir canonical_bytes" => fn ->
        SigilGuard.Backend.Elixir.canonical_bytes(identity, verdict, ts, nonce)
      end,
      "envelope / elixir sign" => fn ->
        SigilGuard.Backend.Elixir.envelope_sign(identity, verdict, signer: SigilGuard.BenchSigner)
      end,
      "envelope / elixir verify" => fn ->
        SigilGuard.Backend.Elixir.envelope_verify(envelope, pub_key)
      end
    }

    if nif? do
      Map.merge(base, %{
        "envelope / nif canonical_bytes" => fn ->
          SigilGuard.Backend.NIF.canonical_bytes(identity, verdict, ts, nonce)
        end
      })
    else
      base
    end
  end

  defp policy_scenarios(nif?) do
    base = %{
      "policy / elixir classify_risk" => fn ->
        SigilGuard.Backend.Elixir.classify_risk("read_file", [])
      end,
      "policy / elixir evaluate" => fn ->
        SigilGuard.Backend.Elixir.evaluate_policy("write_file", :authenticated, [])
      end
    }

    if nif? do
      Map.merge(base, %{
        "policy / nif classify_risk" => fn ->
          SigilGuard.Backend.NIF.classify_risk("read_file", [])
        end,
        "policy / nif evaluate" => fn ->
          SigilGuard.Backend.NIF.evaluate_policy("write_file", :authenticated, [])
        end
      })
    else
      base
    end
  end

  defp audit_scenarios do
    key = :crypto.strong_rand_bytes(32)

    events_10 =
      for i <- 1..10, do: SigilGuard.Audit.new_event("bench", "actor", "action_#{i}", "ok")

    events_100 =
      for i <- 1..100, do: SigilGuard.Audit.new_event("bench", "actor", "action_#{i}", "ok")

    chain_10 = SigilGuard.Audit.build_chain(events_10, key)
    chain_100 = SigilGuard.Audit.build_chain(events_100, key)

    %{
      "audit / elixir build_chain 10" => fn -> SigilGuard.Audit.build_chain(events_10, key) end,
      "audit / elixir build_chain 100" => fn -> SigilGuard.Audit.build_chain(events_100, key) end,
      "audit / elixir verify_chain 10" => fn ->
        SigilGuard.Backend.Elixir.audit_verify_chain(chain_10, key)
      end,
      "audit / elixir verify_chain 100" => fn ->
        SigilGuard.Backend.Elixir.audit_verify_chain(chain_100, key)
      end
    }
  end

  defp nif_available? do
    try do
      SigilGuard.Backend.NIF.Native.classify_risk("test", [])
      true
    rescue
      _ -> false
    end
  end
end

SigilGuard.Bench.run()
