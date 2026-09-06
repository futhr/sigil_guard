defmodule SigilGuard.LimitsTest do
  use ExUnit.Case, async: true
  alias SigilGuard.Limits

  test "enforces byte, depth and node budgets with typed errors" do
    assert :ok = Limits.check(%{"a" => [nil, true, 1.5]})

    for value <- [%{"a" => "too large"}, [1, 2, 3], %{nested: %{child: %{value: 1}}}] do
      assert {:error, :invalid_payload} =
               Limits.check(value, max_input_bytes: 2, max_input_nodes: 2, max_input_depth: 1)
    end

    for value <- [0, -1, nil, "1"] do
      assert {:error, :invalid_payload} = Limits.check("safe", max_input_bytes: value)
    end

    assert {:error, :invalid_payload} = Limits.check([1 | 2])
    assert {:error, :invalid_payload} = Limits.check(DateTime.utc_now())
    assert_raise ArgumentError, fn -> SigilGuard.Scanner.scan("too large", max_input_bytes: 2) end
  end

  test "oversized and improper signature arrays fail before crypto" do
    alias SigilGuard.Attestation.Envelope
    {:ok, envelope} = Envelope.sign("payload", SigilGuard.TestSigner)
    oversized = Map.put(envelope, "signatures", List.duplicate(hd(envelope["signatures"]), 65))
    improper = Map.put(envelope, "signatures", [hd(envelope["signatures"]) | :invalid])

    for candidate <- [oversized, improper] do
      assert {:error, :invalid_envelope} = Envelope.verify(candidate, %{})
      assert {:error, :invalid_envelope} = SigilGuard.TrustBundle.Verify.verify(candidate)
    end
  end
end
