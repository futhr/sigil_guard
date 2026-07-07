defmodule SigilGuard.Audit.ProofTest do
  use ExUnit.Case, async: true

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Proof
  alias SigilGuard.AuditProofFixture, as: Fixture

  # The anchor root from SP.05's five-event golden vector; pinned as a literal so
  # a change to leaf/node hashing is caught even if the fixture regenerates.
  @root_5 "14ba3acb7050e49d3f2c3d633a8057ef39d936281298fb23fe215c774179aa0b"

  defp load(name), do: Jason.decode!(File.read!(Fixture.path(name)))

  describe "golden vectors (SP.05 five-event tree)" do
    test "committed fixtures regenerate byte-identically" do
      assert File.read!(Fixture.path("events.json")) == Fixture.events_json()
      assert File.read!(Fixture.path("tree.json")) == Fixture.tree_json()
      assert File.read!(Fixture.path("inclusion_5.json")) == Fixture.inclusion_json()
      assert File.read!(Fixture.path("checkpoint_5.json")) == Fixture.checkpoint_json()
    end

    test "roots at each size match the normative construction" do
      tree = load("tree.json")
      [h0 | _] = tree["leaves"]

      # root_1 = H0, root_2 = N01, root_4 = N0123, root_5 = R5.
      assert tree["roots"]["1"] == h0
      assert tree["roots"]["2"] == tree["nodes"]["N01"]
      assert tree["roots"]["4"] == tree["nodes"]["N0123"]
      assert tree["roots"]["5"] == @root_5
    end

    test "the committed inclusion proofs match the SP.05 path table" do
      %{"proofs" => proofs} = load("inclusion_5.json")
      tree = load("tree.json")
      [h0, h1, h2, h3, h4] = tree["leaves"]
      %{"N01" => n01, "N23" => n23, "N0123" => n0123} = tree["nodes"]

      assert path(proofs, 0) == [h1, n23, h4]
      assert path(proofs, 1) == [h0, n23, h4]
      assert path(proofs, 2) == [h3, n01, h4]
      assert path(proofs, 3) == [h2, n01, h4]
      assert path(proofs, 4) == [n0123]
    end
  end

  describe "inclusion/2 generation" do
    test "reproduces every committed proof" do
      events = Fixture.signed_events()
      committed = load("inclusion_5.json")["proofs"]

      for i <- 0..4 do
        assert {:ok, proof} = Proof.inclusion(events, i)
        assert proof == Enum.at(committed, i)
      end
    end

    test "a leaf index at or beyond the tree size is out of range" do
      events = Fixture.signed_events()
      assert Proof.inclusion(events, 5) == {:error, :out_of_range}
      assert Proof.inclusion(events, 99) == {:error, :out_of_range}
      assert Proof.inclusion([], 0) == {:error, :out_of_range}
    end

    test "a negative or non-integer index is out of range" do
      events = Fixture.signed_events()
      assert Proof.inclusion(events, -1) == {:error, :out_of_range}
      assert Proof.inclusion(events, :first) == {:error, :out_of_range}
    end

    test "an unsigned event fails like merkle_root/1" do
      events = Fixture.signed_events()
      %Audit{} = last = List.last(events)
      unsigned = %{last | hmac: nil}
      assert Proof.inclusion(Enum.concat(events, [unsigned]), 5) == {:error, :unsigned_event}
    end
  end

  describe "verify_inclusion/3" do
    setup do
      events = Fixture.signed_events()
      proofs = load("inclusion_5.json")["proofs"]
      %{events: events, proofs: proofs, root: @root_5}
    end

    test "every committed proof verifies against the checkpoint root", ctx do
      checkpoint_root = load("checkpoint_5.json")["merkle_root"]
      assert checkpoint_root == ctx.root

      for i <- 0..4 do
        hmac = Enum.at(ctx.events, i).hmac
        assert Proof.verify_inclusion(Enum.at(ctx.proofs, i), hmac, ctx.root) == :ok
      end
    end

    test "a single-leaf tree proof has an empty path and verifies", ctx do
      [first | _] = ctx.events
      assert {:ok, proof} = Proof.inclusion([first], 0)
      assert proof["audit_path"] == []
      root_1 = load("tree.json")["roots"]["1"]
      assert Proof.verify_inclusion(proof, first.hmac, root_1) == :ok
    end

    test "proofs verify at every intermediate size against that size's root", ctx do
      roots = load("tree.json")["roots"]

      for size <- 1..5, index <- 0..(size - 1) do
        segment = Enum.take(ctx.events, size)
        {:ok, proof} = Proof.inclusion(segment, index)
        hmac = Enum.at(segment, index).hmac
        assert Proof.verify_inclusion(proof, hmac, roots[Integer.to_string(size)]) == :ok
      end
    end

    test "a proof for one leaf does not verify another leaf's hmac", ctx do
      proof0 = Enum.at(ctx.proofs, 0)
      hmac2 = Enum.at(ctx.events, 2).hmac

      assert Proof.verify_inclusion(proof0, hmac2, ctx.root) ==
               {:error, :proof_verification_failed}
    end

    test "a wrong checkpoint root fails verification", ctx do
      proof0 = Enum.at(ctx.proofs, 0)
      hmac0 = Enum.at(ctx.events, 0).hmac
      wrong_root = load("tree.json")["roots"]["4"]

      assert Proof.verify_inclusion(proof0, hmac0, wrong_root) ==
               {:error, :proof_verification_failed}
    end

    test "a tampered path node fails verification", ctx do
      [first | rest] = Enum.at(ctx.proofs, 0)["audit_path"]
      flipped = flip_hex(first)
      tampered = Map.put(Enum.at(ctx.proofs, 0), "audit_path", [flipped | rest])
      hmac0 = Enum.at(ctx.events, 0).hmac

      assert Proof.verify_inclusion(tampered, hmac0, ctx.root) ==
               {:error, :proof_verification_failed}
    end

    test "a truncated audit path cannot climb to the root", ctx do
      # tree_size 5 needs a three-node path; one node leaves `sn` non-zero.
      [first | _] = Enum.at(ctx.proofs, 0)["audit_path"]
      truncated = Map.put(Enum.at(ctx.proofs, 0), "audit_path", [first])
      hmac0 = Enum.at(ctx.events, 0).hmac

      assert Proof.verify_inclusion(truncated, hmac0, ctx.root) ==
               {:error, :proof_verification_failed}
    end

    test "an over-long audit path over-climbs past the root", ctx do
      # A size-3 tree: leaf 2's real path is length one; duplicating it over-climbs.
      events = Enum.take(ctx.events, 3)
      {:ok, real} = Proof.inclusion(events, 2)
      [only] = real["audit_path"]
      forged = Map.put(real, "audit_path", [only, only])
      root_3 = load("tree.json")["roots"]["3"]

      assert Proof.verify_inclusion(forged, Enum.at(events, 2).hmac, root_3) ==
               {:error, :proof_verification_failed}
    end

    test "a non-binary hmac or root is rejected", ctx do
      proof0 = Enum.at(ctx.proofs, 0)
      hmac0 = Enum.at(ctx.events, 0).hmac

      assert Proof.verify_inclusion(proof0, 123, ctx.root) == {:error, :invalid_proof}
      assert Proof.verify_inclusion(proof0, hmac0, nil) == {:error, :invalid_proof}
    end

    test "a well-formed proof with leaf_index >= tree_size is out of range", ctx do
      proof = %{
        "kind" => "sigil_guard.audit.inclusion_proof",
        "version" => 1,
        "leaf_index" => 5,
        "tree_size" => 5,
        "audit_path" => []
      }

      assert Proof.verify_inclusion(proof, Enum.at(ctx.events, 0).hmac, ctx.root) ==
               {:error, :out_of_range}
    end

    test "malformed proof objects fail :invalid_proof", ctx do
      hmac = Enum.at(ctx.events, 0).hmac
      base = Enum.at(ctx.proofs, 0)

      malformed = [
        %{},
        "not a map",
        Map.delete(base, "version"),
        Map.put(base, "extra", 1),
        Map.put(base, "kind", "sigil_guard.audit.consistency_proof"),
        Map.put(base, "version", 2),
        Map.put(base, "version", 1.0),
        Map.put(base, "leaf_index", -1),
        Map.put(base, "leaf_index", "0"),
        Map.put(base, "tree_size", 0),
        Map.put(base, "tree_size", 9_007_199_254_740_992),
        Map.put(base, "audit_path", "nope"),
        Map.put(base, "audit_path", ["short"]),
        Map.put(base, "audit_path", [String.upcase(hd(base["audit_path"]))]),
        Map.put(base, "audit_path", List.duplicate(hd(base["audit_path"]), 4))
      ]

      for proof <- malformed do
        assert Proof.verify_inclusion(proof, hmac, ctx.root) == {:error, :invalid_proof},
               "expected :invalid_proof for #{inspect(proof)}"
      end
    end
  end

  defp path(proofs, index), do: Enum.at(proofs, index)["audit_path"]

  defp flip_hex(<<first::binary-size(1), rest::binary>>) do
    flipped = if first == "0", do: "1", else: "0"
    flipped <> rest
  end
end
