defmodule SigilGuard.Audit.ProofTest do
  @moduledoc false

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Proof
  alias SigilGuard.AuditProofFixture, as: Fixture

  # The anchor root from audit's five-event golden vector; pinned as a literal so
  # a change to leaf/node hashing is caught even if the fixture regenerates.
  @root_5 "14ba3acb7050e49d3f2c3d633a8057ef39d936281298fb23fe215c774179aa0b"

  defp load(name), do: Jason.decode!(File.read!(Fixture.path(name)))

  describe "golden vectors (audit five-event tree)" do
    test "committed fixtures regenerate byte-identically" do
      assert File.read!(Fixture.path("events.json")) == Fixture.events_json()
      assert File.read!(Fixture.path("tree.json")) == Fixture.tree_json()
      assert File.read!(Fixture.path("inclusion_5.json")) == Fixture.inclusion_json()
      assert File.read!(Fixture.path("consistency_3_5.json")) == Fixture.consistency_json(3)
      assert File.read!(Fixture.path("consistency_4_5.json")) == Fixture.consistency_json(4)
      assert File.read!(Fixture.path("checkpoint_5.json")) == Fixture.checkpoint_json()
      assert File.read!(Fixture.path("expected.json")) == Fixture.expected_json()
      assert File.read!(Fixture.path("export.json")) == Fixture.export_json()
    end

    test "the committed export package verifies with the embedded evidence" do
      export = load("export.json")
      pk = Base.url_encode64(Fixture.signer().public_key(), padding: false)

      assert {:ok, _} =
               SigilGuard.Audit.Export.verify(export, Fixture.signed_events(),
                 public_key_b64u: pk
               )

      assert Enum.map(export["inclusion_proofs"], & &1["leaf_index"]) == [0, 1, 2, 3, 4]
      assert export["consistency_proof"]["first_size"] == 3
      assert export["checkpoint_statement"]["payloadType"] == "application/vnd.sigilguard+json"
    end

    test "the checkpoint-state statement matches the committed golden vector" do
      {:ok, statement} = Checkpoint.to_statement(Fixture.checkpoint())
      assert statement == load("expected.json")["checkpoint_statement"]
      assert statement["predicate"]["merkle_root"] == @root_5
      assert statement["predicate"]["tree_size"] == "5"
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

    test "the committed inclusion proofs match the audit path table" do
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

  describe "consistency/2 generation" do
    test "the committed proofs match the audit node table" do
      tree = load("tree.json")
      [_, _, h2, h3, _] = tree["leaves"]
      h4 = tree["nodes"]["H4"]
      n01 = tree["nodes"]["N01"]

      assert load("consistency_3_5.json")["proof_nodes"] == [h2, h3, n01, h4]
      assert load("consistency_4_5.json")["proof_nodes"] == [h4]
    end

    test "reproduces the committed proofs" do
      events = Fixture.signed_events()
      assert {:ok, proof3} = Proof.consistency(events, 3)
      assert {:ok, proof4} = Proof.consistency(events, 4)
      assert proof3 == load("consistency_3_5.json")
      assert proof4 == load("consistency_4_5.json")
    end

    test "a first size outside 1..length is out of range" do
      events = Fixture.signed_events()
      assert Proof.consistency(events, 0) == {:error, :out_of_range}
      assert Proof.consistency(events, 6) == {:error, :out_of_range}
      assert Proof.consistency([], 1) == {:error, :out_of_range}
    end

    test "an unsigned event fails :unsigned_event" do
      events = Fixture.signed_events()
      %Audit{} = last = List.last(events)
      unsigned = %{last | hmac: nil}
      assert Proof.consistency(Enum.concat(events, [unsigned]), 3) == {:error, :unsigned_event}
    end
  end

  describe "verify_consistency/3" do
    setup do
      %{events: Fixture.signed_events(), roots: load("tree.json")["roots"]}
    end

    test "the 3-to-5, 4-to-5, and 5-to-5 vectors verify", ctx do
      for first <- [3, 4, 5] do
        {:ok, proof} = Proof.consistency(ctx.events, first)

        assert Proof.verify_consistency(
                 proof,
                 ctx.roots[Integer.to_string(first)],
                 ctx.roots["5"]
               ) == :ok
      end
    end

    test "an equal-size proof requires matching roots and empty nodes", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 5)
      assert Proof.verify_consistency(proof, ctx.roots["5"], ctx.roots["5"]) == :ok

      # Equal sizes with different roots is an inconsistent (forked) tree.
      assert Proof.verify_consistency(proof, ctx.roots["5"], ctx.roots["4"]) ==
               {:error, :inconsistent_tree}

      # Equal sizes MUST carry no proof nodes.
      nonempty = Map.put(proof, "proof_nodes", [ctx.roots["5"]])

      assert Proof.verify_consistency(nonempty, ctx.roots["5"], ctx.roots["5"]) ==
               {:error, :invalid_proof}
    end

    test "a forked newer root fails :inconsistent_tree", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 3)

      assert Proof.verify_consistency(proof, ctx.roots["3"], ctx.roots["4"]) ==
               {:error, :inconsistent_tree}

      assert Proof.verify_consistency(proof, ctx.roots["4"], ctx.roots["5"]) ==
               {:error, :inconsistent_tree}
    end

    test "a tampered proof node fails :inconsistent_tree", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 3)
      [first | rest] = proof["proof_nodes"]
      tampered = Map.put(proof, "proof_nodes", [flip_hex(first) | rest])

      assert Proof.verify_consistency(tampered, ctx.roots["3"], ctx.roots["5"]) ==
               {:error, :inconsistent_tree}
    end

    test "first_size outside 1..second_size is out of range", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 3)

      oob = %{
        "kind" => "sigil_guard.audit.consistency_proof",
        "version" => 1,
        "first_size" => 0,
        "second_size" => 5,
        "proof_nodes" => proof["proof_nodes"]
      }

      assert Proof.verify_consistency(oob, ctx.roots["3"], ctx.roots["5"]) ==
               {:error, :out_of_range}

      bigger_first = Map.merge(oob, %{"first_size" => 6, "second_size" => 5})

      assert Proof.verify_consistency(bigger_first, ctx.roots["5"], ctx.roots["5"]) ==
               {:error, :out_of_range}
    end

    test "malformed consistency proofs fail :invalid_proof", ctx do
      base = load("consistency_3_5.json")

      malformed = [
        %{},
        "not a map",
        Map.delete(base, "proof_nodes"),
        Map.put(base, "extra", 1),
        Map.put(base, "kind", "sigil_guard.audit.inclusion_proof"),
        Map.put(base, "version", 2),
        Map.put(base, "first_size", "3"),
        Map.put(base, "second_size", 9_007_199_254_740_992),
        Map.put(base, "proof_nodes", "nope"),
        Map.put(base, "proof_nodes", ["short"]),
        # A strictly-older first tree cannot carry an empty node list.
        Map.put(base, "proof_nodes", [])
      ]

      for proof <- malformed do
        assert Proof.verify_consistency(proof, ctx.roots["3"], ctx.roots["5"]) ==
                 {:error, :invalid_proof},
               "expected :invalid_proof for #{inspect(proof)}"
      end
    end

    test "a non-binary root is rejected", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 3)
      assert Proof.verify_consistency(proof, nil, ctx.roots["5"]) == {:error, :invalid_proof}
      assert Proof.verify_consistency(proof, ctx.roots["3"], 5) == {:error, :invalid_proof}
    end

    test "a power-of-two first size with an unparseable first root is inconsistent", ctx do
      # first_size 4 prepends the (here malformed) first root before climbing.
      {:ok, proof} = Proof.consistency(ctx.events, 4)
      bad_root = String.duplicate("z", 64)

      assert Proof.verify_consistency(proof, bad_root, ctx.roots["5"]) ==
               {:error, :inconsistent_tree}
    end

    test "a truncated node list cannot reconstruct the roots", ctx do
      # 3-to-5 needs four nodes; dropping one leaves `sn` non-zero.
      {:ok, proof} = Proof.consistency(ctx.events, 3)
      short = Map.update!(proof, "proof_nodes", fn nodes -> Enum.drop(nodes, -1) end)

      assert Proof.verify_consistency(short, ctx.roots["3"], ctx.roots["5"]) ==
               {:error, :invalid_proof}
    end

    test "an over-long node list over-consumes the proof", ctx do
      {:ok, proof} = Proof.consistency(ctx.events, 3)

      long =
        Map.update!(proof, "proof_nodes", fn nodes -> Enum.concat(nodes, [List.last(nodes)]) end)

      assert Proof.verify_consistency(long, ctx.roots["3"], ctx.roots["5"]) ==
               {:error, :invalid_proof}
    end
  end

  describe "promotion-tree and RFC equality properties" do
    test "the promotion tree root equals the RFC 9162 root for every size 1..256" do
      events = build_chain(256)
      {:ok, leaves} = Checkpoint.leaf_hashes(events)

      for size <- 1..256 do
        {:ok, promotion} = Checkpoint.merkle_root(Enum.take(events, size))
        assert Base.encode16(rfc_root(Enum.take(leaves, size)), case: :lower) == promotion
      end
    end

    property "consistency proofs round-trip for random m <= n" do
      events = build_chain(256)

      check all(n <- integer(1..256), m <- integer(1..n), max_runs: 200) do
        segment = Enum.take(events, n)
        {:ok, proof} = Proof.consistency(segment, m)
        {:ok, first_root} = Checkpoint.merkle_root(Enum.take(events, m))
        {:ok, second_root} = Checkpoint.merkle_root(segment)
        assert Proof.verify_consistency(proof, first_root, second_root) == :ok
      end
    end

    property "inclusion proofs round-trip for random leaf in a random tree" do
      events = build_chain(256)

      check all(n <- integer(1..256), i <- integer(0..(n - 1)), max_runs: 200) do
        segment = Enum.take(events, n)
        {:ok, proof} = Proof.inclusion(segment, i)
        {:ok, root} = Checkpoint.merkle_root(segment)
        assert Proof.verify_inclusion(proof, Enum.at(segment, i).hmac, root) == :ok
      end
    end
  end

  # A deterministic n-event signed chain for the size properties.
  defp build_chain(n) do
    {events, _} =
      Enum.reduce(1..n, {[], nil}, fn i, {acc, prev} ->
        event = %Audit{
          id: Integer.to_string(i),
          type: "runtime.gate",
          actor: "actor",
          action: "x",
          result: "allow",
          timestamp: "2026-07-02T12:00:00.000Z"
        }

        signed = Audit.sign_event(event, "sigil-guard-audit-property-key", prev)
        {[signed | acc], signed.hmac}
      end)

    Enum.reverse(events)
  end

  # Independent RFC 9162 recursive Merkle root over leaf hashes.
  defp rfc_root([leaf]), do: leaf

  defp rfc_root(leaves) do
    k = rfc_split(length(leaves))
    Checkpoint.node_hash(rfc_root(Enum.take(leaves, k)), rfc_root(Enum.drop(leaves, k)))
  end

  defp rfc_split(n), do: rfc_split(1, n)
  defp rfc_split(p, n) when p * 2 < n, do: rfc_split(p * 2, n)
  defp rfc_split(p, _), do: p

  defp path(proofs, index), do: Enum.at(proofs, index)["audit_path"]

  defp flip_hex(<<first::binary-size(1), rest::binary>>) do
    flipped = if first == "0", do: "1", else: "0"
    flipped <> rest
  end
end
