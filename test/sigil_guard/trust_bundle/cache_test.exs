defmodule SigilGuard.TrustBundle.CacheTest do
  @moduledoc false

  use ExUnit.Case, async: false
  use ExUnitProperties

  alias SigilGuard.TrustBundle
  alias SigilGuard.TrustBundle.Cache

  setup do
    Cache.clear()
    :ok
  end

  describe "ensure_table/0" do
    test "creates the named trust-bundle ETS table" do
      assert Cache.ensure_table() == :ok
      assert :ets.whereis(:sigil_guard_trust_bundle) != :undefined
    end
  end

  describe "put/1 and get/1" do
    test "accepts the first snapshot and advances the floor" do
      bundle = bundle(sequence: 3, rollback_floor: 2)

      assert Cache.floor("example-org-trust") == 0
      assert Cache.put(bundle) == {:ok, bundle}
      assert Cache.get("example-org-trust") == {:ok, bundle}
      assert Cache.floor("example-org-trust") == 3
    end

    test "treats a same-sequence same-digest re-put as a no-op" do
      original = bundle(sequence: 3, digest: "same")
      duplicate = bundle(sequence: 3, digest: "same", envelope: %{"payload" => "different"})

      assert Cache.put(original) == {:ok, original}
      assert Cache.put(duplicate) == {:ok, original}
      assert Cache.get("example-org-trust") == {:ok, original}
      assert Cache.floor("example-org-trust") == 3
    end

    test "rejects lower sequence, lower floor, and same-sequence different-digest bundles" do
      assert Cache.put(bundle(sequence: 5, rollback_floor: 5, digest: "first")) ==
               {:ok, bundle(sequence: 5, rollback_floor: 5, digest: "first")}

      assert Cache.put(bundle(sequence: 4, rollback_floor: 4, digest: "older")) ==
               {:error, :sequence_below_floor}

      assert Cache.put(bundle(sequence: 5, rollback_floor: 5, digest: "fork")) ==
               {:error, :sequence_below_floor}

      assert Cache.floor("example-org-trust") == 5
      assert Cache.get("missing") == :error
      assert Cache.floor("missing") == 0
    end

    test "rejects root versions below the accepted root version" do
      accepted = bundle(sequence: 5, root_version: 3, digest: "root-v3")
      stale_root = bundle(sequence: 6, root_version: 2, digest: "root-v2")
      advancing_root = bundle(sequence: 6, root_version: 4, digest: "root-v4")

      assert Cache.put(accepted) == {:ok, accepted}
      assert Cache.put(stale_root) == {:error, :sequence_below_floor}
      assert Cache.get("example-org-trust") == {:ok, accepted}
      assert Cache.put(advancing_root) == {:ok, advancing_root}
      assert Cache.get("example-org-trust") == {:ok, advancing_root}
    end

    test "accepts an advancing sequence and keeps the floor monotonic" do
      first = bundle(sequence: 2, rollback_floor: 1)
      second = bundle(sequence: 6, rollback_floor: 4)

      assert Cache.put(first) == {:ok, first}
      assert Cache.floor("example-org-trust") == 2
      assert Cache.put(second) == {:ok, second}
      assert Cache.floor("example-org-trust") == 6
      assert Cache.get("example-org-trust") == {:ok, second}
    end
  end

  describe "properties" do
    property "accepted snapshots never lower the floor" do
      check all(steps <- StreamData.list_of(snapshot_step(), min_length: 1, max_length: 20)) do
        Cache.clear()

        {_, floors} =
          Enum.reduce(steps, {nil, []}, fn {sequence, rollback_floor}, {_, floors} ->
            result = Cache.put(bundle(sequence: sequence, rollback_floor: rollback_floor))
            floor = Cache.floor("example-org-trust")

            {result, [floor | floors]}
          end)

        floors = Enum.reverse(floors)
        assert floors == Enum.sort(floors)
      end
    end
  end

  defp bundle(opts) do
    sequence = Keyword.fetch!(opts, :sequence)
    rollback_floor = Keyword.get(opts, :rollback_floor, sequence)

    %TrustBundle{
      bundle_id: Keyword.get(opts, :bundle_id, "example-org-trust"),
      sequence: sequence,
      root_version: Keyword.get(opts, :root_version, 1),
      digest: Keyword.get(opts, :digest, "digest-#{sequence}-#{rollback_floor}"),
      document: %{
        "rollback_floor" => Integer.to_string(rollback_floor),
        "sequence" => Integer.to_string(sequence)
      },
      envelope: Keyword.get(opts, :envelope, %{}),
      dev?: false,
      source: :none
    }
  end

  defp snapshot_step do
    StreamData.bind(StreamData.integer(1..40), fn sequence ->
      StreamData.map(StreamData.integer(1..sequence), &{sequence, &1})
    end)
  end
end
