defmodule SigilGuard.Audit.Proof do
  @moduledoc """
  Inclusion proofs over the existing signed audit Merkle tree (SP.05).

  A proof lets a verifier holding only a trusted checkpoint root confirm that a
  single event's `hmac` is committed by that root, without the event body or the
  rest of the chain. Proofs operate over the tree built by
  `SigilGuard.Audit.Checkpoint` with no changes: the frozen domain-separated
  `LEAF`/`NODE` construction (`sigil-audit-leaf-v1:` / `sigil-audit-node-v1:`),
  so proofs verify against unmodified 0.2.x checkpoint roots.

  Generation runs on the host holding the events; verification is pure and needs
  only the proof object, the event `hmac`, and the checkpoint `merkle_root`.
  Because leaves are HMAC outputs, a proof reveals only the target event's HMAC
  and unrelated sibling hashes.

  The verification algorithm is adapted from RFC 9162 section 2.1.3.2.
  Consistency proofs (`consistency/2`, `verify_consistency/3`) are specified in
  the same SP.05 section and land alongside the consistency-proof task.
  """

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Checkpoint

  @inclusion_kind "sigil_guard.audit.inclusion_proof"
  @version 1
  # Sizes at or above 2^53 are rejected (JSON-safe integer bound, SP.05).
  @max_size 9_007_199_254_740_992
  @inclusion_keys ~w(kind version leaf_index tree_size audit_path)
  @hex_64 ~r/\A[0-9a-f]{64}\z/

  @typedoc "An inclusion proof object (closed shape; serializes as JSON, SP.05)."
  @type inclusion_proof :: %{
          required(String.t()) => String.t() | non_neg_integer() | [String.t()]
        }

  @doc """
  Generate an inclusion proof for `leaf_index` (zero-based) over `events`.

  Returns a closed proof object whose `audit_path` is ordered leaf-to-root. Fails
  `{:error, :out_of_range}` when `leaf_index` is outside `0..length(events)-1`
  (including the empty tree) and `{:error, :unsigned_event}` when any event lacks
  an `hmac`, exactly as `SigilGuard.Audit.Checkpoint.merkle_root/1` does.
  """
  @spec inclusion([Audit.t()], non_neg_integer()) ::
          {:ok, inclusion_proof()} | {:error, :out_of_range | :unsigned_event}
  def inclusion(events, leaf_index)
      when is_list(events) and is_integer(leaf_index) and leaf_index >= 0 do
    with {:ok, leaves} <- Checkpoint.leaf_hashes(events),
         tree_size = length(leaves),
         true <- leaf_index < tree_size do
      path = audit_path(Checkpoint.levels(leaves), leaf_index)

      {:ok,
       %{
         "kind" => @inclusion_kind,
         "version" => @version,
         "leaf_index" => leaf_index,
         "tree_size" => tree_size,
         "audit_path" => Enum.map(path, &Base.encode16(&1, case: :lower))
       }}
    else
      false -> {:error, :out_of_range}
      {:error, reason} -> {:error, reason}
    end
  end

  def inclusion(_, _), do: {:error, :out_of_range}

  @doc """
  Verify an inclusion `proof` for `hmac` against a trusted checkpoint `merkle_root`.

  `merkle_root` MUST come from a checkpoint whose `event_count` equals the
  proof's `tree_size`. Follows RFC 9162 section 2.1.3.2: a malformed proof fails
  `{:error, :invalid_proof}`, `leaf_index >= tree_size` fails
  `{:error, :out_of_range}`, and a path that does not recompute `merkle_root`
  fails `{:error, :proof_verification_failed}`.
  """
  @spec verify_inclusion(map(), String.t(), String.t()) ::
          :ok | {:error, :invalid_proof | :out_of_range | :proof_verification_failed}
  def verify_inclusion(proof, hmac, merkle_root)
      when is_binary(hmac) and is_binary(merkle_root) do
    with {:ok, leaf_index, tree_size, path} <- decode_inclusion_proof(proof),
         :ok <- in_range(leaf_index, tree_size) do
      verify_path(hmac, leaf_index, tree_size, path, merkle_root)
    end
  end

  def verify_inclusion(_, _, _), do: {:error, :invalid_proof}

  # -- Generation -------------------------------------------------------------

  # Walk every level except the root, collecting the sibling of the current
  # index; an unpaired last (promoted) node contributes nothing at that level.
  defp audit_path(levels, leaf_index) do
    {_, path} =
      levels
      |> Enum.drop(-1)
      |> Enum.reduce({leaf_index, []}, fn level, {index, acc} ->
        {div(index, 2), prepend_sibling(level, index, acc)}
      end)

    Enum.reverse(path)
  end

  defp prepend_sibling(level, index, acc) do
    case sibling(level, index) do
      nil -> acc
      sib -> [sib | acc]
    end
  end

  defp sibling(level, index) do
    cond do
      rem(index, 2) == 1 -> Enum.at(level, index - 1)
      index + 1 < length(level) -> Enum.at(level, index + 1)
      true -> nil
    end
  end

  # -- Verification -----------------------------------------------------------

  defp verify_path(hmac, leaf_index, tree_size, path, merkle_root) do
    seed = {:ok, {Checkpoint.leaf_hash(hmac), leaf_index, tree_size - 1}}

    case Enum.reduce_while(path, seed, &fold_node/2) do
      {:ok, {root, _, sn}} -> finalize(root, sn, merkle_root)
      {:error, reason} -> {:error, reason}
    end
  end

  defp fold_node(_, {:ok, {_, _, 0}}), do: {:halt, {:error, :proof_verification_failed}}

  defp fold_node(p, {:ok, {r, fn_, sn}}) do
    result =
      if rem(fn_, 2) == 1 or fn_ == sn do
        {fn2, sn2} = shift_until_odd(fn_, sn)
        {Checkpoint.node_hash(p, r), fn2, sn2}
      else
        {Checkpoint.node_hash(r, p), fn_, sn}
      end

    {node, fn3, sn3} = result
    {:cont, {:ok, {node, div(fn3, 2), div(sn3, 2)}}}
  end

  defp finalize(root, 0, merkle_root) do
    if Base.encode16(root, case: :lower) == merkle_root do
      :ok
    else
      {:error, :proof_verification_failed}
    end
  end

  defp finalize(_, _, _), do: {:error, :proof_verification_failed}

  # Right-shift `fn` and `sn` together while `fn` is even and non-zero.
  defp shift_until_odd(fn_, sn) when rem(fn_, 2) == 0 and fn_ != 0,
    do: shift_until_odd(div(fn_, 2), div(sn, 2))

  defp shift_until_odd(fn_, sn), do: {fn_, sn}

  # -- Proof object validation (closed shape) ---------------------------------

  defp decode_inclusion_proof(proof) when is_map(proof) do
    with true <- closed_keys?(proof, @inclusion_keys),
         %{"kind" => @inclusion_kind, "version" => @version} <- proof,
         {:ok, leaf_index} <- fetch_size(proof, "leaf_index", 0),
         {:ok, tree_size} <- fetch_size(proof, "tree_size", 1),
         {:ok, path} <- fetch_path(proof, tree_size) do
      {:ok, leaf_index, tree_size, path}
    else
      _ -> {:error, :invalid_proof}
    end
  end

  defp decode_inclusion_proof(_), do: {:error, :invalid_proof}

  defp closed_keys?(map, allowed), do: Enum.sort(Map.keys(map)) == Enum.sort(allowed)

  defp fetch_size(proof, key, min) do
    case Map.fetch(proof, key) do
      {:ok, value} when is_integer(value) and value >= min and value < @max_size -> {:ok, value}
      _ -> :error
    end
  end

  defp fetch_path(proof, tree_size) do
    with list when is_list(list) <- Map.get(proof, "audit_path"),
         true <- length(list) <= max_path_length(tree_size),
         {:ok, decoded} <- decode_hex_list(list) do
      {:ok, decoded}
    else
      _ -> :error
    end
  end

  defp decode_hex_list(list) do
    result =
      Enum.reduce_while(list, {:ok, []}, fn entry, {:ok, acc} ->
        if is_binary(entry) and Regex.match?(@hex_64, entry) do
          {:cont, {:ok, [Base.decode16!(entry, case: :lower) | acc]}}
        else
          {:halt, :error}
        end
      end)

    case result do
      {:ok, acc} -> {:ok, Enum.reverse(acc)}
      :error -> :error
    end
  end

  defp in_range(leaf_index, tree_size) when leaf_index < tree_size, do: :ok
  defp in_range(_, _), do: {:error, :out_of_range}

  # ceil(log2(tree_size)): the maximum leaf-to-root audit-path length.
  defp max_path_length(tree_size), do: bit_length(tree_size - 1)

  defp bit_length(0), do: 0
  defp bit_length(n) when n > 0, do: bit_length(div(n, 2)) + 1
end
