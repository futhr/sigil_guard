defmodule SigilGuard.Audit.Proof do
  @moduledoc """
  Inclusion proofs over signed audit Merkle trees.

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

  Inclusion verification is adapted from RFC 9162 section 2.1.3.2 and
  consistency verification from section 2.1.4.2. A consistency proof shows the
  size-`m` tree is an unmodified prefix of the size-`n` tree; a truncated or
  forked newer chain fails `:inconsistent_tree`.
  """

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Checkpoint

  @inclusion_kind "sigil_guard.audit.inclusion_proof"
  @consistency_kind "sigil_guard.audit.consistency_proof"
  @version 1
  # Reject sizes at or above 2^53 so proofs remain exact JSON integers.
  @max_size 9_007_199_254_740_992
  @inclusion_keys ~w(kind version leaf_index tree_size audit_path)
  @consistency_keys ~w(kind version first_size second_size proof_nodes)
  @hex_64 ~r/\A[0-9a-f]{64}\z/

  @typedoc "A closed, JSON-serializable inclusion proof."
  @type inclusion_proof :: %{
          required(String.t()) => String.t() | non_neg_integer() | [String.t()]
        }

  @typedoc "A closed, JSON-serializable consistency proof."
  @type consistency_proof :: %{
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
    with {:ok, [proof]} <- inclusions(events, [leaf_index]), do: {:ok, proof}
  end

  def inclusion(_, _), do: {:error, :out_of_range}

  @doc false
  @spec inclusions([Audit.t()], Enumerable.t()) ::
          {:ok, [inclusion_proof()]} | {:error, :out_of_range | :unsigned_event}
  def inclusions(events, indices) do
    with {:ok, leaves} <- Checkpoint.leaf_hashes(events) do
      levels =
        leaves
        |> Checkpoint.levels()
        |> Enum.drop(-1)
        |> Enum.map(&List.to_tuple/1)

      proofs_for_indices(indices, levels, length(leaves))
    end
  end

  defp proofs_for_indices(indices, levels, size) do
    result =
      Enum.reduce_while(indices, {:ok, []}, fn index, {:ok, acc} ->
        if is_integer(index) and index >= 0 and index < size do
          {:cont, {:ok, [inclusion_proof(levels, index, size) | acc]}}
        else
          {:halt, {:error, :out_of_range}}
        end
      end)

    case result do
      {:ok, proofs} -> {:ok, Enum.reverse(proofs)}
      error -> error
    end
  end

  defp inclusion_proof(levels, index, size) do
    %{
      "kind" => @inclusion_kind,
      "version" => @version,
      "leaf_index" => index,
      "tree_size" => size,
      "audit_path" => Enum.map(audit_path(levels, index), &Base.encode16(&1, case: :lower))
    }
  end

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

  @doc """
  Generate a consistency proof from `first_size` to the full `events` tree.

  Proves the `first_size`-event tree is an unmodified prefix of the current
  `length(events)`-event tree. Fails `{:error, :out_of_range}` when `first_size`
  is outside `1..length(events)` and `{:error, :unsigned_event}` when any event
  lacks an `hmac`.
  """
  @spec consistency([Audit.t()], pos_integer()) ::
          {:ok, consistency_proof()} | {:error, :out_of_range | :unsigned_event}
  def consistency(events, first_size)
      when is_list(events) and is_integer(first_size) and first_size >= 1 do
    with {:ok, leaves} <- Checkpoint.leaf_hashes(events),
         second_size = length(leaves),
         true <- first_size <= second_size do
      nodes = subproof(first_size, leaves, true)

      {:ok,
       %{
         "kind" => @consistency_kind,
         "version" => @version,
         "first_size" => first_size,
         "second_size" => second_size,
         "proof_nodes" => Enum.map(nodes, &Base.encode16(&1, case: :lower))
       }}
    else
      false -> {:error, :out_of_range}
      {:error, reason} -> {:error, reason}
    end
  end

  def consistency(_, _), do: {:error, :out_of_range}

  @doc """
  Verify a consistency `proof` between two trusted checkpoint roots.

  Follows RFC 9162 section 2.1.4.2: a malformed proof fails
  `{:error, :invalid_proof}`, `first_size` outside `1..second_size` fails
  `{:error, :out_of_range}`, and a proof whose recomputed roots do not match
  both `first_root` and `second_root` fails `{:error, :inconsistent_tree}` (a
  truncated or forked newer chain).
  """
  @spec verify_consistency(map(), String.t(), String.t()) ::
          :ok | {:error, :invalid_proof | :out_of_range | :inconsistent_tree}
  def verify_consistency(proof, first_root, second_root)
      when is_binary(first_root) and is_binary(second_root) do
    with {:ok, first_size, second_size, nodes} <- decode_consistency_proof(proof),
         :ok <- consistency_in_range(first_size, second_size) do
      verify_consistency_sizes(first_size, second_size, nodes, first_root, second_root)
    end
  end

  def verify_consistency(_, _, _), do: {:error, :invalid_proof}

  # Walk every level except the root, collecting the sibling of the current
  # index; an unpaired last (promoted) node contributes nothing at that level.
  defp audit_path(levels, leaf_index) do
    {_, path} =
      Enum.reduce(levels, {leaf_index, []}, fn level, {index, acc} ->
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
      rem(index, 2) == 1 -> elem(level, index - 1)
      index + 1 < tuple_size(level) -> elem(level, index + 1)
      true -> nil
    end
  end

  # RFC 9162 2.1.4.1 SUBPROOF over the promotion tree (root-equal to the RFC
  # split construction for sizes 1..256). `m` is the older size, `leaves`
  # the newer leaf hashes, `b` the "on the boundary" flag.
  defp subproof(m, leaves, b) do
    n = length(leaves)

    cond do
      m == n and b -> []
      m == n -> [subtree_root(leaves)]
      m <= largest_pow2_below(n) -> left_subproof(m, leaves, b)
      true -> right_subproof(m, leaves)
    end
  end

  defp left_subproof(m, leaves, b) do
    k = largest_pow2_below(length(leaves))
    Enum.concat(subproof(m, Enum.take(leaves, k), b), [subtree_root(Enum.drop(leaves, k))])
  end

  defp right_subproof(m, leaves) do
    k = largest_pow2_below(length(leaves))

    Enum.concat(subproof(m - k, Enum.drop(leaves, k), false), [subtree_root(Enum.take(leaves, k))])
  end

  defp subtree_root(leaves) do
    leaves
    |> Checkpoint.levels()
    |> List.last()
    |> hd()
  end

  # Largest power of two strictly less than `n` (`n >= 2`).
  defp largest_pow2_below(n), do: pow2_below(1, n)

  defp pow2_below(p, n) when p * 2 < n, do: pow2_below(p * 2, n)
  defp pow2_below(p, _), do: p

  defp verify_path(hmac, leaf_index, tree_size, path, merkle_root) do
    seed = {:ok, {Checkpoint.leaf_hash(hmac), leaf_index, tree_size - 1}}

    case Enum.reduce_while(path, seed, &fold_node/2) do
      {:ok, {root, _, sn}} -> finalize(root, sn, merkle_root)
      {:error, reason} -> {:error, reason}
    end
  end

  defp fold_node(_, {:ok, {_, _, 0}}), do: {:halt, {:error, :proof_verification_failed}}

  defp fold_node(p, {:ok, {r, fn_, sn}}) do
    {node, fn2, sn2} =
      if rem(fn_, 2) == 1 or fn_ == sn do
        {f, s} = shift_until_odd(fn_, sn)
        {Checkpoint.node_hash(p, r), f, s}
      else
        {Checkpoint.node_hash(r, p), fn_, sn}
      end

    {:cont, {:ok, {node, div(fn2, 2), div(sn2, 2)}}}
  end

  defp finalize(root, 0, merkle_root) do
    if Base.encode16(root, case: :lower) == merkle_root do
      :ok
    else
      {:error, :proof_verification_failed}
    end
  end

  defp finalize(_, _, _), do: {:error, :proof_verification_failed}

  # Right-shift `fn` and `sn` together until `fn` is odd; the `!= 0` guard stops
  # at `fn == 0` (also even) rather than recurring forever.
  defp shift_until_odd(fn_, sn) when rem(fn_, 2) == 0 and fn_ != 0,
    do: shift_until_odd(div(fn_, 2), div(sn, 2))

  defp shift_until_odd(fn_, sn), do: {fn_, sn}

  defp consistency_in_range(first_size, second_size)
       when first_size >= 1 and first_size <= second_size,
       do: :ok

  defp consistency_in_range(_, _), do: {:error, :out_of_range}

  # Step 3: equal sizes prove consistency only when the roots already match.
  defp verify_consistency_sizes(size, size, nodes, first_root, second_root) do
    cond do
      nodes != [] -> {:error, :invalid_proof}
      first_root == second_root -> :ok
      true -> {:error, :inconsistent_tree}
    end
  end

  # Steps 4-11: a strictly older first tree.
  defp verify_consistency_sizes(first_size, second_size, nodes, first_root, second_root) do
    with {:ok, nodes} <- non_empty(nodes),
         {:ok, nodes} <- maybe_prepend_root(first_size, nodes, first_root) do
      run_consistency(first_size, second_size, nodes, first_root, second_root)
    end
  end

  defp non_empty([]), do: {:error, :invalid_proof}
  defp non_empty(nodes), do: {:ok, nodes}

  # Step 5: a power-of-two first size prepends the (decoded) first root.
  defp maybe_prepend_root(first_size, nodes, first_root) do
    if power_of_two?(first_size) do
      case Base.decode16(first_root, case: :lower) do
        {:ok, bin} -> {:ok, [bin | nodes]}
        :error -> {:error, :inconsistent_tree}
      end
    else
      {:ok, nodes}
    end
  end

  defp run_consistency(first_size, second_size, [first_node | rest], first_root, second_root) do
    {fn0, sn0} = shift_while_odd(first_size - 1, second_size - 1)
    seed = {:ok, {first_node, first_node, fn0, sn0}}

    case Enum.reduce_while(rest, seed, &fold_consistency/2) do
      {:ok, {fr, sr, _, sn}} -> finalize_consistency(fr, sr, sn, first_root, second_root)
      {:error, reason} -> {:error, reason}
    end
  end

  defp fold_consistency(_, {:ok, {_, _, _, 0}}), do: {:halt, {:error, :invalid_proof}}

  defp fold_consistency(c, {:ok, {fr, sr, fn_, sn}}) do
    {fr2, sr2, fn2, sn2} =
      if rem(fn_, 2) == 1 or fn_ == sn do
        {f3, s3} = shift_until_odd(fn_, sn)
        {Checkpoint.node_hash(c, fr), Checkpoint.node_hash(c, sr), f3, s3}
      else
        {fr, Checkpoint.node_hash(sr, c), fn_, sn}
      end

    {:cont, {:ok, {fr2, sr2, div(fn2, 2), div(sn2, 2)}}}
  end

  defp finalize_consistency(fr, sr, 0, first_root, second_root) do
    if Base.encode16(fr, case: :lower) == first_root and
         Base.encode16(sr, case: :lower) == second_root do
      :ok
    else
      {:error, :inconsistent_tree}
    end
  end

  defp finalize_consistency(_, _, _, _, _), do: {:error, :invalid_proof}

  # Step 7: right-shift `fn` and `sn` together while `fn` is odd.
  defp shift_while_odd(fn_, sn) when rem(fn_, 2) == 1,
    do: shift_while_odd(div(fn_, 2), div(sn, 2))

  defp shift_while_odd(fn_, sn), do: {fn_, sn}

  defp power_of_two?(1), do: true
  defp power_of_two?(n) when n > 1 and rem(n, 2) == 0, do: power_of_two?(div(n, 2))
  defp power_of_two?(_), do: false

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

  defp decode_consistency_proof(proof) when is_map(proof) do
    with true <- closed_keys?(proof, @consistency_keys),
         %{"kind" => @consistency_kind, "version" => @version} <- proof,
         {:ok, first_size} <- fetch_int(proof, "first_size"),
         {:ok, second_size} <- fetch_int(proof, "second_size"),
         {:ok, nodes} <- fetch_nodes(proof) do
      {:ok, first_size, second_size, nodes}
    else
      _ -> {:error, :invalid_proof}
    end
  end

  defp decode_consistency_proof(_), do: {:error, :invalid_proof}

  defp closed_keys?(map, allowed), do: Enum.sort(Map.keys(map)) == Enum.sort(allowed)

  defp fetch_size(proof, key, min) do
    case Map.fetch(proof, key) do
      {:ok, value} when is_integer(value) and value >= min and value < @max_size -> {:ok, value}
      _ -> :error
    end
  end

  # The `first_size < 1` / `first_size > second_size` relationships are checked
  # separately (`:out_of_range`); here only the JSON-safe integer bound applies.
  defp fetch_int(proof, key) do
    case Map.fetch(proof, key) do
      {:ok, value} when is_integer(value) and value < @max_size -> {:ok, value}
      _ -> :error
    end
  end

  defp fetch_nodes(proof) do
    with list when is_list(list) <- Map.get(proof, "proof_nodes"),
         {:ok, decoded} <- decode_hex_list(list) do
      {:ok, decoded}
    else
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
