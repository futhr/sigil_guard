defmodule SigilGuard.Audit.Export do
  @moduledoc """
  Portable audit checkpoint export package.

  An export packages a checkpoint with optional Ed25519 provenance and an
  optional external anchor record. It is the object a deployment can write to
  append-only or WORM storage while keeping raw audit events local.
  """

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Proof
  alias SigilGuard.Canonical.JCS

  @kind "sigil_guard.audit.export"
  @version 1
  @atom_fields %{
    "anchor" => :anchor,
    "checkpoint" => :checkpoint,
    "checkpoint_statement" => :checkpoint_statement,
    "consistency_proof" => :consistency_proof,
    "generated_at" => :generated_at,
    "inclusion_proofs" => :inclusion_proofs,
    "kind" => :kind,
    "version" => :version
  }

  @type t :: %{required(String.t()) => term()}

  @type verified :: %{
          export: t(),
          checkpoint: Checkpoint.verified(),
          anchor: Anchor.verified() | nil,
          digest: String.t()
        }

  @doc """
  Create an export package from a signed audit chain segment.

  Options:

    * `:chain_id`, `:prev_hmac`, `:metadata`, `:generated_at` - passed to
      `SigilGuard.Audit.Checkpoint.create/2`.
    * `:checkpoint_anchor` - optional checkpoint-local anchor metadata.
    * `:signer`, `:issuer`, `:issued_at` - sign the checkpoint when supplied.
    * `:anchor` - `true`, a keyword list, or map to include an external anchor
      record created with `SigilGuard.Audit.Anchor.create/2`.
    * `:checkpoint_statement` - when `true`, embed the DSSE checkpoint-state
      envelope (`SigilGuard.Audit.Checkpoint.to_statement/1` signed with
      `:signer`; requires `:signer`).
    * `:inclusion_proofs` - `:all` or a list of zero-based leaf indices to embed
      `SigilGuard.Audit.Proof.inclusion/2` proofs.
    * `:consistency_proof` - a `first_size` to embed a
      `SigilGuard.Audit.Proof.consistency/2` proof.

  The three evidence keys are optional and additive: a package created without
  them is byte-identical to a 0.2.x export (D17).
  """
  @spec create([Audit.t()], keyword()) :: {:ok, t()} | {:error, atom()}
  def create(events, opts \\ [])

  def create(events, opts) when is_list(events) and is_list(opts) do
    checkpoint_opts =
      opts
      |> Keyword.take([:chain_id, :prev_hmac, :metadata, :generated_at])
      |> put_checkpoint_anchor(opts)

    with {:ok, checkpoint} <- Checkpoint.create(events, checkpoint_opts),
         {:ok, checkpoint} <- maybe_sign_checkpoint(checkpoint, opts),
         {:ok, anchor} <- maybe_anchor(checkpoint, opts),
         {:ok, statement} <- maybe_statement(checkpoint, opts),
         {:ok, inclusion} <- maybe_inclusion_proofs(events, opts),
         {:ok, consistency} <- maybe_consistency_proof(events, opts) do
      base = %{
        "kind" => @kind,
        "version" => @version,
        "generated_at" => Keyword.get_lazy(opts, :generated_at, &timestamp/0),
        "checkpoint" => checkpoint,
        "anchor" => anchor
      }

      {:ok, put_evidence(base, statement, inclusion, consistency)}
    end
  end

  def create(_, _), do: {:error, :invalid_events}

  @doc """
  Verify an export package against the local signed audit events.

  Options are forwarded to `SigilGuard.Audit.Checkpoint.verify/3`. Set
  `:require_signature` to require Ed25519 checkpoint provenance and
  `:require_anchor` to require an anchor record.
  """
  @spec verify(t(), [Audit.t()], keyword()) :: {:ok, verified()} | {:error, atom()}
  def verify(export, events, opts \\ [])

  def verify(export, events, opts) when is_map(export) and is_list(events) and is_list(opts) do
    with :ok <- verify_static_fields(export),
         {:ok, checkpoint} <- export_checkpoint(export),
         {:ok, checkpoint_status} <- Checkpoint.verify(checkpoint, events, opts),
         {:ok, anchor_status} <- verify_anchor(export, checkpoint, opts),
         :ok <- verify_evidence(export, checkpoint, events),
         {:ok, export_digest} <- safe_digest(export) do
      {:ok,
       %{
         export: export,
         checkpoint: checkpoint_status,
         anchor: anchor_status,
         digest: export_digest
       }}
    end
  end

  def verify(_, _, _), do: {:error, :invalid_export}

  @doc """
  Return canonical export bytes used for digesting.
  """
  @spec canonical_bytes(t()) :: binary()
  def canonical_bytes(export) when is_map(export) do
    export
    |> canonical_iodata()
    |> IO.iodata_to_binary()
  end

  @doc """
  Return the lowercase SHA-256 digest of canonical export bytes.
  """
  @spec digest(t()) :: String.t()
  def digest(export) when is_map(export) do
    export
    |> canonical_bytes()
    |> then(&:crypto.hash(:sha256, &1))
    |> Base.encode16(case: :lower)
  end

  defp put_checkpoint_anchor(checkpoint_opts, opts) do
    case Keyword.fetch(opts, :checkpoint_anchor) do
      {:ok, anchor} -> Keyword.put(checkpoint_opts, :anchor, anchor)
      :error -> checkpoint_opts
    end
  end

  defp maybe_sign_checkpoint(checkpoint, opts) do
    case Keyword.fetch(opts, :signer) do
      {:ok, signer} -> {:ok, Checkpoint.sign(checkpoint, signer, signer_opts(opts))}
      :error -> {:ok, checkpoint}
    end
  rescue
    KeyError -> {:error, :missing_issuer}
  end

  defp signer_opts(opts) do
    opts
    |> Keyword.take([:issuer, :issued_at])
    |> Keyword.put_new_lazy(:issued_at, &timestamp/0)
  end

  defp maybe_anchor(checkpoint, opts) do
    case Keyword.get(opts, :anchor, false) do
      false ->
        {:ok, nil}

      nil ->
        {:ok, nil}

      true ->
        create_anchor(checkpoint, [])

      anchor_opts when is_list(anchor_opts) ->
        create_anchor(checkpoint, anchor_opts)

      anchor_opts when is_map(anchor_opts) ->
        create_anchor(checkpoint, normalize_anchor_map(anchor_opts))

      _ ->
        {:error, :invalid_anchor_options}
    end
  end

  defp create_anchor(checkpoint, opts) do
    anchor = Anchor.create(checkpoint, opts)

    case Anchor.validate(anchor) do
      :ok -> {:ok, anchor}
      {:error, reason} -> {:error, reason}
    end
  end

  # Only present evidence keys are added, so an export without them stays
  # byte-identical to a 0.2.x package (D17).
  defp put_evidence(base, statement, inclusion, consistency) do
    base
    |> maybe_put("checkpoint_statement", statement)
    |> maybe_put("inclusion_proofs", inclusion)
    |> maybe_put("consistency_proof", consistency)
  end

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp maybe_statement(checkpoint, opts) do
    if Keyword.get(opts, :checkpoint_statement, false) do
      build_statement_envelope(checkpoint, opts)
    else
      {:ok, nil}
    end
  end

  defp build_statement_envelope(checkpoint, opts) do
    with {:ok, signer} <- statement_signer(opts),
         {:ok, statement} <- Checkpoint.to_statement(checkpoint),
         {:ok, payload} <- JCS.encode(statement) do
      Envelope.sign(payload, signer)
    end
  end

  defp statement_signer(opts) do
    case Keyword.get(opts, :signer) do
      signer when is_atom(signer) and not is_nil(signer) -> {:ok, signer}
      _ -> {:error, :missing_signer}
    end
  end

  defp maybe_inclusion_proofs(events, opts) do
    case Keyword.get(opts, :inclusion_proofs) do
      nil -> {:ok, nil}
      :all -> inclusion_proofs(events, 0..(length(events) - 1))
      indices when is_list(indices) -> inclusion_proofs(events, indices)
      _ -> {:error, :invalid_inclusion_proofs}
    end
  end

  defp inclusion_proofs(events, indices) do
    result =
      Enum.reduce_while(indices, {:ok, []}, fn index, {:ok, acc} ->
        case Proof.inclusion(events, index) do
          {:ok, proof} -> {:cont, {:ok, [proof | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, proofs} -> {:ok, Enum.reverse(proofs)}
      error -> error
    end
  end

  defp maybe_consistency_proof(events, opts) do
    case Keyword.get(opts, :consistency_proof) do
      nil -> {:ok, nil}
      first_size when is_integer(first_size) -> Proof.consistency(events, first_size)
      _ -> {:error, :invalid_consistency_proof}
    end
  end

  defp normalize_anchor_map(map) do
    Enum.flat_map(map, fn
      {key, value} when key in [:anchored_at, "anchored_at"] -> [anchored_at: value]
      {key, value} when key in [:storage, "storage"] -> [storage: value]
      {key, value} when key in [:uri, "uri"] -> [uri: value]
      {key, value} when key in [:worm, "worm"] -> [worm: value]
      {key, value} when key in [:metadata, "metadata"] -> [metadata: value]
      _ -> []
    end)
  end

  defp verify_static_fields(export) do
    with :ok <- require_field(export, "kind", @kind, :invalid_kind),
         :ok <- require_field(export, "version", @version, :invalid_version) do
      require_binary(field(export, "generated_at"), :missing_generated_at)
    end
  end

  defp export_checkpoint(export) do
    case field(export, "checkpoint") do
      checkpoint when is_map(checkpoint) -> {:ok, checkpoint}
      _ -> {:error, :missing_checkpoint}
    end
  end

  defp verify_anchor(export, checkpoint, opts) do
    case field(export, "anchor") do
      nil ->
        if Keyword.get(opts, :require_anchor, false) do
          {:error, :missing_anchor}
        else
          {:ok, nil}
        end

      anchor when is_map(anchor) ->
        Anchor.verify(anchor, checkpoint)

      _ ->
        {:error, :invalid_anchor}
    end
  end

  # Validate the optional evidence keys against the verified checkpoint. Absent
  # keys are a no-op; a present statement must digest the same checkpoint and a
  # present inclusion proof must recompute the checkpoint's Merkle root.
  defp verify_evidence(export, checkpoint, events) do
    with :ok <- verify_statement_evidence(export, checkpoint) do
      verify_inclusion_evidence(export, checkpoint, events)
    end
  end

  defp verify_statement_evidence(export, checkpoint) do
    case field(export, "checkpoint_statement") do
      nil -> :ok
      envelope when is_map(envelope) -> match_statement_digest(envelope, checkpoint)
      _ -> {:error, :invalid_checkpoint_statement}
    end
  end

  defp match_statement_digest(envelope, checkpoint) do
    with {:ok, subject_digest} <- statement_subject_digest(envelope) do
      if subject_digest == Checkpoint.digest(checkpoint) do
        :ok
      else
        {:error, :statement_mismatch}
      end
    end
  end

  defp statement_subject_digest(envelope) do
    with payload when is_binary(payload) <- Map.get(envelope, "payload"),
         {:ok, bytes} <- Base.url_decode64(payload, padding: false),
         {:ok, decoded} <- Jason.decode(bytes),
         digest when is_binary(digest) <- subject_digest(decoded) do
      {:ok, digest}
    else
      _ -> {:error, :invalid_checkpoint_statement}
    end
  end

  defp subject_digest(%{"subject" => [%{"digest" => %{"sha256" => digest}} | _]}), do: digest
  defp subject_digest(_), do: nil

  defp verify_inclusion_evidence(export, checkpoint, events) do
    case field(export, "inclusion_proofs") do
      nil -> :ok
      proofs when is_list(proofs) -> verify_each_inclusion(proofs, checkpoint, events)
      _ -> {:error, :invalid_inclusion_proofs}
    end
  end

  defp verify_each_inclusion(proofs, checkpoint, events) do
    # Read the root tolerantly (string or atom key), like the rest of the module.
    root = Map.get(checkpoint, "merkle_root") || Map.get(checkpoint, :merkle_root)

    Enum.reduce_while(proofs, :ok, fn proof, :ok ->
      case verify_one_inclusion(proof, root, events) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp verify_one_inclusion(proof, root, events) when is_map(proof) and is_binary(root) do
    case event_hmac(events, Map.get(proof, "leaf_index")) do
      hmac when is_binary(hmac) -> Proof.verify_inclusion(proof, hmac, root)
      _ -> {:error, :invalid_inclusion_proof}
    end
  end

  defp verify_one_inclusion(_, _, _), do: {:error, :invalid_inclusion_proof}

  defp event_hmac(events, index) when is_integer(index) and index >= 0 do
    case Enum.at(events, index) do
      %Audit{hmac: hmac} -> hmac
      _ -> nil
    end
  end

  defp event_hmac(_, _), do: nil

  defp require_field(map, key, value, reason) do
    if field(map, key) == value, do: :ok, else: {:error, reason}
  end

  defp require_binary(value, _) when is_binary(value) and value != "", do: :ok
  defp require_binary(_, reason), do: {:error, reason}

  defp safe_digest(export) do
    {:ok, digest(export)}
  rescue
    _ in [ArgumentError, FunctionClauseError, Jason.EncodeError, Protocol.UndefinedError] ->
      {:error, :invalid_export}
  end

  defp field(map, key) when is_map(map) do
    case Map.fetch(map, key) do
      {:ok, value} -> value
      :error -> Map.get(map, Map.fetch!(@atom_fields, key))
    end
  end

  defp timestamp do
    DateTime.utc_now(:millisecond)
    |> DateTime.to_iso8601()
  end

  defp canonical_iodata(value) when is_map(value) do
    value
    |> Enum.map(fn {key, item} -> {canonical_key(key), item} end)
    |> Enum.sort_by(fn {key, _} -> key end)
    |> Enum.map(fn {key, item} -> [Jason.encode!(key), ?:, canonical_iodata(item)] end)
    |> Enum.intersperse(",")
    |> then(&[?{, &1, ?}])
  end

  defp canonical_iodata(value) when is_list(value) do
    value
    |> Enum.map(&canonical_iodata/1)
    |> Enum.intersperse(",")
    |> then(&[?[, &1, ?]])
  end

  defp canonical_iodata(value)
       when is_binary(value) or is_number(value) or is_boolean(value) or is_nil(value) do
    Jason.encode!(value)
  end

  defp canonical_iodata(value) when is_atom(value) do
    value
    |> Atom.to_string()
    |> Jason.encode!()
  end

  defp canonical_iodata(value), do: Jason.encode!(value)

  defp canonical_key(key) when is_atom(key), do: Atom.to_string(key)
  defp canonical_key(key) when is_binary(key), do: key
  defp canonical_key(key), do: to_string(key)
end
