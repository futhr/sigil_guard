defmodule SigilGuard.Audit.Witness do
  @moduledoc """
  Witness cosigning and threshold verification for audit checkpoints.

  Cosigning lets independent witnesses co-attest a checkpoint so verification no
  longer rests on the operator's key alone. It is optional, offline-compatible,
  and additive: witnesses append a `{keyid, sig}` entry over the **identical**
  DSSE PAE bytes of the operator's checkpoint-state statement
  (`SigilGuard.Audit.Checkpoint.to_statement/1`), never modifying the payload or
  the existing signatures.

  When a witness holds a previously cosigned checkpoint for the same chain, it
  passes it as `:previous` and `cosign/3` verifies a consistency proof from that
  checkpoint to this one before appending; a failed proof refuses the
  cosignature with the proof's error. With no prior checkpoint the witness
  records this one as its baseline (trust-on-first-checkpoint) - the caller owns
  that persistence, and verifying the operator signature against the witness's
  own trust material is the witness's responsibility around this call.

  `verify_threshold/3` counts the distinct witness keyids from a named key set
  whose signatures verify; a bad or unresolved witness signature is not
  counted, duplicate key IDs are rejected, and fewer than
  `threshold` valid signatures produces `:witness_threshold_not_met`.
  Thresholds are opt-in: an unwitnessed
  single-signature checkpoint stays valid where no threshold policy applies.
  """

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Proof

  @typedoc "A prior cosigned checkpoint: its statement and a consistency proof to the current one."
  @type previous :: %{
          required(:statement) => map(),
          required(:consistency_proof) => map()
        }

  @doc """
  Cosign a checkpoint-state DSSE `envelope` with a witness `signer`.

  Options:

    * `:keyid` - explicit witness key id (defaults to the signer's derived id).
    * `:previous` - `%{statement: prior_statement, consistency_proof: proof}`; when
      present, the consistency proof from the prior checkpoint to this one MUST
      verify first, else the cosignature is refused with the proof's error.

  Appends the witness signature over the envelope's identical PAE bytes without
  modifying the payload. A key id already present fails `:duplicate_keyid`.
  """
  @spec cosign(map(), module(), keyword()) ::
          {:ok, map()}
          | {:error,
             :invalid_envelope
             | :invalid_payload_type
             | :invalid_base64
             | :duplicate_keyid
             | :invalid_signer
             | :invalid_proof
             | :out_of_range
             | :inconsistent_tree}
  def cosign(envelope, signer, opts \\ [])

  def cosign(envelope, signer, opts)
      when is_map(envelope) and is_atom(signer) and is_list(opts) do
    with {:ok, state} <- envelope_statement_state(envelope),
         :ok <- verify_previous(state, Keyword.get(opts, :previous)) do
      Envelope.add_signature(envelope, signer, Keyword.take(opts, [:keyid]))
    end
  end

  def cosign(_, _, _), do: {:error, :invalid_envelope}

  @doc """
  Verify that at least `threshold` distinct witness keyids cosigned `envelope`.

  `witness_keys` maps witness key ids to their public keys. Only key ids whose
  signatures verify over the envelope's PAE are counted; unresolved or invalid
  witness signatures are ignored. Fewer than `threshold` verified key ids
  produces `:witness_threshold_not_met`; a structurally invalid envelope
  surfaces the DSSE error. Returns the sorted verified key ids on success.
  """
  @spec verify_threshold(map(), %{optional(String.t()) => binary()}, pos_integer()) ::
          {:ok, %{verified_keyids: [String.t()]}}
          | {:error,
             :witness_threshold_not_met
             | :invalid_envelope
             | :invalid_payload_type
             | :invalid_base64
             | :duplicate_keyid}
  def verify_threshold(envelope, witness_keys, threshold)
      when is_map(envelope) and is_map(witness_keys) and is_integer(threshold) and threshold >= 1 do
    case structural_check(Envelope.verify(envelope, witness_keys)) do
      :ok ->
        verified = verified_keyids(envelope, witness_keys)

        if length(verified) >= threshold do
          {:ok, %{verified_keyids: verified}}
        else
          {:error, :witness_threshold_not_met}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp verify_previous(_, nil), do: :ok

  defp verify_previous(current, %{statement: previous, consistency_proof: proof})
       when is_map(previous) and is_map(proof) do
    with {:ok, prior} <- Checkpoint.statement_state(previous),
         :ok <- Proof.verify_consistency(proof, prior.root, current.root) do
      if prior.chain_id === current.chain_id and
           proof["first_size"] === prior.size and proof["second_size"] === current.size,
         do: :ok,
         else: {:error, :inconsistent_tree}
    end
  end

  defp verify_previous(_, _), do: {:error, :invalid_proof}

  defp envelope_statement_state(envelope) do
    with {:ok, decoded} <- Envelope.decode(envelope),
         {:ok, statement} <- SigilGuard.Canonical.JSON.decode(decoded.payload),
         {:ok, state} <- Checkpoint.statement_state(statement) do
      {:ok, state}
    else
      _ -> {:error, :invalid_envelope}
    end
  end

  # A signature-verification outcome means the envelope is well-formed enough to
  # count per keyid; a structural DSSE error is surfaced as-is.
  defp structural_check({:ok, _}), do: :ok
  defp structural_check({:error, :invalid_signature}), do: :ok
  defp structural_check({:error, :unknown_key_id}), do: :ok
  defp structural_check({:error, reason}), do: {:error, reason}

  defp verified_keyids(envelope, witness_keys) do
    witness_keys
    |> Enum.filter(fn {keyid, key} -> signature_verifies?(envelope, keyid, key) end)
    |> Enum.map(fn {keyid, _} -> keyid end)
    |> Enum.sort()
  end

  defp signature_verifies?(envelope, keyid, key) do
    match?({:ok, _}, Envelope.verify(envelope, %{keyid => key}))
  end
end
