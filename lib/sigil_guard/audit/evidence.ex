defmodule SigilGuard.Audit.Evidence do
  @moduledoc """
  Audit evidence references binding attestations to audit artifacts (SP.01, SP.05).

  An evidence ref is the SP.01 shape `%{"kind" => "checkpoint" | "export" |
  "anchor", "ref" => digest}`, where `ref` is the artifact's `digest/1`. Refs are
  carried in an attestation predicate's `evidence` list and in a signed audit
  event's `metadata["evidence"]`, so a decision, its attestation, and its audit
  event all point at the same checkpoint/export/anchor.

  `ref/2` builds a ref from an artifact, `validate/1` checks a ref list's shape,
  and `resolve/2` confirms every ref resolves to one of the supplied artifacts -
  a ref whose `(kind, digest)` matches no artifact is a dangling ref
  (`:dangling_evidence_ref`), which detects tampered or missing evidence.
  """

  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Checkpoint
  alias SigilGuard.Audit.Export

  @kinds ~w(checkpoint export anchor)
  @kind_atoms [:checkpoint, :export, :anchor]

  @typedoc "An audit artifact kind referenced by evidence."
  @type kind :: :checkpoint | :export | :anchor

  @typedoc "An SP.01 evidence reference: a `kind` and the artifact's `ref` digest."
  @type ref :: %{required(String.t()) => String.t()}

  @doc """
  Build an evidence ref for an audit `artifact` of the given `kind`.

  The `ref` is the artifact's `digest/1` (`SigilGuard.Audit.Checkpoint`,
  `SigilGuard.Audit.Export`, or `SigilGuard.Audit.Anchor`).
  """
  @spec ref(kind(), map()) :: ref()
  def ref(kind, artifact) when kind in @kind_atoms and is_map(artifact) do
    %{"kind" => Atom.to_string(kind), "ref" => digest(kind, artifact)}
  end

  @doc """
  Validate that `refs` is a list of well-formed evidence references.

  Fails `{:error, :invalid_evidence}` unless every entry is a map with a `kind`
  in `checkpoint`/`export`/`anchor` and a non-empty binary `ref`.
  """
  @spec validate(term()) :: :ok | {:error, :invalid_evidence}
  def validate(refs) when is_list(refs) do
    if Enum.all?(refs, &valid_ref?/1), do: :ok, else: {:error, :invalid_evidence}
  end

  def validate(_), do: {:error, :invalid_evidence}

  @doc """
  Confirm every ref in `refs` resolves to one of the supplied `artifacts`.

  `artifacts` is a list of `{kind, artifact}` tuples. A ref whose `(kind, ref)`
  digest matches no artifact fails `{:error, :dangling_evidence_ref}`; a
  malformed ref list fails `{:error, :invalid_evidence}`.
  """
  @spec resolve(term(), [{kind(), map()}]) ::
          :ok | {:error, :invalid_evidence | :dangling_evidence_ref}
  def resolve(refs, artifacts) when is_list(refs) and is_list(artifacts) do
    with :ok <- validate(refs) do
      resolve_all(refs, known_digests(artifacts))
    end
  end

  def resolve(_, _), do: {:error, :invalid_evidence}

  defp known_digests(artifacts) do
    MapSet.new(artifacts, fn {kind, artifact} ->
      {Atom.to_string(kind), digest(kind, artifact)}
    end)
  end

  defp resolve_all(refs, known) do
    if Enum.all?(refs, fn ref -> MapSet.member?(known, {ref["kind"], ref["ref"]}) end) do
      :ok
    else
      {:error, :dangling_evidence_ref}
    end
  end

  defp digest(:checkpoint, artifact), do: Checkpoint.digest(artifact)
  defp digest(:export, artifact), do: Export.digest(artifact)
  defp digest(:anchor, artifact), do: Anchor.digest(artifact)

  defp valid_ref?(%{"kind" => kind, "ref" => ref})
       when kind in @kinds and is_binary(ref) and ref != "",
       do: true

  defp valid_ref?(_), do: false
end
