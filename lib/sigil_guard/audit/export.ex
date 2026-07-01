defmodule SigilGuard.Audit.Export do
  @moduledoc """
  Portable audit checkpoint export package.

  An export packages a checkpoint with optional Ed25519 provenance and an
  optional external anchor record. It is the object a deployment can write to
  append-only or WORM storage while keeping raw audit events local.
  """

  alias SigilGuard.Audit
  alias SigilGuard.Audit.Anchor
  alias SigilGuard.Audit.Checkpoint

  @kind "sigil_guard.audit.export"
  @version 1
  @atom_fields %{
    "anchor" => :anchor,
    "checkpoint" => :checkpoint,
    "generated_at" => :generated_at,
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
         {:ok, anchor} <- maybe_anchor(checkpoint, opts) do
      {:ok,
       %{
         "kind" => @kind,
         "version" => @version,
         "generated_at" => Keyword.get_lazy(opts, :generated_at, &timestamp/0),
         "checkpoint" => checkpoint,
         "anchor" => anchor
       }}
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
         {:ok, anchor_status} <- verify_anchor(export, checkpoint, opts) do
      {:ok,
       %{
         export: export,
         checkpoint: checkpoint_status,
         anchor: anchor_status,
         digest: digest(export)
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
        {:ok, Anchor.create(checkpoint)}

      anchor_opts when is_list(anchor_opts) ->
        {:ok, Anchor.create(checkpoint, anchor_opts)}

      anchor_opts when is_map(anchor_opts) ->
        {:ok, Anchor.create(checkpoint, anchor_opts(anchor_opts))}

      _ ->
        {:error, :invalid_anchor_options}
    end
  end

  defp anchor_opts(anchor_opts) do
    Enum.flat_map(anchor_opts, fn
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

  defp require_field(map, key, value, reason) do
    if field(map, key) == value, do: :ok, else: {:error, reason}
  end

  defp require_binary(value, _) when is_binary(value) and value != "", do: :ok
  defp require_binary(_, reason), do: {:error, reason}

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
