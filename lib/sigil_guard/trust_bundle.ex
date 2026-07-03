defmodule SigilGuard.TrustBundle do
  @moduledoc """
  Public API shell for embedded SigilGuard trust bundles.

  Trust bundles are local, DSSE-signed JSON documents. The full schema,
  role-threshold verification, cache, quarantine, and development bootstrap
  behavior are implemented in the staged `TrustBundle.*` modules. Until those
  stages are present this module fails closed for unverified input while
  exposing the stable struct, source type, error taxonomy, and section
  accessors from SP.02.
  """

  alias SigilGuard.TrustBundle.Verify

  @typedoc "Closed set of supported trust-bundle loading sources."
  @type source ::
          :none
          | {:file, Path.t()}
          | {:priv, atom(), String.t()}
          | {:map, map()}
          | {:binary, binary()}

  @typedoc "SP.01 envelope errors reused by trust-bundle verification."
  @type shared_envelope_error ::
          :invalid_envelope
          | :invalid_payload_type
          | :invalid_base64
          | :duplicate_keyid
          | :unsupported_number_range

  @typedoc "Trust-bundle verification errors."
  @type verify_error ::
          shared_envelope_error()
          | :invalid_bundle_format
          | :unsupported_profile_version
          | :unknown_role
          | :unknown_key_id
          | :invalid_signature
          | :threshold_not_met
          | :bundle_expired
          | :role_expired
          | :revoked_key
          | :sequence_below_floor
          | :forked_root_chain
          | :rotation_below_threshold

  @typedoc "Trust-bundle loading errors."
  @type load_error :: verify_error() | :invalid_source

  @typedoc "Verified embedded trust-bundle snapshot."
  @type t :: %__MODULE__{
          bundle_id: String.t(),
          sequence: pos_integer(),
          root_version: pos_integer(),
          digest: String.t(),
          document: map(),
          envelope: map(),
          dev?: boolean(),
          source: source() | :dev
        }

  defstruct bundle_id: nil,
            sequence: nil,
            root_version: nil,
            digest: nil,
            document: %{},
            envelope: %{},
            dev?: false,
            source: nil

  @doc """
  Load and verify a trust bundle from a source.
  """
  @spec load(source()) :: {:ok, t()} | {:error, load_error()}
  @spec load(source(), keyword()) :: {:ok, t()} | {:error, load_error()}
  def load(source, opts \\ [])

  def load({:map, envelope}, opts) when is_map(envelope) and is_list(opts) do
    verify(envelope, Keyword.put_new(opts, :source, {:map, envelope}))
  end

  def load({:binary, bytes}, opts) when is_binary(bytes) and is_list(opts) do
    case Jason.decode(bytes) do
      {:ok, envelope} when is_map(envelope) ->
        verify(envelope, Keyword.put_new(opts, :source, {:binary, bytes}))

      _ ->
        {:error, :invalid_source}
    end
  end

  def load({:file, path}, opts) when is_binary(path) and is_list(opts),
    do: {:error, :invalid_source}

  def load({:priv, app, rel}, opts) when is_atom(app) and is_binary(rel) and is_list(opts),
    do: {:error, :invalid_source}

  def load(:none, opts) when is_list(opts), do: {:error, :invalid_source}
  def load(_, _), do: {:error, :invalid_source}

  @doc """
  Verify a decoded DSSE trust-bundle envelope.

  This verifies the envelope, schema, bundle role, signature threshold,
  revocations, and freshness checks implemented in SP.02. Loading sources,
  cache rollback checks, quarantine records, and rotation-chain walking are
  staged in later trust-bundle modules.
  """
  @spec verify(envelope :: map(), opts :: keyword()) :: {:ok, t()} | {:error, verify_error()}
  def verify(envelope, opts \\ [])
  def verify(envelope, opts) when is_list(opts), do: Verify.verify(envelope, opts)
  def verify(_, _), do: {:error, :invalid_bundle_format}

  @doc """
  Build, sign, verify, and cache a development-only trust bundle.

  The bootstrap implementation lands with the dedicated SP.02 development
  bundle task. Until then the API fails closed.
  """
  @spec dev_bundle(keyword()) :: {:ok, t()} | {:error, load_error()}
  def dev_bundle(opts \\ [])
  def dev_bundle(opts) when is_list(opts), do: {:error, :invalid_bundle_format}
  def dev_bundle(_), do: {:error, :invalid_bundle_format}

  @doc "Return verified scanner pattern sections, or an empty list when absent."
  @spec patterns(t()) :: [term()]
  def patterns(%__MODULE__{document: document}), do: list_section(document, "patterns")

  @doc "Return verified policy sections, or an empty list when absent."
  @spec policies(t()) :: [term()]
  def policies(%__MODULE__{document: document}), do: list_section(document, "policies")

  @doc "Return verified tool sections, or an empty list when absent."
  @spec tools(t()) :: [term()]
  def tools(%__MODULE__{document: document}), do: list_section(document, "tools")

  @doc "Return verified identity issuer sections, or an empty list when absent."
  @spec identity_issuers(t()) :: [term()]
  def identity_issuers(%__MODULE__{document: document}),
    do: list_section(document, "identity_issuers")

  defp list_section(document, key) when is_map(document) do
    case Map.fetch(document, key) do
      {:ok, section} when is_list(section) -> section
      _ -> []
    end
  end
end
