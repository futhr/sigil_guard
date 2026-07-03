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

  alias SigilGuard.ConfigError
  alias SigilGuard.Telemetry
  alias SigilGuard.TrustBundle.Cache
  alias SigilGuard.TrustBundle.Quarantine
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

  def load(source, opts) when is_list(opts) do
    Telemetry.span([:sigil_guard, :trust_bundle, :load], load_metadata(source), fn ->
      result = do_load(source, opts)
      {result, load_metadata(result, source)}
    end)
  end

  def load(_, _), do: {:error, :invalid_source}

  defp do_load({:map, envelope}, opts) when is_map(envelope) do
    load_envelope(envelope, {:map, envelope}, opts)
  end

  defp do_load({:binary, bytes}, opts) when is_binary(bytes) do
    load_binary(bytes, {:binary, bytes}, opts)
  end

  # sobelow_skip ["Traversal.FileModule"]
  defp do_load({:file, path}, opts) when is_binary(path) do
    case File.read(path) do
      {:ok, bytes} -> load_binary(bytes, {:file, path}, opts)
      {:error, _} -> quarantine_error(:invalid_source, %{source: {:file, path}}, opts)
    end
  end

  # sobelow_skip ["Traversal.FileModule"]
  defp do_load({:priv, app, rel}, opts) when is_atom(app) and is_binary(rel) do
    path = Application.app_dir(app, Path.join("priv", rel))

    case File.read(path) do
      {:ok, bytes} -> load_binary(bytes, {:priv, app, rel}, opts)
      {:error, _} -> quarantine_error(:invalid_source, %{source: {:priv, app, rel}}, opts)
    end
  rescue
    ArgumentError -> quarantine_error(:invalid_source, %{source: {:priv, app, rel}}, opts)
  end

  defp do_load(:none, opts),
    do: quarantine_error(:invalid_source, %{source: :none}, opts)

  defp do_load(source, opts),
    do: quarantine_error(:invalid_source, %{source: source}, opts)

  @doc false
  @spec load_configured!(keyword(), keyword()) :: :ok | no_return()
  def load_configured!(config, opts \\ [])

  def load_configured!(config, opts) when is_list(config) and is_list(opts) do
    config
    |> Keyword.get(:trust_bundle, :none)
    |> load_configured_source!(opts)
  end

  def load_configured!(_, _) do
    raise ConfigError.new(:trust_bundle, :invalid_config, "expected validated configuration")
  end

  defp load_binary(bytes, source, opts) do
    case Jason.decode(bytes) do
      {:ok, envelope} when is_map(envelope) ->
        load_envelope(envelope, source, opts)

      _ ->
        quarantine_error(:invalid_source, %{source: source}, opts)
    end
  end

  defp load_envelope(envelope, source, opts) do
    envelope
    |> verify(Keyword.put_new(opts, :source, source))
    |> cache_loaded(opts)
  end

  defp cache_loaded({:ok, bundle}, opts) do
    if Keyword.get(opts, :cache, true) do
      case Cache.put(bundle) do
        {:ok, _} -> {:ok, bundle}
        {:error, reason} -> quarantine_error(reason, cache_error_info(bundle), opts)
      end
    else
      {:ok, bundle}
    end
  end

  defp cache_loaded({:error, _} = error, _), do: error

  defp cache_error_info(bundle) do
    %{
      bundle_id: bundle.bundle_id,
      bundle_digest: bundle.digest,
      sequence: bundle.sequence,
      document: bundle.document,
      envelope: bundle.envelope
    }
  end

  defp load_configured_source!(:none, _), do: :ok

  defp load_configured_source!(source, opts) do
    case load(source, opts) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        raise ConfigError.new(
                :trust_bundle,
                :invalid_config,
                "configured trust bundle failed with #{inspect(reason)}"
              )
    end
  end

  @doc """
  Verify a decoded DSSE trust-bundle envelope.

  This verifies the envelope, schema, bundle role, signature threshold,
  revocations, and freshness checks implemented in SP.02. Loading sources,
  cache rollback checks, quarantine records, and rotation-chain walking are
  staged in later trust-bundle modules.
  """
  @spec verify(envelope :: map(), opts :: keyword()) :: {:ok, t()} | {:error, verify_error()}
  def verify(envelope, opts \\ [])

  def verify(envelope, opts) when is_list(opts) do
    Telemetry.span([:sigil_guard, :trust_bundle, :verify], verify_metadata(envelope), fn ->
      result = do_verify(envelope, opts)
      {result, verify_metadata(result, envelope)}
    end)
  end

  def verify(_, _), do: {:error, :invalid_bundle_format}

  defp do_verify(envelope, opts) do
    case Verify.verify(envelope, opts) do
      {:ok, bundle} -> {:ok, bundle}
      {:error, reason} -> quarantine_error(reason, %{envelope: envelope}, opts)
    end
  end

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

  defp load_metadata(source) do
    %{source: source_kind(source), bundle_id: nil, result: nil, error: nil, dev: false}
  end

  defp load_metadata({:ok, bundle}, _) do
    %{
      source: source_kind(bundle.source),
      bundle_id: bundle.bundle_id,
      result: :ok,
      error: nil,
      dev: bundle.dev?
    }
  end

  defp load_metadata({:error, reason}, source) do
    %{source: source_kind(source), bundle_id: nil, result: :error, error: reason, dev: false}
  end

  defp verify_metadata(envelope) do
    envelope
    |> envelope_document()
    |> verify_document_metadata()
    |> Map.merge(%{result: nil, error: nil})
  end

  defp verify_metadata({:ok, bundle}, _) do
    %{
      bundle_id: bundle.bundle_id,
      sequence: bundle.sequence,
      root_version: bundle.root_version,
      result: :ok,
      error: nil
    }
  end

  defp verify_metadata({:error, reason}, envelope) do
    envelope
    |> envelope_document()
    |> verify_document_metadata()
    |> Map.merge(%{result: :error, error: reason})
  end

  defp verify_document_metadata(%{"bundle_id" => bundle_id} = document) do
    %{
      bundle_id: bundle_id,
      sequence: positive_integer(Map.get(document, "sequence")),
      root_version: positive_integer(get_in(document, ["roles", "root", "version"]))
    }
  end

  defp verify_document_metadata(_), do: %{bundle_id: nil, sequence: nil, root_version: nil}

  defp envelope_document(%{} = envelope) do
    with payload when is_binary(payload) <-
           Map.get(envelope, "payload") || Map.get(envelope, :payload),
         {:ok, bytes} <- decode_base64(payload),
         {:ok, %{} = document} <- Jason.decode(bytes) do
      document
    else
      _ -> nil
    end
  end

  defp envelope_document(_), do: nil

  defp decode_base64(value) when is_binary(value) do
    [
      &Base.url_decode64(&1, padding: false),
      &Base.url_decode64(&1, padding: true),
      &Base.decode64(&1, padding: false),
      &Base.decode64(&1, padding: true)
    ]
    |> Enum.reduce_while(:error, fn decoder, :error ->
      case decoder.(value) do
        {:ok, bytes} -> {:halt, {:ok, bytes}}
        :error -> {:cont, :error}
      end
    end)
  end

  defp positive_integer(value) when is_binary(value) do
    case Integer.parse(value) do
      {integer, ""} when integer > 0 -> integer
      _ -> nil
    end
  end

  defp positive_integer(_), do: nil

  defp source_kind(:dev), do: :dev
  defp source_kind({:file, _}), do: :file
  defp source_kind({:priv, _, _}), do: :priv
  defp source_kind({:map, _}), do: :map
  defp source_kind({:binary, _}), do: :binary
  defp source_kind(:none), do: :none
  defp source_kind(_), do: :invalid

  defp quarantine_error(reason, info, opts) do
    if Keyword.get(opts, :quarantine, true) do
      Quarantine.record(reason, quarantine_info(info, opts))
    end

    {:error, reason}
  end

  defp quarantine_info(info, opts) do
    opts
    |> Keyword.take([:evidence, :now])
    |> Map.new()
    |> Map.merge(info)
  end
end
