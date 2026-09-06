defmodule SigilGuard.TrustBundle do
  @moduledoc """
  Public API shell for embedded SigilGuard trust bundles.

  Trust bundles are local, DSSE-signed JSON documents. The full schema,
  role-threshold verification, cache, quarantine, and development bootstrap
  behavior are implemented in the staged `TrustBundle.*` modules. Core
  verification never fetches remote material; hosts own any transport and pass
  verified bytes, maps, files, or `priv/` sources into this API.

  ## Examples

      {:ok, bundle} = SigilGuard.TrustBundle.dev_bundle(cache: false)
      bundle.dev?
      # => true

      source = {:map, bundle.envelope}
      {:ok, loaded} = SigilGuard.TrustBundle.load(source, cache: false)
      loaded.bundle_id == bundle.bundle_id
  """

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.ConfigError
  alias SigilGuard.PatternSets
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

  @typedoc "Attestation-envelope errors reused by trust-bundle verification."
  @type shared_envelope_error ::
          :invalid_envelope
          | :invalid_payload_type
          | :invalid_base64
          | :duplicate_keyid

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
    if Keyword.keyword?(opts) do
      Telemetry.span([:sigil_guard, :trust_bundle, :load], load_metadata(source), fn ->
        result = do_load(source, opts)
        {result, load_metadata(result, source)}
      end)
    else
      {:error, :invalid_source}
    end
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
    decoded = with :ok <- SigilGuard.Limits.check(bytes), do: Jason.decode(bytes)

    case decoded do
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
  revocations, and freshness checks for the complete trust bundle.

  ## Options

    * `:now` - `DateTime` used for freshness checks. Defaults to current UTC
      time.
    * `:max_skew_ms` - accepted future clock skew for bundle and role expiry.
      Defaults to `60_000`.
    * `:enforce_declared_threshold` - when `true`, enforce the bundle role's
      declared threshold. For compatibility, the 1.0 release line defaults to an effective
      threshold of `1`; bundle documents still carry their declared threshold,
      and root rotation documents always enforce full declared old-root and
      new-root thresholds.
    * `:quarantine` - when `true`, records failed verification attempts in
      `SigilGuard.TrustBundle.Quarantine`. Defaults to `true`.
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

  This helper is for development and tests only. It creates a short-lived
  bundle with `provenance.issuer_class` set to `"dev"`.

      iex> seed = :binary.copy(<<1>>, 32)
      ...> {:ok, bundle} = SigilGuard.TrustBundle.dev_bundle(seed: seed, cache: false)
      ...> {bundle.dev?, bundle.source, bundle.sequence, bundle.root_version}
      {true, :dev, 1, 1}
  """
  @spec dev_bundle(keyword()) :: {:ok, t()} | {:error, load_error()}
  def dev_bundle(opts \\ [])

  def dev_bundle(opts) when is_list(opts) do
    with {:ok, seed} <- dev_seed(opts),
         {:ok, now} <- dev_now(opts),
         {:ok, ttl_ms} <- dev_ttl_ms(opts),
         {:ok, sections} <- dev_sections(opts),
         {:ok, envelope} <- dev_envelope(seed, now, ttl_ms, sections) do
      load({:map, envelope}, dev_load_opts(opts))
    end
  end

  def dev_bundle(_), do: {:error, :invalid_bundle_format}

  @doc "Return verified scanner pattern sections, or an empty list when absent."
  @spec patterns(t()) :: [term()]
  def patterns(%__MODULE__{document: document}), do: list_section(document, "patterns")

  @doc """
  Resolve the verified `patterns` section into the three runtime pattern sets.

  Routes the bundle's `patterns` entries through `SigilGuard.PatternSets.resolve/1`:
  each `set` (`secret`, `injection`, `poisoning`) is independently overridable and
  an absent set keeps its built-in default. A malformed entry fails closed with
  `{:error, :invalid_pattern_set}`. An absent section resolves to all built-ins.
  """
  @spec pattern_sets(t()) :: {:ok, PatternSets.t()} | {:error, :invalid_pattern_set}
  def pattern_sets(%__MODULE__{} = bundle), do: PatternSets.resolve(patterns(bundle))

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

  defp dev_seed(opts) do
    case Keyword.get_lazy(opts, :seed, fn -> :crypto.strong_rand_bytes(32) end) do
      seed when is_binary(seed) and byte_size(seed) == 32 -> {:ok, seed}
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp dev_now(opts) do
    case Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now(:millisecond) end) do
      %DateTime{} = now -> {:ok, DateTime.truncate(now, :millisecond)}
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp dev_ttl_ms(opts) do
    case Keyword.get(opts, :ttl_ms, 3_600_000) do
      ttl_ms when is_integer(ttl_ms) and ttl_ms > 0 -> {:ok, ttl_ms}
      _ -> {:error, :invalid_bundle_format}
    end
  end

  defp dev_sections(opts) do
    [:patterns, :policies, :tools, :identity_issuers]
    |> Enum.reduce_while({:ok, %{}}, fn key, {:ok, sections} ->
      case Keyword.fetch(opts, key) do
        {:ok, section} when is_list(section) ->
          {:cont, {:ok, Map.put(sections, to_string(key), section)}}

        {:ok, _} ->
          {:halt, {:error, :invalid_bundle_format}}

        :error ->
          {:cont, {:ok, sections}}
      end
    end)
  end

  defp dev_load_opts(opts) do
    opts
    |> Keyword.put(:source, :dev)
    |> Keyword.put(:quarantine, false)
  end

  defp dev_envelope(seed, now, ttl_ms, sections) do
    bundle_seed = :crypto.hash(:sha256, seed)
    root_public_key = public_key(seed)
    bundle_public_key = public_key(bundle_seed)
    bundle_keyid = Envelope.keyid(bundle_public_key)

    document = dev_document(sections, now, ttl_ms, root_public_key, bundle_public_key)

    with {:ok, payload} <- JCS.encode(document),
         {:ok, signature} <- dev_signature(payload, bundle_seed, bundle_keyid) do
      {:ok,
       %{
         "payload" => encode_base64url(payload),
         "payloadType" => Envelope.payload_type(),
         "signatures" => [signature]
       }}
    end
  end

  defp dev_document(sections, now, ttl_ms, root_public_key, bundle_public_key) do
    root_keyid = Envelope.keyid(root_public_key)
    bundle_keyid = Envelope.keyid(bundle_public_key)
    expires_at = DateTime.add(now, ttl_ms, :millisecond)
    role_expires_at = expires_at
    root_expires_at = DateTime.add(now, ttl_ms, :millisecond)

    %{
      "profile" => "sigil_guard_trust_bundle/v1",
      "bundle_id" => "sigilguard-dev",
      "sequence" => "1",
      "issued_at" => DateTime.to_iso8601(now),
      "expires_at" => DateTime.to_iso8601(expires_at),
      "roles" => %{
        "root" => %{
          "keyids" => [root_keyid],
          "threshold" => 1,
          "version" => "1",
          "expires_at" => DateTime.to_iso8601(root_expires_at)
        },
        "delegates" => [
          %{
            "name" => "bundle",
            "keyids" => [bundle_keyid],
            "threshold" => 1,
            "expires_at" => DateTime.to_iso8601(role_expires_at)
          }
        ]
      },
      "keys" => %{
        root_keyid => %{"alg" => "ed25519", "public_key" => encode_base64url(root_public_key)},
        bundle_keyid => %{"alg" => "ed25519", "public_key" => encode_base64url(bundle_public_key)}
      },
      "rollback_floor" => "1",
      "provenance" => %{
        "builder" => "SigilGuard.TrustBundle.dev_bundle/1",
        "issuer_class" => "dev"
      }
    }
    |> Map.merge(sections)
  end

  defp dev_signature(payload, seed, keyid) do
    pae = Envelope.pae(Envelope.payload_type(), payload)
    {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, seed)
    signature = :crypto.sign(:eddsa, :none, pae, [private_key, :ed25519])

    {:ok, %{"keyid" => keyid, "sig" => encode_base64url(signature)}}
  rescue
    _ -> {:error, :invalid_bundle_format}
  end

  defp public_key(seed) do
    {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, seed)
    public_key
  end

  defp encode_base64url(value), do: Base.url_encode64(value, padding: false)

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
