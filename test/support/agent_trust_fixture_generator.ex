defmodule SigilGuard.AgentTrustFixtureGenerator do
  @moduledoc false

  alias SigilGuard.Attestation.AgentPredicate
  alias SigilGuard.Attestation.Digest
  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Attestation.Statement
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.CapabilityManifest
  alias SigilGuard.TrustProfile

  @types [
    :tool_request,
    :tool_result,
    :model_ingress,
    :model_egress,
    :repo_change,
    :release,
    :agent_request,
    :agent_response
  ]

  @seed_hex "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
  @issued_at ~U[2026-07-02 12:00:00.000Z]
  @expires_at ~U[2026-07-02 12:05:00.000Z]
  @nonce "000102030405060708090a0b0c0d0e0f"
  @request_action_digest String.duplicate("1", 64)
  @agent_card_digest String.duplicate("2", 64)

  @doc false
  @spec types() :: [TrustProfile.statement_type()]
  def types, do: @types

  @doc false
  @spec write!(Path.t()) :: :ok
  def write!(root) do
    root = Path.expand(root)

    File.rm_rf!(root)

    for {type, files} <- generate() do
      dir = Path.join(root, Atom.to_string(type))
      File.mkdir_p!(dir)

      for {name, bytes} <- files do
        File.write!(Path.join(dir, name), bytes)
      end
    end

    :ok
  end

  @doc false
  @spec generate() :: %{
          required(TrustProfile.statement_type()) => %{required(String.t()) => binary()}
        }
  def generate do
    Map.new(@types, fn type -> {type, vector_files(type)} end)
  end

  defp vector_files(type) do
    vector = vector(type)

    {:ok, statement} =
      Statement.build(vector.predicate_type, vector.predicate, vector.digests)

    {:ok, statement} = TrustProfile.validate(statement)
    {:ok, statement_json} = JCS.encode(statement)
    {:ok, envelope} = Envelope.sign(statement_json, __MODULE__.SeedSigner)
    {:ok, envelope_json} = JCS.encode(envelope)

    expected =
      expected(
        vector,
        statement_json,
        Envelope.pae(Envelope.payload_type(), statement_json),
        envelope
      )

    {:ok, expected_json} = JCS.encode(expected)

    %{
      "statement.json" => statement_json,
      "envelope.json" => envelope_json,
      "expected.json" => expected_json
    }
  end

  defp vector(type) do
    {:ok, predicate_type} = TrustProfile.predicate_type(type)
    data = data(type)
    opts = Map.get(data, :opts, [])
    {:ok, digests} = Digest.digests(type, data.payload, data.context, opts)
    predicate = data.predicate || predicate(type, data, opts)

    %{
      type: type,
      predicate_type: predicate_type,
      payload: data.payload,
      context: data.context,
      opts: opts,
      digests: digests,
      predicate: predicate
    }
  end

  defp data(:tool_request) do
    payload = %{
      "id" => 42,
      "jsonrpc" => "2.0",
      "method" => "tools/call",
      "params" => %{
        "arguments" => %{"content" => "## 3.0.0\n", "path" => "docs/CHANGELOG.md"},
        "name" => "repo_file_write"
      }
    }

    context = %{
      actor: "spiffe://prod.example.org/agents/release-bot",
      identity: "spiffe://prod.example.org/agents/release-bot",
      intended_audience: :internal,
      isolation_level: "container",
      mcp_server: "repo-mcp",
      origin: :user,
      phase: :tool_request,
      sandbox_id: "sbx-9c2e4d10",
      sink: :repo,
      source: "session-7f3acb12",
      tool: "repo_file_write",
      trust_level: :medium,
      trust_zone: :semi_trusted
    }

    manifest_digest = repo_file_write_manifest_digest()

    %{
      payload: payload,
      context: context,
      opts: [manifest_digest: manifest_digest],
      predicate: tool_request_predicate(manifest_digest)
    }
  end

  defp data(:tool_result) do
    %{
      payload: %{
        "method" => "tools/call",
        "result" => %{"content" => "wrote docs/CHANGELOG.md"}
      },
      context: Map.merge(base_context(), %{phase: :tool_result, origin: :tool, sink: :model}),
      opts: [
        request_action_digest: @request_action_digest,
        manifest_digest: repo_file_write_manifest_digest()
      ],
      predicate: nil
    }
  end

  defp data(:model_ingress) do
    %{
      payload: %{"content" => "prepare the release notes"},
      context: Map.merge(base_context(), %{phase: :inbound_user, origin: :user, sink: :model}),
      predicate: nil
    }
  end

  defp data(:model_egress) do
    %{
      payload: %{"content" => "I will update docs/CHANGELOG.md."},
      context: Map.merge(base_context(), %{phase: :outbound_model, origin: :model, sink: :user}),
      predicate: nil
    }
  end

  defp data(:repo_change) do
    %{
      payload: %{
        "operation" => "write",
        "paths" => ["docs/CHANGELOG.md"],
        "ref" => "refs/heads/native",
        "repository" => "sigil_guard"
      },
      context: Map.merge(base_context(), %{phase: :repo_change, origin: :tool, sink: :repo}),
      predicate: nil
    }
  end

  defp data(:release) do
    %{
      payload: %{
        "artifacts" => [
          %{"name" => "sigil_guard-3.0.0.tar", "sha256" => String.duplicate("a", 64)}
        ],
        "package" => "sigil_guard",
        "version" => "3.0.0"
      },
      context: Map.merge(base_context(), %{phase: :repo_change, origin: :repo, sink: :registry}),
      predicate: nil
    }
  end

  defp data(:agent_request) do
    %{
      payload: %{
        "arguments" => %{"topic" => "release summary"},
        "capability" => "summarize",
        "peer_agent" => "spiffe://prod.example.org/agents/reviewer"
      },
      context:
        Map.merge(base_context(), %{phase: :tool_request, origin: :model, sink: :external}),
      opts: [
        card_digest: @agent_card_digest,
        manifest_digest: @agent_card_digest,
        peer_trust: :medium
      ],
      predicate: nil
    }
  end

  defp data(:agent_response) do
    %{
      payload: %{
        "capability" => "summarize",
        "peer_agent" => "spiffe://prod.example.org/agents/reviewer",
        "status" => "ok"
      },
      context: Map.merge(base_context(), %{phase: :tool_result, origin: :external, sink: :model}),
      opts: [
        card_digest: @agent_card_digest,
        manifest_digest: @agent_card_digest,
        peer_trust: :medium,
        quarantined: false,
        request_action_digest: @request_action_digest
      ],
      predicate: nil
    }
  end

  defp predicate(:agent_request, data, opts) do
    {:ok, extension} =
      AgentPredicate.build_request(data.payload, Keyword.put(opts, :verdict, :allow))

    Map.merge(base_predicate(:agent_request), extension)
  end

  defp predicate(:agent_response, data, opts) do
    {:ok, extension} = AgentPredicate.build_response(data.payload, opts)
    Map.merge(base_predicate(:agent_response), extension)
  end

  defp predicate(type, _, _), do: base_predicate(type)

  defp base_predicate(type) do
    %{
      "actor" => %{"id" => base_context().actor, "trust_level" => "medium"},
      "expires_at" => DateTime.to_iso8601(@expires_at),
      "issued_at" => DateTime.to_iso8601(@issued_at),
      "nonce" => @nonce,
      "profile" => TrustProfile.profile_id(),
      "statement_type" => Atom.to_string(type),
      "verdict" => "allow"
    }
  end

  defp tool_request_predicate(manifest_digest) do
    Map.merge(base_predicate(:tool_request), %{
      "boundary" => %{
        "intended_audience" => "internal",
        "isolation_level" => "container",
        "origin" => "user",
        "phase" => "tool_request",
        "sandbox_id" => "sbx-9c2e4d10",
        "sink" => "repo",
        "source" => "session-7f3acb12",
        "trust_zone" => "semi_trusted"
      },
      "matched_rules" => [
        %{"explanation" => "repo write within approved path set", "id" => "repo.write.allow"}
      ],
      "tool" => %{
        "manifest_digest" => manifest_digest,
        "mcp_server" => "repo-mcp",
        "name" => "repo_file_write"
      }
    })
  end

  defp base_context do
    %{
      actor: "spiffe://prod.example.org/agents/release-bot",
      identity: "spiffe://prod.example.org/agents/release-bot",
      intended_audience: :internal,
      mcp_server: "repo-mcp",
      origin: :user,
      phase: :tool_request,
      sink: :tool,
      source: "session-7f3acb12",
      tool: "repo_file_write",
      trust_level: :medium,
      trust_zone: :semi_trusted
    }
  end

  defp repo_file_write_manifest_digest do
    {:ok, digest} = CapabilityManifest.digest(repo_file_write_manifest())

    digest
  end

  defp repo_file_write_manifest do
    %{
      "allowed_sink_zones" => ["semi_trusted", "trusted"],
      "allowed_source_zones" => ["semi_trusted", "trusted"],
      "annotations" => %{"destructiveHint" => false, "title" => "Repo File Write"},
      "description" => "Write one UTF-8 text file inside the repository working tree.",
      "expires_at" => "2027-01-01T00:00:00.000Z",
      "input_schema" => %{
        "$schema" => "https://json-schema.org/draft/2020-12/schema",
        "additionalProperties" => false,
        "properties" => %{"content" => %{"type" => "string"}, "path" => %{"type" => "string"}},
        "required" => ["content", "path"],
        "type" => "object"
      },
      "input_sensitivity" => "internal",
      "issuer_keyid" => Envelope.keyid(__MODULE__.SeedSigner.public_key()),
      "manifest_format" => "sigil_guard_capability_manifest/v1",
      "name" => "repo_file_write",
      "network_access" => "none",
      "output_sensitivity" => "internal",
      "reversibility" => "reversible",
      "sandbox" => %{"min_isolation" => "container", "required" => true},
      "scopes" => ["repo:write"],
      "server" => "repo-mcp",
      "side_effects" => ["write"],
      "suspicious_params" => [],
      "version" => "1.4.2"
    }
  end

  defp expected(vector, statement_json, pae, envelope) do
    [signature] = envelope["signatures"]

    expected = %{
      "action_digest" => vector.digests["action"],
      "context_digest" => vector.digests["context"],
      "inputs" => %{
        "context" => stringify_context(vector.context),
        "payload" => vector.payload,
        "sign_opts" => %{
          "expires_at" => DateTime.to_iso8601(@expires_at),
          "issued_at" => DateTime.to_iso8601(@issued_at),
          "nonce" => @nonce,
          "seed_hex" => @seed_hex
        }
      },
      "keyid" => Envelope.keyid(__MODULE__.SeedSigner.public_key()),
      "pae_sha256" => sha256_bytes(pae),
      "payload_digest" => vector.digests["payload"],
      "public_key_hex" => Base.encode16(__MODULE__.SeedSigner.public_key(), case: :lower),
      "signature" => signature["sig"],
      "statement_sha256" => sha256_bytes(statement_json)
    }

    expected
    |> maybe_put("manifest_digest", vector.digests["manifest"])
  end

  defp stringify_context(context) do
    context
    |> Map.new(fn {key, value} -> {Atom.to_string(key), stringify_value(value)} end)
  end

  defp stringify_value(value) when is_atom(value), do: Atom.to_string(value)
  defp stringify_value(value), do: value

  defp sha256_bytes(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defmodule SeedSigner do
    @moduledoc false

    @behaviour SigilGuard.Signer
    @seed Base.decode16!("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20")

    @impl SigilGuard.Signer
    def sign(message) do
      {_, private_key} = keypair()
      :crypto.sign(:eddsa, :none, message, [private_key, :ed25519])
    end

    @impl SigilGuard.Signer
    def public_key do
      {public_key, _} = keypair()
      public_key
    end

    defp keypair do
      :crypto.generate_key(:eddsa, :ed25519, @seed)
    end
  end
end
