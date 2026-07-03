defmodule SigilGuard.TrustBundleFixtureGenerator.SeedSigner do
  @moduledoc false

  defmacro __using__(opts) do
    seed = Keyword.fetch!(opts, :seed)

    quote bind_quoted: [seed: seed] do
      @moduledoc false
      @behaviour SigilGuard.Signer
      @seed seed

      @impl SigilGuard.Signer
      def sign(message), do: :crypto.sign(:eddsa, :none, message, [private_key(), :ed25519])

      @impl SigilGuard.Signer
      def public_key do
        {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
        public_key
      end

      def seed, do: @seed

      defp private_key do
        {_, private_key} = :crypto.generate_key(:eddsa, :ed25519, @seed)
        private_key
      end
    end
  end
end

defmodule SigilGuard.TrustBundleFixtureGenerator do
  @moduledoc false

  alias SigilGuard.Attestation.Envelope
  alias SigilGuard.Canonical.JCS
  alias SigilGuard.TrustBundleFixtureGenerator.BundleBackupSigner
  alias SigilGuard.TrustBundleFixtureGenerator.BundleSigner
  alias SigilGuard.TrustBundleFixtureGenerator.BundleWitnessSigner
  alias SigilGuard.TrustBundleFixtureGenerator.ForkedRootSigner
  alias SigilGuard.TrustBundleFixtureGenerator.NewBundleSigner
  alias SigilGuard.TrustBundleFixtureGenerator.NewRootSigner
  alias SigilGuard.TrustBundleFixtureGenerator.RootSigner

  @issued_at "2026-07-02T12:00:00.000Z"
  @expires_at "2026-08-01T12:00:00.000Z"
  @role_expires_at "2026-10-01T12:00:00.000Z"
  @root_expires_at "2027-07-02T12:00:00.000Z"
  @root_v2_expires_at "2028-07-02T12:00:00.000Z"

  @doc false
  @spec write!(Path.t()) :: :ok
  def write!(root) do
    root = Path.expand(root)
    File.rm_rf!(root)

    for {dir, files} <- generate() do
      path = Path.join(root, dir)
      File.mkdir_p!(path)

      for {name, bytes} <- files do
        File.write!(Path.join(path, name), bytes)
      end
    end

    :ok
  end

  @doc false
  @spec generate() :: %{required(String.t()) => %{required(String.t()) => binary()}}
  def generate do
    %{
      "minimal" => minimal_files(),
      "multisig" => multisig_files(),
      "rotation" => rotation_files()
    }
  end

  defp minimal_files do
    vector_files(
      "minimal",
      minimal_document(),
      [BundleSigner],
      %{seed_hex: %{"root" => seed_hex(RootSigner), "bundle" => seed_hex(BundleSigner)}}
    )
  end

  defp multisig_files do
    vector_files(
      "multisig",
      multisig_document(),
      [BundleSigner, BundleBackupSigner, BundleWitnessSigner],
      %{
        seed_hex: %{
          "root" => seed_hex(RootSigner),
          "bundle" => seed_hex(BundleSigner),
          "bundle_backup" => seed_hex(BundleBackupSigner),
          "bundle_witness" => seed_hex(BundleWitnessSigner)
        }
      }
    )
  end

  defp rotation_files do
    genesis = minimal_document()
    rotation = rotation_document(NewRootSigner)
    forked = rotation_document(ForkedRootSigner)
    {:ok, rotation_envelope} = signed_envelope(rotation, [RootSigner, NewRootSigner])
    successor = successor_document(rotation_envelope)

    {:ok, genesis_bundle} = JCS.encode(genesis)
    {:ok, genesis_envelope} = signed_envelope(genesis, [BundleSigner])
    {:ok, genesis_json} = JCS.encode(genesis_envelope)
    {:ok, rotation_json} = JCS.encode(rotation_envelope)
    {:ok, forked_envelope} = signed_envelope(forked, [RootSigner, ForkedRootSigner])
    {:ok, forked_json} = JCS.encode(forked_envelope)
    {:ok, successor_envelope} = signed_envelope(successor, [NewBundleSigner])
    {:ok, successor_json} = JCS.encode(successor_envelope)

    expected =
      %{
        "name" => "rotation",
        "seed_hex" => %{
          "root" => seed_hex(RootSigner),
          "bundle" => seed_hex(BundleSigner),
          "new_root" => seed_hex(NewRootSigner),
          "new_bundle" => seed_hex(NewBundleSigner),
          "forked_root" => seed_hex(ForkedRootSigner)
        },
        "keyids" =>
          keyids([RootSigner, BundleSigner, NewRootSigner, NewBundleSigner, ForkedRootSigner]),
        "bundle_digest" => %{
          "genesis" => digest(genesis_bundle),
          "rotation-2" => document_digest(rotation),
          "successor" => document_digest(successor),
          "forked-2" => document_digest(forked)
        },
        "pae_sha256" => %{
          "genesis" => pae_digest(genesis),
          "rotation-2" => pae_digest(rotation),
          "successor" => pae_digest(successor),
          "forked-2" => pae_digest(forked)
        },
        "signatures" => %{
          "genesis" => signatures(genesis_envelope),
          "rotation-2" => signatures(rotation_envelope),
          "successor" => signatures(successor_envelope),
          "forked-2" => signatures(forked_envelope)
        }
      }

    {:ok, expected_json} = JCS.encode(expected)

    %{
      "genesis.json" => genesis_json,
      "genesis.bundle.json" => genesis_bundle,
      "rotation-2.json" => rotation_json,
      "successor.json" => successor_json,
      "forked-2.json" => forked_json,
      "expected.json" => expected_json
    }
  end

  defp vector_files(name, document, signers, extra_expected) do
    {:ok, bundle_json} = JCS.encode(document)
    {:ok, envelope} = signed_envelope(document, signers)
    {:ok, envelope_json} = JCS.encode(envelope)

    expected =
      Map.merge(
        %{
          "name" => name,
          "document" => document,
          "keyids" => keyids([RootSigner | signers]),
          "public_keys" => public_keys([RootSigner | signers]),
          "bundle_digest" => digest(bundle_json),
          "pae_sha256" => digest(Envelope.pae(Envelope.payload_type(), bundle_json)),
          "signatures" => signatures(envelope)
        },
        stringify(extra_expected)
      )

    {:ok, expected_json} = JCS.encode(expected)

    %{
      "bundle.json" => bundle_json,
      "envelope.json" => envelope_json,
      "expected.json" => expected_json
    }
  end

  defp minimal_document do
    bundle_document(%{
      "bundle_id" => "example-org-trust",
      "sequence" => "1",
      "rollback_floor" => "1",
      "root" => root_role(RootSigner, "1", @root_expires_at),
      "delegates" => [bundle_role([BundleSigner], 1)],
      "keys" => descriptors([RootSigner, BundleSigner])
    })
  end

  defp multisig_document do
    signers = [BundleSigner, BundleBackupSigner, BundleWitnessSigner]

    minimal_document()
    |> put_in(["roles", "delegates"], [bundle_role(signers, 2)])
    |> Map.put("keys", descriptors([RootSigner | signers]))
  end

  defp successor_document(rotation_envelope) do
    bundle_document(%{
      "bundle_id" => "example-org-trust",
      "sequence" => "2",
      "rollback_floor" => "2",
      "root" => root_role(NewRootSigner, "2", @root_v2_expires_at),
      "delegates" => [bundle_role([NewBundleSigner], 1)],
      "keys" => descriptors([NewRootSigner, NewBundleSigner]),
      "rotation_chain" => [rotation_envelope]
    })
  end

  defp bundle_document(fields) do
    base = %{
      "profile" => "sigil_guard_trust_bundle/v1",
      "bundle_id" => fields["bundle_id"],
      "sequence" => fields["sequence"],
      "issued_at" => @issued_at,
      "expires_at" => @expires_at,
      "roles" => %{
        "root" => fields["root"],
        "delegates" => fields["delegates"]
      },
      "keys" => fields["keys"],
      "rollback_floor" => fields["rollback_floor"]
    }

    case Map.fetch(fields, "rotation_chain") do
      {:ok, chain} -> Map.put(base, "rotation_chain", chain)
      :error -> base
    end
  end

  defp rotation_document(root_signer) do
    %{
      "profile" => "sigil_guard_root_rotation/v1",
      "bundle_id" => "example-org-trust",
      "root_version" => "2",
      "roles" => %{"root" => root_role(root_signer, "2", @root_v2_expires_at)},
      "keys" => descriptors([RootSigner, root_signer]),
      "rollback_floor" => "2",
      "issued_at" => @issued_at
    }
  end

  defp root_role(signer, version, expires_at) do
    %{
      "keyids" => [keyid(signer)],
      "threshold" => 1,
      "version" => version,
      "expires_at" => expires_at
    }
  end

  defp bundle_role(signers, threshold) do
    %{
      "name" => "bundle",
      "keyids" => Enum.map(signers, &keyid/1),
      "threshold" => threshold,
      "expires_at" => @role_expires_at
    }
  end

  defp descriptors(signers) do
    Map.new(signers, fn signer ->
      {keyid(signer), %{"alg" => "ed25519", "public_key" => public_key(signer)}}
    end)
  end

  defp signed_envelope(document, signers) do
    with {:ok, payload} <- JCS.encode(document) do
      Envelope.sign_many(payload, signers)
    end
  end

  defp keyids(signers), do: Map.new(signers, &{signer_name(&1), keyid(&1)})
  defp public_keys(signers), do: Map.new(signers, &{signer_name(&1), public_key(&1)})
  defp signatures(envelope), do: Map.new(envelope["signatures"], &{&1["keyid"], &1["sig"]})

  defp pae_digest(document) do
    document
    |> pae()
    |> digest()
  end

  defp document_digest(document) do
    document
    |> encode!()
    |> digest()
  end

  defp pae(document), do: Envelope.pae(Envelope.payload_type(), encode!(document))
  defp encode!(document), do: elem(JCS.encode(document), 1)
  defp digest(bytes), do: Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
  defp keyid(signer), do: Envelope.keyid(signer.public_key())
  defp public_key(signer), do: Base.url_encode64(signer.public_key(), padding: false)
  defp seed_hex(signer), do: Base.encode16(signer.seed(), case: :lower)

  defp signer_name(RootSigner), do: "root"
  defp signer_name(BundleSigner), do: "bundle"
  defp signer_name(BundleBackupSigner), do: "bundle_backup"
  defp signer_name(BundleWitnessSigner), do: "bundle_witness"
  defp signer_name(NewRootSigner), do: "new_root"
  defp signer_name(NewBundleSigner), do: "new_bundle"
  defp signer_name(ForkedRootSigner), do: "forked_root"

  defp stringify(map) do
    Map.new(map, fn {key, value} -> {to_string(key), value} end)
  end

  defmodule RootSigner do
    @moduledoc false
    use SigilGuard.TrustBundleFixtureGenerator.SeedSigner, seed: :binary.copy(<<0xAA>>, 32)
  end

  defmodule BundleSigner do
    @moduledoc false
    use SigilGuard.TrustBundleFixtureGenerator.SeedSigner, seed: :binary.copy(<<0xBB>>, 32)
  end

  defmodule BundleBackupSigner do
    @moduledoc false
    use SigilGuard.TrustBundleFixtureGenerator.SeedSigner, seed: :binary.copy(<<0xCC>>, 32)
  end

  defmodule BundleWitnessSigner do
    @moduledoc false
    use SigilGuard.TrustBundleFixtureGenerator.SeedSigner, seed: :binary.copy(<<0xDD>>, 32)
  end

  defmodule NewRootSigner do
    @moduledoc false
    use SigilGuard.TrustBundleFixtureGenerator.SeedSigner, seed: :binary.copy(<<0xEE>>, 32)
  end

  defmodule NewBundleSigner do
    @moduledoc false
    use SigilGuard.TrustBundleFixtureGenerator.SeedSigner, seed: :binary.copy(<<0x99>>, 32)
  end

  defmodule ForkedRootSigner do
    @moduledoc false
    use SigilGuard.TrustBundleFixtureGenerator.SeedSigner, seed: :binary.copy(<<0x88>>, 32)
  end
end
