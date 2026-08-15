defmodule SigilGuard.Assessment.OSCAL do
  @moduledoc """
  Project finalized audit evidence into OSCAL Assessment Results v1.2.3.

  `project/2` is an observation-only interoperability adapter. The host supplies
  the governing Assessment Plan reference, exact reviewed controls, assessment
  subjects, observation text, collection times, and the expected digest of the
  finalized `SigilGuard.Audit.Export`. The adapter verifies that digest before
  building a deterministic OSCAL document. The referenced evidence bytes must
  be the exact output of `SigilGuard.Audit.Export.canonical_bytes/1`.

  The projection never emits findings, risks, assessment attestations, or
  control-satisfaction states. It does not authenticate the host's assessment
  authority or replace native audit-chain, checkpoint, signature, witness, or
  anchor verification. URI references are serialized but never dereferenced.

  See `docs/specs/SP.17-external-assessment-projection.md` for the closed context
  contract and authority boundary.
  """

  import Bitwise

  alias SigilGuard.Audit.Export
  alias SigilGuard.Canonical.JCS

  @oscal_version "1.2.3"
  @property_namespace "https://sigilguard.dev/ns/oscal"
  @default_media_type "application/json"
  @default_evidence_description "Finalized SigilGuard audit export."

  @root_keys ~w(
    assessment_results_uuid assessment_plan_href title version last_modified
    result evidence
  )a
  @result_keys ~w(title description start end reviewed_controls observations)a
  @evidence_keys ~w(href digest media_type description)a
  @observation_keys ~w(
    title description collected expires control_ids subjects methods sigilguard
  )a
  @subject_keys ~w(uuid type title)a
  @sigilguard_keys ~w(verdict risk_level phase sink)a

  @required_root_keys @root_keys
  @required_result_keys ~w(title description start reviewed_controls observations)a
  @required_evidence_keys ~w(href digest)a
  @required_observation_keys ~w(description collected control_ids subjects)a
  @required_subject_keys ~w(uuid type)a

  @method_values %{test: "TEST", examine: "EXAMINE", interview: "INTERVIEW", unknown: "UNKNOWN"}
  @subject_type_values %{
    component: "component",
    inventory_item: "inventory-item",
    location: "location",
    party: "party",
    user: "user",
    resource: "resource"
  }
  @sigilguard_property_names %{
    verdict: "verdict",
    risk_level: "risk-level",
    phase: "phase",
    sink: "sink"
  }
  @sigilguard_property_order ~w(verdict risk_level phase sink)a
  @export_atom_fields %{
    "kind" => :kind,
    "version" => :version,
    "generated_at" => :generated_at,
    "checkpoint" => :checkpoint
  }

  @uuid_regex ~r/\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[45][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\z/
  @digest_regex ~r/\A[0-9a-f]{64}\z/
  @token_regex ~r/\A[\p{L}_][\p{L}\p{N}._-]*\z/u
  @uri_reference_regex ~r/\A(?:[A-Za-z0-9._~!$&'()*+,;=:@\/?#\[\]-]|%[0-9A-Fa-f]{2})+\z/

  @typedoc "A JSON-shaped OSCAL Assessment Results v1.2.3 document."
  @type assessment_results :: %{required(String.t()) => term()}

  @typedoc "A host-owned reference to an assessed system element."
  @type subject_context :: %{
          required(:uuid) => String.t(),
          required(:type) =>
            :component | :inventory_item | :location | :party | :user | :resource,
          optional(:title) => String.t()
        }

  @typedoc "Optional SigilGuard labels carried as private OSCAL properties."
  @type sigilguard_context :: %{
          optional(:verdict) => String.t(),
          optional(:risk_level) => String.t(),
          optional(:phase) => String.t(),
          optional(:sink) => String.t()
        }

  @typedoc "A host-authorized observation and its explicit assessment scope."
  @type observation_context :: %{
          required(:description) => String.t(),
          required(:collected) => String.t(),
          required(:control_ids) => [String.t(), ...],
          required(:subjects) => [subject_context(), ...],
          optional(:title) => String.t(),
          optional(:expires) => String.t(),
          optional(:methods) => [:test | :examine | :interview | :unknown, ...],
          optional(:sigilguard) => sigilguard_context()
        }

  @typedoc "The result collection window, reviewed controls, and observations."
  @type result_context :: %{
          required(:title) => String.t(),
          required(:description) => String.t(),
          required(:start) => String.t(),
          required(:reviewed_controls) => [String.t(), ...],
          required(:observations) => [observation_context(), ...],
          optional(:end) => String.t()
        }

  @typedoc "The canonical export-byte location and expected SHA-256 digest."
  @type evidence_context :: %{
          required(:href) => String.t(),
          required(:digest) => String.t(),
          optional(:media_type) => String.t(),
          optional(:description) => String.t()
        }

  @typedoc "Closed host-owned assessment context."
  @type context :: %{
          required(:assessment_results_uuid) => String.t(),
          required(:assessment_plan_href) => String.t(),
          required(:title) => String.t(),
          required(:version) => String.t(),
          required(:last_modified) => String.t(),
          required(:result) => result_context(),
          required(:evidence) => evidence_context()
        }

  @typedoc "A projection validation or integrity failure."
  @type project_error ::
          :invalid_export
          | :invalid_context
          | :invalid_uuid
          | :invalid_timestamp
          | :invalid_uri
          | :invalid_digest
          | :export_digest_mismatch
          | :invalid_reviewed_controls
          | :invalid_observation
          | :unknown_control

  @doc """
  Project a finalized audit export into OSCAL Assessment Results v1.2.3.

  The atom-keyed `context` is closed and host-owned. Its evidence digest must
  equal `SigilGuard.Audit.Export.digest/1` for the supplied export. Successful
  output contains observations and a hashed back-matter reference to the exact
  `SigilGuard.Audit.Export.canonical_bytes/1` output, but never findings, risks,
  assessment attestations, or satisfaction states.

  Identical inputs return identical maps and UUIDv5 identifiers. The function
  performs no network, filesystem, clock, process, or application-environment
  access.
  """
  @spec project(Export.t(), context()) ::
          {:ok, assessment_results()} | {:error, project_error()}
  def project(export, context) when is_map(export) and is_map(context) do
    with {:ok, export_digest} <- export_digest(export),
         {:ok, normalized} <- validate_context(context, export_digest) do
      build_document(normalized, export_digest)
    end
  end

  def project(export, _) when not is_map(export), do: {:error, :invalid_export}
  def project(_, _), do: {:error, :invalid_context}

  defp export_digest(export) do
    with :ok <- validate_export_shape(export),
         :ok <- validate_export_data(export) do
      {:ok, Export.digest(export)}
    else
      _ -> {:error, :invalid_export}
    end
  end

  defp validate_export_shape(export) do
    with "sigil_guard.audit.export" <- field(export, "kind"),
         1 <- field(export, "version"),
         generated_at when is_binary(generated_at) and generated_at != "" <-
           field(export, "generated_at"),
         checkpoint when is_map(checkpoint) <- field(export, "checkpoint") do
      :ok
    else
      _ -> {:error, :invalid_export}
    end
  end

  defp validate_export_data(value) when is_integer(value) or is_atom(value),
    do: :ok

  defp validate_export_data(value) when is_binary(value) do
    if String.valid?(value), do: :ok, else: {:error, :invalid_export}
  end

  defp validate_export_data(value) when is_float(value), do: :ok

  defp validate_export_data(values) when is_list(values) do
    Enum.reduce_while(values, :ok, fn value, :ok ->
      case validate_export_data(value) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp validate_export_data(%_{}), do: {:error, :invalid_export}

  defp validate_export_data(value) when is_map(value) do
    result =
      Enum.reduce_while(value, {:ok, MapSet.new()}, fn {key, item}, {:ok, keys} ->
        with {:ok, normalized_key} <- normalize_export_key(key),
             false <- MapSet.member?(keys, normalized_key),
             :ok <- validate_export_data(item) do
          {:cont, {:ok, MapSet.put(keys, normalized_key)}}
        else
          _ -> {:halt, {:error, :invalid_export}}
        end
      end)

    case result do
      {:ok, _} -> :ok
      error -> error
    end
  end

  defp validate_export_data(_), do: {:error, :invalid_export}

  defp normalize_export_key(key) when is_atom(key), do: {:ok, Atom.to_string(key)}

  defp normalize_export_key(key) when is_binary(key) do
    if String.valid?(key), do: {:ok, key}, else: {:error, :invalid_export}
  end

  defp normalize_export_key(_), do: {:error, :invalid_export}

  defp validate_context(context, export_digest) do
    with :ok <- closed_map(context, @root_keys, @required_root_keys, :invalid_context),
         :ok <- validate_uuid(context.assessment_results_uuid),
         :ok <- validate_locator_uri(context.assessment_plan_href),
         :ok <- validate_line(context.title),
         :ok <- validate_scalar_text(context.version),
         {:ok, _} <- validate_timestamp(context.last_modified),
         {:ok, evidence} <- validate_evidence(context.evidence, export_digest),
         {:ok, result} <- validate_result(context.result) do
      {:ok,
       %{
         assessment_results_uuid: context.assessment_results_uuid,
         assessment_plan_href: context.assessment_plan_href,
         title: context.title,
         version: context.version,
         last_modified: context.last_modified,
         evidence: evidence,
         result: result
       }}
    end
  end

  defp validate_evidence(evidence, export_digest) do
    with :ok <-
           closed_map(evidence, @evidence_keys, @required_evidence_keys, :invalid_context),
         :ok <- validate_locator_uri(evidence.href),
         :ok <- validate_digest(evidence.digest),
         :ok <- compare_digest(evidence.digest, export_digest),
         {:ok, media_type} <-
           optional_scalar_text(evidence, :media_type, @default_media_type),
         {:ok, description} <-
           optional_text(evidence, :description, @default_evidence_description) do
      {:ok,
       %{
         href: evidence.href,
         digest: evidence.digest,
         media_type: media_type,
         description: description
       }}
    end
  end

  defp validate_result(result) do
    with :ok <-
           closed_map(result, @result_keys, @required_result_keys, :invalid_context),
         :ok <- validate_line(result.title),
         :ok <- validate_text(result.description),
         {:ok, start_time} <- validate_timestamp(result.start),
         {:ok, end_time} <- optional_timestamp(result, :end),
         :ok <- validate_window(start_time, end_time),
         {:ok, controls} <- validate_controls(result.reviewed_controls),
         {:ok, observations} <-
           validate_observations(result.observations, controls, {start_time, end_time}) do
      {:ok,
       %{
         title: result.title,
         description: result.description,
         start: result.start,
         end: Map.get(result, :end),
         reviewed_controls: controls,
         observations: observations
       }}
    end
  end

  defp validate_controls(controls) when is_list(controls) and controls != [] do
    if valid_unique_tokens?(controls) do
      {:ok, controls}
    else
      {:error, :invalid_reviewed_controls}
    end
  end

  defp validate_controls(_), do: {:error, :invalid_reviewed_controls}

  defp validate_observations(observations, controls, window)
       when is_list(observations) and observations != [] do
    map_validated(observations, &validate_observation(&1, controls, window))
  end

  defp validate_observations(_, _, _), do: {:error, :invalid_observation}

  defp validate_observation(observation, controls, window) when is_map(observation) do
    with :ok <-
           closed_map(
             observation,
             @observation_keys,
             @required_observation_keys,
             :invalid_observation
           ),
         :ok <- validate_optional_line(observation, :title),
         :ok <- validate_text(observation.description, :invalid_observation),
         {:ok, collected_time} <- validate_timestamp(observation.collected),
         :ok <- validate_collected(collected_time, window),
         {:ok, expires_time} <- optional_timestamp(observation, :expires),
         :ok <- validate_expiry(collected_time, expires_time),
         {:ok, control_ids} <- validate_observation_controls(observation.control_ids, controls),
         {:ok, subjects} <- validate_subjects(observation.subjects),
         {:ok, methods} <- validate_methods(Map.get(observation, :methods, [:test])),
         {:ok, sigilguard} <- validate_sigilguard(Map.get(observation, :sigilguard, %{})) do
      {:ok,
       %{
         title: Map.get(observation, :title),
         description: observation.description,
         collected: observation.collected,
         expires: Map.get(observation, :expires),
         control_ids: control_ids,
         subjects: subjects,
         methods: methods,
         sigilguard: sigilguard
       }}
    end
  end

  defp validate_observation(_, _, _), do: {:error, :invalid_observation}

  defp validate_observation_controls(control_ids, controls)
       when is_list(control_ids) and control_ids != [] do
    with true <- valid_unique_tokens?(control_ids),
         true <- Enum.all?(control_ids, &(&1 in controls)) do
      {:ok, control_ids}
    else
      false -> control_error(control_ids, controls)
    end
  end

  defp validate_observation_controls(_, _), do: {:error, :invalid_observation}

  defp control_error(control_ids, _) do
    if valid_unique_tokens?(control_ids) do
      {:error, :unknown_control}
    else
      {:error, :invalid_observation}
    end
  end

  defp validate_subjects(subjects) when is_list(subjects) and subjects != [] do
    with {:ok, normalized} <- map_validated(subjects, &validate_subject/1),
         true <- unique_subjects?(normalized) do
      {:ok, normalized}
    else
      false -> {:error, :invalid_observation}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_subjects(_), do: {:error, :invalid_observation}

  defp validate_subject(subject) when is_map(subject) do
    with :ok <- closed_map(subject, @subject_keys, @required_subject_keys, :invalid_observation),
         :ok <- validate_uuid(subject.uuid),
         {:ok, type} <- fetch_subject_type(subject.type),
         :ok <- validate_optional_line(subject, :title) do
      {:ok, %{uuid: subject.uuid, type: type, title: Map.get(subject, :title)}}
    end
  end

  defp validate_subject(_), do: {:error, :invalid_observation}

  defp validate_methods(methods) when is_list(methods) and methods != [] do
    if Enum.uniq(methods) == methods and Enum.all?(methods, &Map.has_key?(@method_values, &1)) do
      {:ok, methods}
    else
      {:error, :invalid_observation}
    end
  end

  defp validate_methods(_), do: {:error, :invalid_observation}

  defp validate_sigilguard(properties) when is_map(properties) do
    with :ok <- closed_map(properties, @sigilguard_keys, [], :invalid_observation),
         true <- Enum.all?(properties, fn {_, value} -> valid_scalar_text?(value) end) do
      {:ok, properties}
    else
      false -> {:error, :invalid_observation}
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_sigilguard(_), do: {:error, :invalid_observation}

  defp build_document(context, export_digest) do
    resource_uuid = uuid5(context.assessment_results_uuid, "resource:" <> export_digest)

    with {:ok, observations} <- build_observations(context, resource_uuid),
         {:ok, result_uuid} <- build_result_uuid(context, export_digest) do
      {:ok,
       %{
         "assessment-results" => %{
           "uuid" => context.assessment_results_uuid,
           "metadata" => metadata(context),
           "import-ap" => %{"href" => context.assessment_plan_href},
           "results" => [result(context.result, result_uuid, observations)],
           "back-matter" => %{
             "resources" => [resource(context.evidence, resource_uuid)]
           }
         }
       }}
    end
  end

  defp metadata(context) do
    %{
      "title" => context.title,
      "last-modified" => context.last_modified,
      "version" => context.version,
      "oscal-version" => @oscal_version,
      "props" => projection_properties()
    }
  end

  defp result(result, result_uuid, observations) do
    %{
      "uuid" => result_uuid,
      "title" => result.title,
      "description" => result.description,
      "start" => result.start,
      "reviewed-controls" => reviewed_controls(result.reviewed_controls),
      "observations" => observations
    }
    |> maybe_put("end", result.end)
  end

  defp reviewed_controls(controls) do
    %{
      "control-selections" => [
        %{"include-controls" => Enum.map(controls, &%{"control-id" => &1})}
      ]
    }
  end

  defp build_observations(context, resource_uuid) do
    context.result.observations
    |> Enum.with_index()
    |> map_validated(fn {observation, index} ->
      build_observation(observation, index, context, resource_uuid)
    end)
  end

  defp build_observation(observation, index, context, resource_uuid) do
    projected =
      %{
        "description" => observation.description,
        "props" => observation_properties(observation),
        "methods" => Enum.map(observation.methods, &Map.fetch!(@method_values, &1)),
        "subjects" => Enum.map(observation.subjects, &project_subject/1),
        "relevant-evidence" => [
          %{
            "href" => "##{resource_uuid}",
            "description" => context.evidence.description
          }
        ],
        "collected" => observation.collected
      }
      |> maybe_put("title", observation.title)
      |> maybe_put("expires", observation.expires)

    canonical = canonical_identity(projected)
    uuid = uuid5(context.assessment_results_uuid, "observation:#{index}:" <> canonical)
    {:ok, Map.put(projected, "uuid", uuid)}
  end

  defp build_result_uuid(context, export_digest) do
    identity = %{
      "export-digest" => export_digest,
      "result" => context.result
    }

    canonical = canonical_identity(identity)
    {:ok, uuid5(context.assessment_results_uuid, "result:" <> canonical)}
  end

  defp resource(evidence, resource_uuid) do
    %{
      "uuid" => resource_uuid,
      "title" => "SigilGuard audit export",
      "description" => evidence.description,
      "props" => [property("verification", "host-policy-required")],
      "rlinks" => [
        %{
          "href" => evidence.href,
          "media-type" => evidence.media_type,
          "hashes" => [%{"algorithm" => "SHA-256", "value" => evidence.digest}]
        }
      ]
    }
  end

  defp project_subject(subject) do
    %{
      "subject-uuid" => subject.uuid,
      "type" => Map.fetch!(@subject_type_values, subject.type)
    }
    |> maybe_put("title", subject.title)
  end

  defp projection_properties do
    [
      property("projection-profile", "assessment-observation/v1"),
      property("authoritative-artifact", "sigil_guard.audit.export"),
      property("verification", "host-policy-required"),
      property("loss", "signature-binding"),
      property("loss", "actor-binding"),
      property("loss", "issuance-time-binding"),
      property("loss", "assessment-conclusion")
    ]
  end

  defp observation_properties(observation) do
    control_properties = Enum.map(observation.control_ids, &property("control-id", &1))

    local_properties =
      Enum.flat_map(@sigilguard_property_order, fn key ->
        case Map.fetch(observation.sigilguard, key) do
          {:ok, value} -> [property(Map.fetch!(@sigilguard_property_names, key), value)]
          :error -> []
        end
      end)

    control_properties ++ local_properties
  end

  defp property(name, value) do
    %{"name" => name, "ns" => @property_namespace, "value" => value}
  end

  defp canonical_identity(value) do
    {:ok, canonical} = JCS.encode(value)
    canonical
  end

  defp uuid5(namespace_uuid, name) do
    {:ok, namespace_bytes} = decode_uuid(namespace_uuid)

    <<head::binary-size(6), version_byte, next_byte, variant_byte, tail::binary-size(7)>> =
      :crypto.hash(:sha, namespace_bytes <> name) |> binary_part(0, 16)

    bytes =
      <<head::binary, (version_byte &&& 0x0F) ||| 0x50, next_byte,
        (variant_byte &&& 0x3F) ||| 0x80, tail::binary>>

    format_uuid(bytes)
  end

  defp decode_uuid(uuid) do
    uuid
    |> String.replace("-", "")
    |> Base.decode16(case: :mixed)
  end

  defp format_uuid(bytes) do
    hex = Base.encode16(bytes, case: :lower)

    Enum.join(
      [
        binary_part(hex, 0, 8),
        binary_part(hex, 8, 4),
        binary_part(hex, 12, 4),
        binary_part(hex, 16, 4),
        binary_part(hex, 20, 12)
      ],
      "-"
    )
  end

  defp closed_map(map, allowed, required, error) when is_map(map) do
    keys = Map.keys(map)

    if Enum.all?(keys, &(&1 in allowed)) and Enum.all?(required, &Map.has_key?(map, &1)) do
      :ok
    else
      {:error, error}
    end
  end

  defp closed_map(_, _, _, error), do: {:error, error}

  defp validate_uuid(value) when is_binary(value) do
    if String.valid?(value) and Regex.match?(@uuid_regex, value) do
      :ok
    else
      {:error, :invalid_uuid}
    end
  end

  defp validate_uuid(_), do: {:error, :invalid_uuid}

  defp validate_locator_uri(value) when is_binary(value) do
    with true <- String.valid?(value),
         true <- Regex.match?(@uri_reference_regex, value),
         {:ok, uri} <- URI.new(value),
         true <- locator_uri?(uri) do
      :ok
    else
      _ -> {:error, :invalid_uri}
    end
  end

  defp validate_locator_uri(_), do: {:error, :invalid_uri}

  defp locator_uri?(uri) do
    nonempty?(uri.scheme) or nonempty?(uri.host) or nonempty?(uri.path)
  end

  defp nonempty?(value), do: is_binary(value) and value != ""

  defp validate_digest(value) when is_binary(value) do
    if String.valid?(value) and Regex.match?(@digest_regex, value) do
      :ok
    else
      {:error, :invalid_digest}
    end
  end

  defp validate_digest(_), do: {:error, :invalid_digest}

  defp compare_digest(digest, digest), do: :ok
  defp compare_digest(_, _), do: {:error, :export_digest_mismatch}

  defp validate_line(value), do: validate_line(value, :invalid_context)

  defp validate_line(value, error) do
    if valid_text?(value) and not String.contains?(value, ["\n", "\r"]) do
      :ok
    else
      {:error, error}
    end
  end

  defp validate_optional_line(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> validate_line(value, :invalid_observation)
      :error -> :ok
    end
  end

  defp validate_text(value), do: validate_text(value, :invalid_context)

  defp validate_text(value, error) do
    if valid_text?(value), do: :ok, else: {:error, error}
  end

  defp validate_scalar_text(value) do
    if valid_scalar_text?(value), do: :ok, else: {:error, :invalid_context}
  end

  defp valid_text?(value) do
    is_binary(value) and String.valid?(value) and String.trim(value) != ""
  end

  defp optional_text(map, key, default) do
    value = Map.get(map, key, default)

    if valid_text?(value), do: {:ok, value}, else: {:error, :invalid_context}
  end

  defp optional_scalar_text(map, key, default) do
    value = Map.get(map, key, default)

    if valid_scalar_text?(value), do: {:ok, value}, else: {:error, :invalid_context}
  end

  defp valid_scalar_text?(value) do
    valid_text?(value) and String.trim(value) == value
  end

  defp validate_timestamp(value) when is_binary(value) do
    with true <- String.ends_with?(value, "Z"),
         {:ok, datetime, 0} <- DateTime.from_iso8601(value),
         true <- datetime.year in 1900..2999 do
      {:ok, datetime}
    else
      _ -> {:error, :invalid_timestamp}
    end
  end

  defp validate_timestamp(_), do: {:error, :invalid_timestamp}

  defp optional_timestamp(map, key) do
    case Map.fetch(map, key) do
      {:ok, value} -> validate_timestamp(value)
      :error -> {:ok, nil}
    end
  end

  defp validate_window(_, nil), do: :ok

  defp validate_window(start_time, end_time) do
    if DateTime.compare(end_time, start_time) in [:eq, :gt] do
      :ok
    else
      {:error, :invalid_timestamp}
    end
  end

  defp validate_collected(collected_time, {start_time, nil}) do
    if DateTime.compare(collected_time, start_time) in [:eq, :gt] do
      :ok
    else
      {:error, :invalid_timestamp}
    end
  end

  defp validate_collected(collected_time, {start_time, end_time}) do
    after_start = DateTime.compare(collected_time, start_time) in [:eq, :gt]
    before_end = DateTime.compare(collected_time, end_time) in [:eq, :lt]

    if after_start and before_end, do: :ok, else: {:error, :invalid_timestamp}
  end

  defp validate_expiry(_, nil), do: :ok

  defp validate_expiry(collected_time, expires_time) do
    if DateTime.compare(expires_time, collected_time) == :gt do
      :ok
    else
      {:error, :invalid_timestamp}
    end
  end

  defp valid_unique_tokens?(tokens) do
    Enum.uniq(tokens) == tokens and
      Enum.all?(tokens, fn token ->
        is_binary(token) and String.valid?(token) and Regex.match?(@token_regex, token)
      end)
  end

  defp unique_subjects?(subjects) do
    identities = Enum.map(subjects, &{&1.uuid, &1.type})
    Enum.uniq(identities) == identities
  end

  defp fetch_subject_type(type) do
    case Map.fetch(@subject_type_values, type) do
      {:ok, _} -> {:ok, type}
      :error -> {:error, :invalid_observation}
    end
  end

  defp map_validated(values, validator) do
    values
    |> Enum.reduce_while({:ok, []}, fn value, {:ok, accepted} ->
      case validator.(value) do
        {:ok, normalized} -> {:cont, {:ok, [normalized | accepted]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> reverse_validated()
  end

  defp reverse_validated({:ok, values}), do: {:ok, Enum.reverse(values)}
  defp reverse_validated(error), do: error

  defp maybe_put(map, _, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  defp field(map, key), do: Map.get(map, key, Map.get(map, Map.fetch!(@export_atom_fields, key)))
end
