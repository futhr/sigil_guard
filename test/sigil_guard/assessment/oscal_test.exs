defmodule SigilGuard.Assessment.OSCALTest do
  @moduledoc false

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SigilGuard.Assessment.OSCAL
  alias SigilGuard.Audit.Export

  @export_fixture "audit_proofs/export.json"
  @golden_fixture "oscal/assessment-results-observation.json"
  @root_uuid "11111111-2222-4333-8444-555555555555"
  @subject_uuid "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

  setup do
    export = SigilGuard.FixturePath.read_json!(@export_fixture)
    %{export: export, context: context(export)}
  end

  describe "project/2" do
    test "matches the OSCAL v1.2.3-schema-validated golden projection", ctx do
      assert {:ok, projection} = OSCAL.project(ctx.export, ctx.context)
      assert projection == SigilGuard.FixturePath.read_json!(@golden_fixture)

      assessment = projection["assessment-results"]
      [result] = assessment["results"]
      [resource] = assessment["back-matter"]["resources"]

      assert assessment["uuid"] == @root_uuid
      assert assessment["metadata"]["oscal-version"] == "1.2.3"
      assert result["uuid"] == "c459a934-6b08-54bb-97e1-f8256dce73bf"
      assert resource["uuid"] == "383b1ffc-3f61-57df-b26d-2f20b9f8be4c"

      assert Enum.map(result["observations"], & &1["uuid"]) == [
               "ccaed027-a5bc-5a24-92f4-3d8e0e9dacd0",
               "90b1be02-45c6-560a-ba5c-70019b1a5cc4"
             ]
    end

    test "emits observations and loss markers without assessment conclusions", ctx do
      assert {:ok, projection} = OSCAL.project(ctx.export, ctx.context)
      assessment = projection["assessment-results"]
      [result] = assessment["results"]

      refute Map.has_key?(result, "findings")
      refute Map.has_key?(result, "risks")
      refute Map.has_key?(result, "attestations")

      json = Jason.encode!(projection)
      refute json =~ "satisfied"
      refute json =~ "not-satisfied"
      refute json =~ "claim-strength"

      loss_values =
        assessment["metadata"]["props"]
        |> Enum.filter(&(&1["name"] == "loss"))
        |> Enum.map(& &1["value"])

      assert loss_values == [
               "signature-binding",
               "actor-binding",
               "issuance-time-binding",
               "assessment-conclusion"
             ]
    end

    test "binds observations to exact controls, subjects, and evidence", ctx do
      assert {:ok, projection} = OSCAL.project(ctx.export, ctx.context)
      assessment = projection["assessment-results"]
      [result] = assessment["results"]
      [first | _] = result["observations"]
      [resource] = assessment["back-matter"]["resources"]

      assert result["reviewed-controls"] == %{
               "control-selections" => [
                 %{
                   "include-controls" => [
                     %{"control-id" => "ac-3"},
                     %{"control-id" => "au-2"}
                   ]
                 }
               ]
             }

      assert first["subjects"] == [
               %{
                 "subject-uuid" => @subject_uuid,
                 "type" => "component",
                 "title" => "Agent boundary service"
               }
             ]

      assert first["relevant-evidence"] == [
               %{
                 "href" => "##{resource["uuid"]}",
                 "description" => "Verified boundary decision export."
               }
             ]

      [rlink] = resource["rlinks"]
      [hash] = rlink["hashes"]

      canonical_digest =
        ctx.export
        |> Export.canonical_bytes()
        |> then(&:crypto.hash(:sha256, &1))
        |> Base.encode16(case: :lower)

      assert rlink["href"] == "https://evidence.example/audit/export.json"
      assert canonical_digest == Export.digest(ctx.export)
      assert hash == %{"algorithm" => "SHA-256", "value" => canonical_digest}
    end

    test "is deterministic under replay and content-binds child UUIDs", ctx do
      assert {:ok, first} = OSCAL.project(ctx.export, ctx.context)
      assert {:ok, second} = OSCAL.project(ctx.export, ctx.context)
      assert first == second

      changed =
        put_in(ctx.context, [:result, :observations, Access.at(0), :description], "Changed")

      assert {:ok, changed_projection} = OSCAL.project(ctx.export, changed)

      [first_result] = first["assessment-results"]["results"]
      [changed_result] = changed_projection["assessment-results"]["results"]

      refute first_result["uuid"] == changed_result["uuid"]

      refute hd(first_result["observations"])["uuid"] ==
               hd(changed_result["observations"])["uuid"]

      [first_resource] = first["assessment-results"]["back-matter"]["resources"]

      [changed_resource] =
        changed_projection["assessment-results"]["back-matter"]["resources"]

      assert first_resource["uuid"] == changed_resource["uuid"]
    end

    test "defaults optional evidence, method, title, end, expiry, and local labels", ctx do
      observation = %{
        description: "The host associated the evidence with the selected control.",
        collected: "2026-07-02T12:01:00.000Z",
        control_ids: ["ac-3"],
        subjects: [%{uuid: @subject_uuid, type: :component}]
      }

      context =
        ctx.context
        |> update_in([:evidence], &Map.drop(&1, [:media_type, :description]))
        |> update_in([:result], &Map.delete(&1, :end))
        |> put_in([:result, :observations], [observation])

      assert {:ok, projection} = OSCAL.project(ctx.export, context)
      assessment = projection["assessment-results"]
      [result] = assessment["results"]
      [projected_observation] = result["observations"]
      [resource] = assessment["back-matter"]["resources"]

      refute Map.has_key?(result, "end")
      refute Map.has_key?(projected_observation, "title")
      refute Map.has_key?(projected_observation, "expires")
      assert projected_observation["methods"] == ["TEST"]
      assert resource["description"] == "Finalized SigilGuard audit export."
      assert hd(resource["rlinks"])["media-type"] == "application/json"
    end

    test "rejects a tampered or stale export against the pinned digest", ctx do
      tampered = put_in(ctx.export, ["checkpoint", "merkle_root"], String.duplicate("0", 64))

      assert {:error, :export_digest_mismatch} = OSCAL.project(tampered, ctx.context)

      stale_digest = put_in(ctx.context, [:evidence, :digest], String.duplicate("0", 64))
      assert {:error, :export_digest_mismatch} = OSCAL.project(ctx.export, stale_digest)
    end

    test "does not mutate or change the canonical digest of the export", ctx do
      original = ctx.export
      digest = Export.digest(original)

      assert {:ok, _} = OSCAL.project(original, ctx.context)
      assert ctx.export == original
      assert Export.digest(ctx.export) == digest
    end

    test "does not copy raw actors, payloads, or unknown export metadata", ctx do
      secret = "raw-host-secret-that-must-not-project"

      export =
        ctx.export
        |> Map.put("raw_actor", "did:web:private.example")
        |> Map.put("raw_payload", secret)

      context = put_in(ctx.context, [:evidence, :digest], Export.digest(export))
      assert {:ok, projection} = OSCAL.project(export, context)

      json = Jason.encode!(projection)
      refute json =~ secret
      refute json =~ "did:web:private.example"
      refute json =~ "raw_actor"
      refute json =~ "raw_payload"
    end

    test "rejects malformed exports without raising", ctx do
      for export <- [nil, [], "export", 1, %{}, Map.put(ctx.export, "kind", "wrong")] do
        assert {:error, :invalid_export} = OSCAL.project(export, ctx.context)
      end

      noncanonical = Map.put(ctx.export, "unsupported", self())
      assert {:error, :invalid_export} = OSCAL.project(noncanonical, ctx.context)

      ambiguous = Map.put(ctx.export, :kind, "sigil_guard.audit.export")
      assert {:error, :invalid_export} = OSCAL.project(ambiguous, ctx.context)

      invalid_utf8 = Map.put(ctx.export, "unsupported", <<255>>)
      assert {:error, :invalid_export} = OSCAL.project(invalid_utf8, ctx.context)

      invalid_key = Map.put(ctx.export, 1, "unsupported")
      assert {:error, :invalid_export} = OSCAL.project(invalid_key, ctx.context)

      invalid_utf8_key = Map.put(ctx.export, <<255>>, "unsupported")
      assert {:error, :invalid_export} = OSCAL.project(invalid_utf8_key, ctx.context)

      encoded_struct = Map.put(ctx.export, "unsupported", %URI{path: "export"})
      assert {:error, :invalid_export} = OSCAL.project(encoded_struct, ctx.context)
    end

    test "accepts the existing atom-keyed export compatibility shape" do
      export = %{
        kind: "sigil_guard.audit.export",
        version: 1,
        generated_at: "2026-07-02T12:00:05.000Z",
        checkpoint: %{}
      }

      assert {:ok, projection} = OSCAL.project(export, context(export))
      assert projection["assessment-results"]["uuid"] == @root_uuid
    end

    test "preserves existing JSON number compatibility", ctx do
      export =
        put_in(
          ctx.export,
          ["checkpoint", "metadata", "large_integer"],
          9_007_199_254_740_992
        )

      context = put_in(ctx.context, [:evidence, :digest], Export.digest(export))
      assert {:ok, _} = OSCAL.project(export, context)

      export = put_in(export, ["checkpoint", "metadata", "ratio"], 1.5)
      context = put_in(ctx.context, [:evidence, :digest], Export.digest(export))
      assert {:ok, _} = OSCAL.project(export, context)
    end

    test "accepts absolute and relative locator references", ctx do
      references = [
        "urn:example:assessment-plan:2026",
        "../plans/assessment-plan.json",
        "//assessment.example/plans/current.json"
      ]

      for href <- references do
        context = put_in(ctx.context, [:assessment_plan_href], href)
        assert {:ok, projection} = OSCAL.project(ctx.export, context)
        assert projection["assessment-results"]["import-ap"]["href"] == href
      end

      context = put_in(ctx.context, [:evidence, :href], "../exports/audit.json")
      assert {:ok, projection} = OSCAL.project(ctx.export, context)

      assert get_in(projection, [
               "assessment-results",
               "back-matter",
               "resources",
               Access.at(0),
               "rlinks",
               Access.at(0),
               "href"
             ]) == "../exports/audit.json"
    end

    test "rejects open, string-keyed, missing, and malformed root context", ctx do
      variants = [
        {nil, :invalid_context},
        {%{}, :invalid_context},
        {Map.put(ctx.context, :unknown, true), :invalid_context},
        {Map.delete(ctx.context, :title), :invalid_context},
        {Map.put(ctx.context, "title", "wrong key type"), :invalid_context},
        {Map.put(ctx.context, :title, "line\nbreak"), :invalid_context},
        {Map.put(ctx.context, :version, " "), :invalid_context},
        {Map.put(ctx.context, :assessment_results_uuid, "not-a-uuid"), :invalid_uuid},
        {Map.put(ctx.context, :assessment_results_uuid, nil), :invalid_uuid},
        {Map.put(ctx.context, :assessment_plan_href, "bad uri"), :invalid_uri},
        {Map.put(ctx.context, :assessment_plan_href, "#assessment-plan"), :invalid_uri},
        {Map.put(ctx.context, :assessment_plan_href, "?assessment-plan=1"), :invalid_uri},
        {Map.put(ctx.context, :assessment_plan_href, "plan##fragment"), :invalid_uri},
        {Map.put(ctx.context, :assessment_plan_href, "http://[invalid]"), :invalid_uri},
        {Map.put(ctx.context, :assessment_plan_href, "plan/%2G"), :invalid_uri},
        {Map.put(ctx.context, :assessment_plan_href, nil), :invalid_uri},
        {Map.put(ctx.context, :result, nil), :invalid_context},
        {Map.put(ctx.context, :version, " 1.0.0"), :invalid_context},
        {Map.put(ctx.context, :last_modified, nil), :invalid_timestamp},
        {Map.put(ctx.context, :last_modified, "2026-07-02T12:15:00+01:00"), :invalid_timestamp}
      ]

      for {context, reason} <- variants do
        assert {:error, ^reason} = OSCAL.project(ctx.export, context)
      end
    end

    test "rejects malformed evidence context", ctx do
      evidence = ctx.context.evidence

      evidence_variants = [
        {Map.put(evidence, :unknown, true), :invalid_context},
        {Map.delete(evidence, :href), :invalid_context},
        {Map.put(evidence, :href, "bad uri"), :invalid_uri},
        {Map.put(evidence, :href, "#export"), :invalid_uri},
        {Map.put(evidence, :digest, String.duplicate("A", 64)), :invalid_digest},
        {Map.put(evidence, :digest, "abc"), :invalid_digest},
        {Map.put(evidence, :digest, nil), :invalid_digest},
        {Map.put(evidence, :media_type, " "), :invalid_context},
        {Map.put(evidence, :media_type, " application/json"), :invalid_context},
        {Map.put(evidence, :description, ""), :invalid_context},
        {nil, :invalid_context}
      ]

      for {evidence, reason} <- evidence_variants do
        context = Map.put(ctx.context, :evidence, evidence)
        assert {:error, ^reason} = OSCAL.project(ctx.export, context)
      end
    end

    test "rejects invalid or ambiguous control scope", ctx do
      result = ctx.context.result
      observation = hd(result.observations)

      result_variants = [
        {%{result | reviewed_controls: []}, :invalid_reviewed_controls},
        {%{result | reviewed_controls: ["ac-3", "ac-3"]}, :invalid_reviewed_controls},
        {%{result | reviewed_controls: ["3-ac"]}, :invalid_reviewed_controls},
        {%{result | observations: []}, :invalid_observation},
        {%{result | observations: [nil]}, :invalid_observation},
        {%{result | observations: [%{observation | control_ids: ["ia-5"]}]}, :unknown_control},
        {%{result | observations: [%{observation | control_ids: ["ac-3", "ac-3"]}]},
         :invalid_observation},
        {%{result | observations: [%{observation | control_ids: :all}]}, :invalid_observation}
      ]

      for {result, reason} <- result_variants do
        assert {:error, ^reason} = OSCAL.project(ctx.export, %{ctx.context | result: result})
      end
    end

    test "rejects malformed subjects, methods, and local labels", ctx do
      observation = hd(ctx.context.result.observations)

      variants = [
        {Map.put(observation, :subjects, []), :invalid_observation},
        {Map.put(observation, :subjects, [nil]), :invalid_observation},
        {put_in(observation.subjects, [%{uuid: "bad", type: :component}]), :invalid_uuid},
        {put_in(observation.subjects, [%{uuid: @subject_uuid, type: :server}]),
         :invalid_observation},
        {put_in(observation.subjects, [hd(observation.subjects), hd(observation.subjects)]),
         :invalid_observation},
        {put_in(observation.subjects, [Map.put(hd(observation.subjects), :unknown, true)]),
         :invalid_observation},
        {put_in(observation.methods, []), :invalid_observation},
        {put_in(observation.methods, [:test, :test]), :invalid_observation},
        {put_in(observation.methods, [:automated]), :invalid_observation},
        {put_in(observation.sigilguard, %{claim: "mitigates"}), :invalid_observation},
        {put_in(observation.sigilguard, %{verdict: ""}), :invalid_observation},
        {put_in(observation.sigilguard, %{verdict: " block"}), :invalid_observation},
        {Map.put(observation, :sigilguard, []), :invalid_observation}
      ]

      for {changed, reason} <- variants do
        context = put_in(ctx.context, [:result, :observations], [changed])
        assert {:error, ^reason} = OSCAL.project(ctx.export, context)
      end
    end

    test "rejects reversed, out-of-window, and expired collection times", ctx do
      observation = hd(ctx.context.result.observations)

      variants = [
        put_in(ctx.context, [:result, :end], "2026-07-02T11:59:59.000Z"),
        put_in(
          ctx.context,
          [:result, :observations],
          [%{observation | collected: "2026-07-02T11:59:59.000Z"}]
        ),
        put_in(
          ctx.context,
          [:result, :observations],
          [%{observation | collected: "2026-07-02T12:10:01.000Z"}]
        ),
        put_in(
          ctx.context,
          [:result, :observations],
          [%{observation | expires: observation.collected}]
        ),
        put_in(
          ctx.context,
          [:result, :observations],
          [%{observation | expires: "2026-07-02T12:00:00.000Z"}]
        )
      ]

      for context <- variants do
        assert {:error, :invalid_timestamp} = OSCAL.project(ctx.export, context)
      end
    end

    test "is total over arbitrary top-level terms", ctx do
      for export <- [nil, false, 42, :export, [], {}, self()] do
        assert match?({:error, _}, OSCAL.project(export, ctx.context))
      end

      for context <- [nil, false, 42, :context, [], {}, self()] do
        assert match?({:error, _}, OSCAL.project(ctx.export, context))
      end
    end

    test "rejects malformed UTF-8 at every regex-backed boundary", ctx do
      invalid = <<255>>
      observation = hd(ctx.context.result.observations)
      subject = hd(observation.subjects)

      variants = [
        {put_in(ctx.context, [:assessment_results_uuid], invalid), :invalid_uuid},
        {put_in(ctx.context, [:assessment_plan_href], invalid), :invalid_uri},
        {put_in(ctx.context, [:last_modified], invalid), :invalid_timestamp},
        {put_in(ctx.context, [:evidence, :href], invalid), :invalid_uri},
        {put_in(ctx.context, [:evidence, :digest], invalid), :invalid_digest},
        {put_in(ctx.context, [:result, :reviewed_controls], [invalid]),
         :invalid_reviewed_controls},
        {put_in(ctx.context, [:result, :observations], [
           %{observation | collected: invalid}
         ]), :invalid_timestamp},
        {put_in(ctx.context, [:result, :observations], [
           %{observation | control_ids: [invalid]}
         ]), :invalid_observation},
        {put_in(ctx.context, [:result, :observations], [
           %{observation | subjects: [%{subject | uuid: invalid}]}
         ]), :invalid_uuid}
      ]

      for {context, reason} <- variants do
        assert {:error, ^reason} = OSCAL.project(ctx.export, context)
      end
    end

    property "is total over recursively malformed export and context content", ctx do
      check all(value <- StreamData.term(), max_runs: 100) do
        export = Map.put(ctx.export, "untrusted", value)
        assert tagged_result?(OSCAL.project(export, ctx.context))

        for context <- adversarial_contexts(ctx.context, value) do
          assert tagged_result?(OSCAL.project(ctx.export, context))
        end
      end
    end
  end

  defp tagged_result?({tag, _}) when tag in [:ok, :error], do: true
  defp tagged_result?(_), do: false

  defp adversarial_contexts(context, value) do
    observation = hd(context.result.observations)
    subject = hd(observation.subjects)

    [
      Map.put(context, :assessment_results_uuid, value),
      Map.put(context, :assessment_plan_href, value),
      Map.put(context, :title, value),
      Map.put(context, :version, value),
      Map.put(context, :last_modified, value),
      put_in(context, [:evidence, :href], value),
      put_in(context, [:evidence, :digest], value),
      put_in(context, [:evidence, :media_type], value),
      put_in(context, [:evidence, :description], value),
      put_in(context, [:result, :start], value),
      put_in(context, [:result, :end], value),
      put_in(context, [:result, :reviewed_controls], value),
      put_in(context, [:result, :observations], value),
      observation_context(context, Map.put(observation, :title, value)),
      observation_context(context, Map.put(observation, :description, value)),
      observation_context(context, Map.put(observation, :collected, value)),
      observation_context(context, Map.put(observation, :expires, value)),
      observation_context(context, Map.put(observation, :control_ids, value)),
      observation_context(context, Map.put(observation, :subjects, value)),
      observation_context(context, Map.put(observation, :methods, value)),
      observation_context(context, Map.put(observation, :sigilguard, value)),
      observation_context(context, %{observation | subjects: [Map.put(subject, :uuid, value)]}),
      observation_context(context, %{observation | subjects: [Map.put(subject, :type, value)]}),
      observation_context(context, %{observation | subjects: [Map.put(subject, :title, value)]})
    ]
  end

  defp observation_context(context, observation) do
    put_in(context, [:result, :observations], [observation])
  end

  defp context(export) do
    %{
      assessment_results_uuid: @root_uuid,
      assessment_plan_href: "https://assessment.example/oscal/assessment-plan.json",
      title: "SigilGuard boundary evidence observations",
      version: "1.0.0",
      last_modified: "2026-07-02T12:15:00.000Z",
      result: %{
        title: "Boundary evidence collection",
        description: "Host-authorized observations backed by a finalized audit export.",
        start: "2026-07-02T12:00:00.000Z",
        end: "2026-07-02T12:10:00.000Z",
        reviewed_controls: ["ac-3", "au-2"],
        observations: [
          %{
            title: "Privileged boundary decision",
            description: "The guard blocked a host-designated privileged boundary action.",
            collected: "2026-07-02T12:01:00.000Z",
            expires: "2026-07-02T13:01:00.000Z",
            control_ids: ["ac-3"],
            methods: [:test],
            subjects: [
              %{uuid: @subject_uuid, type: :component, title: "Agent boundary service"}
            ],
            sigilguard: %{
              verdict: "block",
              risk_level: "high",
              phase: "tool-request",
              sink: "tool"
            }
          },
          %{
            description: "The export records host-designated audit evidence generation.",
            collected: "2026-07-02T12:02:00.000Z",
            control_ids: ["au-2"],
            methods: [:examine],
            subjects: [%{uuid: @subject_uuid, type: :component}]
          }
        ]
      },
      evidence: %{
        href: "https://evidence.example/audit/export.json",
        digest: Export.digest(export),
        media_type: "application/json",
        description: "Verified boundary decision export."
      }
    }
  end
end
