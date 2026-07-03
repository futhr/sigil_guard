defmodule SigilGuard.Attestation.StatementTest do
  use ExUnit.Case, async: true

  alias SigilGuard.Attestation.Statement
  alias SigilGuard.Canonical.JCS

  @predicate_type "https://sigilguard.dev/attestation/tool_request/v1"
  @digest_a String.duplicate("a", 64)
  @digest_b String.duplicate("b", 64)
  @digest_c String.duplicate("c", 64)
  @digest_d String.duplicate("d", 64)

  describe "build/3" do
    test "builds an in-toto statement with required subjects in fixed order" do
      assert {:ok, statement} =
               Statement.build(@predicate_type, predicate(), %{
                 action: @digest_a,
                 payload: @digest_b,
                 context: @digest_c
               })

      assert statement["_type"] == "https://in-toto.io/Statement/v1"
      assert statement["predicateType"] == @predicate_type
      assert statement["predicate"] == predicate()

      assert subject_names(statement) == ~w(action payload context)
      assert subject_digests(statement) == [@digest_a, @digest_b, @digest_c]
    end

    test "includes manifest only when a manifest digest is present" do
      assert {:ok, statement} =
               Statement.build(@predicate_type, predicate(), %{
                 "action" => @digest_a,
                 "payload" => @digest_b,
                 "context" => @digest_c,
                 "manifest" => @digest_d
               })

      assert subject_names(statement) == ~w(action payload context manifest)
      assert subject_digests(statement) == [@digest_a, @digest_b, @digest_c, @digest_d]
    end

    test "rejects malformed inputs and digests" do
      assert Statement.build(@predicate_type, predicate(), %{
               payload: @digest_b,
               context: @digest_c
             }) ==
               {:error, :invalid_profile}

      assert Statement.build(@predicate_type, predicate(), %{
               action: String.upcase(@digest_a),
               payload: @digest_b,
               context: @digest_c
             }) == {:error, :invalid_profile}

      assert Statement.build("", predicate(), %{}) == {:error, :invalid_profile}
      assert Statement.build(@predicate_type, "bad", %{}) == {:error, :invalid_profile}
    end

    test "matches the compact canonical statement golden vector" do
      assert {:ok, statement} =
               Statement.build(@predicate_type, predicate(), %{
                 action: @digest_a,
                 payload: @digest_b,
                 context: @digest_c,
                 manifest: @digest_d
               })

      assert JCS.encode(statement) ==
               {:ok,
                "{\"_type\":\"https://in-toto.io/Statement/v1\",\"predicate\":{\"profile\":\"sigil_guard_agent_trust/v1\",\"statement_type\":\"tool_request\",\"verdict\":\"allow\"},\"predicateType\":\"https://sigilguard.dev/attestation/tool_request/v1\",\"subject\":[{\"digest\":{\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"},\"name\":\"action\"},{\"digest\":{\"sha256\":\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"},\"name\":\"payload\"},{\"digest\":{\"sha256\":\"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc\"},\"name\":\"context\"},{\"digest\":{\"sha256\":\"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd\"},\"name\":\"manifest\"}]}"}
    end
  end

  describe "parse/1" do
    test "normalizes valid string-keyed and atom-keyed statements" do
      assert {:ok, statement} =
               Statement.build(@predicate_type, predicate(), %{
                 action: @digest_a,
                 payload: @digest_b,
                 context: @digest_c
               })

      atom_statement = %{
        _type: statement["_type"],
        predicateType: statement["predicateType"],
        predicate: statement["predicate"],
        subject: [
          %{name: "action", digest: %{sha256: @digest_a}},
          %{name: "payload", digest: %{sha256: @digest_b}},
          %{name: "context", digest: %{sha256: @digest_c}}
        ]
      }

      assert Statement.parse(statement) == {:ok, statement}
      assert Statement.parse(atom_statement) == {:ok, statement}
    end

    test "rejects subject name and order violations" do
      assert {:ok, statement} =
               Statement.build(@predicate_type, predicate(), %{
                 action: @digest_a,
                 payload: @digest_b,
                 context: @digest_c
               })

      assert statement
             |> put_in(["subject"], Enum.reverse(statement["subject"]))
             |> Statement.parse() == {:error, :invalid_profile}

      assert statement
             |> put_in(["subject", Access.at(0), "name"], "unexpected")
             |> Statement.parse() == {:error, :invalid_profile}

      [action, payload, context] = statement["subject"]

      invalid_subject = [
        action,
        payload,
        context,
        %{"name" => "manifest", "digest" => %{"sha256" => @digest_d}},
        %{"name" => "extra", "digest" => %{"sha256" => @digest_d}}
      ]

      assert statement
             |> put_in(["subject"], invalid_subject)
             |> Statement.parse() == {:error, :invalid_profile}
    end

    test "rejects malformed statements" do
      assert Statement.parse("bad") == {:error, :invalid_profile}
      assert Statement.parse(%{}) == {:error, :invalid_profile}

      assert Statement.parse(%{
               "_type" => "wrong",
               "predicateType" => @predicate_type,
               "predicate" => predicate(),
               "subject" => []
             }) == {:error, :invalid_profile}

      assert Statement.parse(%{
               "_type" => Statement.statement_type(),
               "predicateType" => @predicate_type,
               "predicate" => predicate(),
               "subject" => [
                 %{"name" => "action", "digest" => %{"sha256" => @digest_a}},
                 %{"name" => "payload", "digest" => %{"sha512" => @digest_b}},
                 %{"name" => "context", "digest" => %{"sha256" => @digest_c}}
               ]
             }) == {:error, :invalid_profile}

      assert Statement.parse(%{
               "_type" => Statement.statement_type(),
               "predicateType" => @predicate_type,
               "predicate" => predicate(),
               "subject" => "bad"
             }) == {:error, :invalid_profile}

      assert Statement.parse(%{
               "_type" => Statement.statement_type(),
               "predicateType" => @predicate_type,
               "predicate" => predicate(),
               "subject" => ["bad"]
             }) == {:error, :invalid_profile}
    end
  end

  defp predicate do
    %{
      "profile" => "sigil_guard_agent_trust/v1",
      "statement_type" => "tool_request",
      "verdict" => "allow"
    }
  end

  defp subject_names(statement) do
    Enum.map(statement["subject"], & &1["name"])
  end

  defp subject_digests(statement) do
    Enum.map(statement["subject"], &get_in(&1, ["digest", "sha256"]))
  end
end
