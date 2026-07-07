defmodule SigilGuard.BoundaryTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Boundary

  @digest String.duplicate("a", 64)

  defp valid_fields(overrides \\ %{}) do
    Map.merge(
      %{
        phase: :tool_request,
        source: :tool,
        sink: :model,
        action_digest: @digest,
        payload_digest: @digest,
        context_digest: @digest,
        trust_level: :high
      },
      Map.new(overrides)
    )
  end

  defp valid, do: Boundary.new(valid_fields())

  describe "new/1" do
    test "builds from a keyword list, map, or struct" do
      keyword = valid_fields() |> Map.to_list()
      assert %Boundary{phase: :tool_request} = Boundary.new(keyword)
      assert %Boundary{phase: :tool_request} = Boundary.new(valid_fields())
      assert %Boundary{} = built = valid()
      assert Boundary.new(built) == built
    end

    test "defaults source_sensitivity, trust_level, and the list fields" do
      boundary = Boundary.new(valid_fields())
      assert boundary.source_sensitivity == :internal
      assert boundary.hits == []
      assert boundary.indicators == []
      assert boundary.hook_results == []
      assert boundary.repo_changes == []
    end

    test "normalizes string enum values and the nested isolation level" do
      boundary =
        Boundary.new(
          valid_fields(%{
            phase: "model_egress",
            trust_level: "medium",
            source_sensitivity: "private",
            sandbox: %{"isolation_level" => "container", "sandbox_id" => "sbx"}
          })
        )

      assert boundary.phase == :model_egress
      assert boundary.trust_level == :medium
      assert boundary.source_sensitivity == :private
      assert boundary.sandbox["isolation_level"] == :container
    end

    test "leaves unknown enum values intact for validation to reject" do
      boundary = Boundary.new(valid_fields(%{trust_level: "godmode"}))
      assert boundary.trust_level == "godmode"
    end

    test "normalizes an atom-keyed sandbox and ignores unknown map keys" do
      fields = valid_fields(%{sandbox: %{isolation_level: "vm"}}) |> Map.put("unknown", 1)
      boundary = Boundary.new(fields)
      assert boundary.sandbox[:isolation_level] == :vm
      assert Boundary.validate(boundary) == :ok
    end
  end

  describe "validate/1" do
    test "accepts a well-formed boundary, including absent sandbox and nil isolation" do
      assert Boundary.validate(valid()) == :ok

      assert Boundary.validate(Boundary.new(valid_fields(%{sandbox: %{"sandbox_id" => "s"}}))) ==
               :ok

      assert Boundary.validate(
               Boundary.new(valid_fields(%{sandbox: %{"isolation_level" => nil}}))
             ) ==
               :ok
    end

    test "rejects out-of-enum values with typed errors" do
      cases = [
        {:invalid_phase, %{phase: :session_paused}},
        {:invalid_phase, %{phase: :inbound_user}},
        {:invalid_source, %{source: nil}},
        {:invalid_sink, %{sink: ""}},
        {:invalid_source_sensitivity, %{source_sensitivity: :secret}},
        {:invalid_trust_level, %{trust_level: :ultra}},
        {:invalid_isolation_level, %{sandbox: %{"isolation_level" => :sandbox}}}
      ]

      for {reason, overrides} <- cases do
        assert Boundary.validate(Boundary.new(valid_fields(overrides))) == {:error, reason},
               inspect(reason)
      end
    end

    test "rejects malformed digests and non-list fields" do
      assert Boundary.validate(Boundary.new(valid_fields(%{action_digest: "short"}))) ==
               {:error, :invalid_boundary}

      assert Boundary.validate(Boundary.new(valid_fields(%{payload_digest: nil}))) ==
               {:error, :invalid_boundary}

      assert Boundary.validate(Boundary.new(valid_fields(%{context_digest: "NOTHEX" <> @digest}))) ==
               {:error, :invalid_boundary}

      assert Boundary.validate(%{Boundary.new(valid_fields()) | hits: :nope}) ==
               {:error, :invalid_boundary}
    end

    test "rejects a non-map sandbox" do
      assert Boundary.validate(Boundary.new(valid_fields(%{sandbox: "sbx"}))) ==
               {:error, :invalid_boundary}
    end

    test "rejects a non-struct input" do
      assert Boundary.validate(%{phase: :tool_request}) == {:error, :invalid_boundary}
    end
  end
end
