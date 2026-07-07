defmodule SigilGuard.AttestationTest do
  @moduledoc false

  use ExUnit.Case, async: true
  use ExUnitProperties

  alias SigilGuard.Attestation
  alias SigilGuard.Canonical.JCS

  @envelope %{"payload" => "abc", "signatures" => []}
  @token "confirm.token"

  describe "attach/2 and fetch/1" do
    test "writes and reads trust metadata under string and atom keys" do
      payload = %{"method" => "tools/call"}

      assert Attestation.attach(payload, @envelope) == %{
               "method" => "tools/call",
               "_agent_trust" => @envelope
             }

      assert Attestation.fetch(%{"_agent_trust" => @envelope}) == {:ok, @envelope}
      assert Attestation.fetch(%{_agent_trust: @envelope}) == {:ok, @envelope}
    end

    test "returns error for absent or malformed trust metadata" do
      assert Attestation.fetch(%{}) == :error
      assert Attestation.fetch(%{"_agent_trust" => "bad"}) == :error
      assert Attestation.fetch(%{"_sigil" => @envelope}) == :error
      assert Attestation.fetch(%{_sigil: @envelope}) == :error
      assert Attestation.fetch("bad") == :error
    end

    test "raises on non-map payloads and envelopes" do
      error =
        assert_raise ArgumentError, ~r/expected attestation payload to be a map/, fn ->
          Attestation.attach({"secret", "do-not-leak"}, @envelope)
        end

      refute Exception.message(error) =~ "do-not-leak"

      error =
        assert_raise ArgumentError, ~r/expected attestation envelope to be a map/, fn ->
          Attestation.attach(%{}, {"secret", "do-not-leak"})
        end

      refute Exception.message(error) =~ "do-not-leak"
    end
  end

  describe "attach_confirmation/2 and fetch_confirmation/1" do
    test "writes and reads confirmation metadata under string and atom keys" do
      payload = %{"method" => "tools/call"}

      assert Attestation.attach_confirmation(payload, @token) == %{
               "method" => "tools/call",
               "_agent_confirmation" => @token
             }

      assert Attestation.fetch_confirmation(%{"_agent_confirmation" => @token}) == {:ok, @token}
      assert Attestation.fetch_confirmation(%{_agent_confirmation: @token}) == {:ok, @token}
    end

    test "returns error for absent or malformed confirmation metadata" do
      assert Attestation.fetch_confirmation(%{}) == :error
      assert Attestation.fetch_confirmation(%{"_agent_confirmation" => %{}}) == :error
      assert Attestation.fetch_confirmation(%{"_sigil_confirmation" => @token}) == :error
      assert Attestation.fetch_confirmation(%{_sigil_confirmation: @token}) == :error
      assert Attestation.fetch_confirmation("bad") == :error
    end

    test "raises on non-map payloads and non-string tokens" do
      error =
        assert_raise ArgumentError, ~r/expected attestation payload to be a map/, fn ->
          Attestation.attach_confirmation({"secret", "do-not-leak"}, @token)
        end

      refute Exception.message(error) =~ "do-not-leak"

      error =
        assert_raise ArgumentError, ~r/expected confirmation token to be a string/, fn ->
          Attestation.attach_confirmation(%{}, {"secret", "secret-token"})
        end

      refute Exception.message(error) =~ "secret-token"
    end
  end

  describe "strip_metadata/1" do
    test "removes only SP.01 metadata keys at root and params level" do
      payload = %{
        "_agent_trust" => @envelope,
        :_agent_trust => %{"atom" => true},
        "_agent_confirmation" => @token,
        :_agent_confirmation => "atom-token",
        "confirmation_token" => "legacy-token",
        :confirmation_token => "atom-legacy-token",
        "_sigil" => "user-content",
        :_sigil => "atom-user-content",
        "_sigil_confirmation" => "user-confirmation-field",
        :_sigil_confirmation => "atom-user-confirmation-field",
        "params" => %{
          "_agent_trust" => @envelope,
          :_agent_confirmation => "nested-token",
          "confirmation_token" => "nested-legacy-token",
          "_sigil" => "nested-user-content",
          "_sigil_confirmation" => "nested-user-confirmation-field",
          "arguments" => %{"confirmation_token" => "user-content"}
        },
        :params => %{
          :_agent_trust => @envelope,
          "_agent_confirmation" => "nested-token",
          :_sigil => "nested-atom-user-content",
          :_sigil_confirmation => "nested-atom-user-confirmation-field"
        }
      }

      assert Attestation.strip_metadata(payload) == %{
               "_sigil" => "user-content",
               :_sigil => "atom-user-content",
               "_sigil_confirmation" => "user-confirmation-field",
               :_sigil_confirmation => "atom-user-confirmation-field",
               "params" => %{
                 "_sigil" => "nested-user-content",
                 "_sigil_confirmation" => "nested-user-confirmation-field",
                 "arguments" => %{"confirmation_token" => "user-content"}
               },
               params: %{
                 _sigil: "nested-atom-user-content",
                 _sigil_confirmation: "nested-atom-user-confirmation-field"
               }
             }
    end

    test "strips each map element in list payloads" do
      payload = [
        %{"value" => 1, "_agent_trust" => @envelope, "_sigil" => @envelope},
        %{
          "value" => 2,
          "params" => %{"confirmation_token" => @token, "_sigil_confirmation" => @token}
        },
        "unchanged"
      ]

      assert Attestation.strip_metadata(payload) == [
               %{"value" => 1, "_sigil" => @envelope},
               %{"value" => 2, "params" => %{"_sigil_confirmation" => @token}},
               "unchanged"
             ]
    end

    test "removes mixed atom and string forms before canonical encoding collisions" do
      payload = %{
        "_agent_trust" => @envelope,
        :_agent_trust => %{"other" => true},
        "params" => %{
          "_agent_confirmation" => @token,
          :_agent_confirmation => "other"
        }
      }

      assert JCS.encode(payload) == {:error, :invalid_map}
      assert JCS.encode(Attestation.strip_metadata(payload)) == {:ok, "{\"params\":{}}"}
    end

    property "canonical payload bytes are invariant under attached metadata" do
      check all(
              payload <- payload_map(),
              envelope <- metadata_map(),
              token <- string(:alphanumeric, min_length: 1),
              max_runs: 50
            ) do
        stripped = Attestation.strip_metadata(payload)

        with {:ok, expected} <- JCS.encode(stripped) do
          attached =
            payload
            |> Attestation.attach(envelope)
            |> Attestation.attach_confirmation(token)
            |> Map.put(:confirmation_token, token)
            |> put_params_metadata(envelope, token)

          assert Attestation.strip_metadata(attached) == stripped
          assert JCS.encode(Attestation.strip_metadata(attached)) == {:ok, expected}
        end
      end
    end
  end

  defp put_params_metadata(payload, envelope, token) do
    case Map.fetch(payload, "params") do
      {:ok, params} when is_map(params) ->
        params =
          params
          |> Map.put("_agent_trust", envelope)
          |> Map.put(:_agent_confirmation, token)
          |> Map.put("confirmation_token", token)

        Map.put(payload, "params", params)

      _ ->
        payload
    end
  end

  defp payload_map do
    map_of(
      one_of([
        member_of(["method", "name", "params", "value", "nested"]),
        string(:alphanumeric, min_length: 1, max_length: 8)
      ]),
      payload_value(),
      max_length: 5
    )
  end

  defp payload_value do
    one_of([
      string(:alphanumeric, max_length: 16),
      integer(0..100),
      boolean(),
      map_of(
        string(:alphanumeric, min_length: 1, max_length: 8),
        string(:alphanumeric, max_length: 8),
        max_length: 3
      )
    ])
  end

  defp metadata_map do
    map_of(
      string(:alphanumeric, min_length: 1, max_length: 8),
      string(:alphanumeric, max_length: 8),
      min_length: 1,
      max_length: 3
    )
  end
end
