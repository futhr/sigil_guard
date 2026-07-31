defmodule SigilGuard.MCP.ProtocolTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.MCP.Protocol

  doctest Protocol

  test "selects explicit and request-scoped protocol versions" do
    request = %{
      "params" => %{
        "_meta" => %{
          "io.modelcontextprotocol/protocolVersion" => "2026-07-28"
        }
      }
    }

    assert Protocol.current_version() == "2026-07-28"
    assert Protocol.version(request) == "2026-07-28"
    assert Protocol.version(request, protocol_version: "2027-01-01") == "2027-01-01"
    assert Protocol.modern?(request)
    refute Protocol.modern?(request, protocol_version: "2025-11-25")
    refute Protocol.modern?(request, protocol_version: "2027-01-01")
    refute Protocol.modern?(request, protocol_version: "v2")

    root_meta = %{
      _meta: %{"io.modelcontextprotocol/protocolVersion" => "2026-07-28"}
    }

    assert Protocol.version(root_meta, :invalid_options) == "2026-07-28"
    assert Protocol.version(%{}) == nil
  end

  test "recognizes multi-round-trip results and preserves their discriminator" do
    interim = %{"resultType" => "input_required", "requestState" => "state-1"}

    assert Protocol.result_type(%{"result" => interim}) == "input_required"
    assert Protocol.result_type(%{result: %{result_type: "complete"}}) == "complete"
    assert Protocol.result_type(%{resultType: "complete"}) == "complete"
    assert Protocol.result_type(%{"result_type" => "complete"}) == "complete"
    assert Protocol.input_required?(interim)

    result =
      Protocol.ensure_result_type(interim, %{}, protocol_version: Protocol.current_version())

    assert result == interim
  end

  test "adds complete only for modern direct result maps" do
    result = %{"content" => [%{"type" => "text", "text" => "done"}]}

    assert Protocol.ensure_result_type(result, %{}, protocol_version: Protocol.current_version()) ==
             Map.put(result, "resultType", "complete")

    assert Protocol.ensure_result_type(result, %{}, protocol_version: "2025-11-25") == result
    assert Protocol.ensure_result_type(result, %{}, protocol_version: "2027-01-01") == result
    assert Protocol.ensure_result_type(result, %{}, :invalid_options) == result
    assert Protocol.ensure_result_type("done", %{}, protocol_version: "2026-07-28") == "done"

    malformed = %{"resultType" => 42, "content" => []}

    assert Protocol.ensure_result_type(
             malformed,
             %{},
             protocol_version: Protocol.current_version()
           ) == malformed

    atom_malformed = %{resultType: :complete, content: []}

    assert Protocol.ensure_result_type(
             atom_malformed,
             %{},
             protocol_version: Protocol.current_version()
           ) == atom_malformed
  end
end
