defmodule SigilGuard.Audit.ActorTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Audit.Actor

  test "captures actor fields with nil defaults" do
    assert %Actor{} = actor = %Actor{}
    assert actor.channel == nil
    assert actor.user_id == nil
    assert actor.username == nil
  end

  test "stores actor identity facts without coercion" do
    actor = %Actor{channel: "mcp", user_id: "did:web:alice", username: "Alice"}

    assert actor.channel == "mcp"
    assert actor.user_id == "did:web:alice"
    assert actor.username == "Alice"
  end
end
