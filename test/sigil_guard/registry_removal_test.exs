defmodule SigilGuard.RegistryRemovalTest do
  use ExUnit.Case, async: true

  @removed_module SigilGuard.Registry
  @removed_functions [
    {:fetch_bundle, []},
    {:resolve_did, ["did:example:alice"]},
    {:resolve_key, ["did:example:alice"]},
    {:fetch_policies, []}
  ]

  describe "v3 registry adapter removal" do
    test "SigilGuard.Registry is deleted, not hidden" do
      refute Code.ensure_loaded?(@removed_module)
    end

    test "removed public calls raise UndefinedFunctionError cleanly" do
      for {function, args} <- @removed_functions do
        assert_raise UndefinedFunctionError, fn ->
          apply(@removed_module, function, args)
        end
      end
    end
  end
end
