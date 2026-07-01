defmodule SigilGuard.ProfileTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Profile

  describe "profiles/0" do
    test "lists supported compatibility profiles" do
      assert Profile.profiles() == [
               :auto,
               :legacy_sigil_guard,
               :sigil_reference_0_1,
               :sigil_spec_draft_2026_02
             ]
    end
  end

  describe "normalize!/1" do
    test "accepts known profiles and rejects unknown profiles" do
      assert Profile.normalize!(:auto) == :auto

      assert_raise ArgumentError, ~r/invalid :sigil_guard protocol_profile/, fn ->
        Profile.normalize!(:unknown)
      end
    end
  end

  describe "wire and registry behavior" do
    test "keeps legacy and draft compatibility differences explicit" do
      assert Profile.wire_verdict_format(:legacy_sigil_guard) == :legacy_titlecase
      assert Profile.wire_verdict_format(:sigil_reference_0_1) == :lowercase

      assert Profile.verdict_acceptance(:sigil_spec_draft_2026_02) == :lowercase_only
      assert Profile.verdict_acceptance(:legacy_sigil_guard) == :legacy_and_lowercase

      assert Profile.require_blocked_reason_on_verify?(:sigil_spec_draft_2026_02)
      refute Profile.require_blocked_reason_on_verify?(:auto)

      assert Profile.registry_identity_endpoints(:legacy_sigil_guard) == [:identities, :resolve]
      assert Profile.registry_identity_endpoints(:sigil_spec_draft_2026_02) == [:resolve]
      assert Profile.registry_identity_endpoints(:auto) == [:resolve, :identities]
    end
  end
end
