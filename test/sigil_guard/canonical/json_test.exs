defmodule SigilGuard.Canonical.JSONTest do
  @moduledoc false

  use ExUnit.Case, async: true

  alias SigilGuard.Canonical.JSON
  alias SigilGuard.Canonical.LegacyJSON

  test "decodes native JSON values without numeric or literal coercion" do
    assert {:ok, value} = JSON.decode(~s({"values":[null,true,false,1,1.0,{"empty":[]}]}))
    assert value === %{"values" => [nil, true, false, 1, 1.0, %{"empty" => []}]}
    assert {:ok, %{}} = JSON.decode("{}")
    assert {:ok, nil} = JSON.decode("null")
  end

  test "rejects duplicate keys at any depth, including escaped aliases" do
    for bytes <- [
          ~s({"a":1,"a":2}),
          ~s({"a":1,"a":1}),
          ~S({"a":1,"\u0061":2}),
          ~s([{"nested":{"key":null,"key":false}}])
        ] do
      assert JSON.decode(bytes) == {:error, :invalid_json}
    end
  end

  test "classifies invalid JSON and input types" do
    for bytes <- ["{", <<255>>, "[1,]", nil] do
      assert JSON.decode(bytes) == {:error, :invalid_json}
    end
  end

  test "legacy bytes reject normalized collisions while preserving native values" do
    for value <- [%{:a => 1, "a" => 2}, %{nested: [%{1 => true, "1" => false}]}] do
      assert_raise ArgumentError, ~r/duplicate JSON object key/, fn ->
        LegacyJSON.encode(value)
      end
    end

    bytes = LegacyJSON.encode(%{1 => :ok, :values => [nil, true, false, 1, 1.0]})
    assert IO.iodata_to_binary(bytes) == ~s({"1":"ok","values":[null,true,false,1,1.0]})
  end
end
