defmodule SigilGuard.MutationReport do
  @moduledoc false
  @source_hash "78fbc726abf4e730b44cfc1f8d4c86595c82e82a62023176f06bb95a68322837"
  @equivalents [
    {"%{allow: 0, redact: 1, confirm: 2, quarantine: 3, block: 4}",
     "%{redact: 1, allow: 0, confirm: 2, quarantine: 3, block: 4}"},
    {"strongest(a, b)", "strongest(b, a)"},
    {"rank(a) >= rank(b)", "rank(a) > rank(b)"}
  ]

  @doc false
  def validate(%{"mutations" => mutations}, source) when is_list(mutations) do
    hash = Base.encode16(:crypto.hash(:sha256, source), case: :lower)
    killed = Enum.count(mutations, &(&1["status"] == "killed"))
    equivalent = Enum.count(mutations, &equivalent?(&1, hash))
    invalid = Enum.count(mutations, &compiler_invalid?/1)

    if killed > 0 and killed + equivalent + invalid == length(mutations) do
      {:ok, %{killed: killed, equivalent: equivalent, invalid: invalid, behavioral_score: 100}}
    else
      {:error, :unaccounted_mutations}
    end
  end

  def validate(_, _), do: {:error, :invalid_report}

  defp equivalent?(%{"status" => "survived", "patch" => patch, "location" => location}, hash) do
    hash == @source_hash and location["file"] == "lib/sigil_guard/verdict.ex" and
      {patch["before"], patch["after"]} in @equivalents
  end

  defp equivalent?(_, _), do: false

  defp compiler_invalid?(%{"status" => "invalid", "error" => error}) when is_binary(error),
    do:
      String.starts_with?(error, "{:compile_error,") and
        String.contains?(error, "== Compilation error")

  defp compiler_invalid?(_), do: false
end

case System.argv() do
  ["--report", path] ->
    log = File.read!(path)
    {start, _} = :binary.match(log, "{\n  \"summary\"")
    # Muex appends its threshold failure after the JSON object.
    json = binary_part(log, start, byte_size(log) - start) |> String.split("\n** (Mix)") |> hd()
    report = Jason.decode!(String.trim(json))
    source = File.read!("lib/sigil_guard/verdict.ex")

    case SigilGuard.MutationReport.validate(report, source) do
      {:ok, result} -> IO.inspect(result, label: "Verified verdict mutation accounting")
      {:error, reason} -> Mix.raise("mutation gate failed: #{reason}; inspect #{path}")
    end

  _ ->
    :ok
end
