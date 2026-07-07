defmodule SigilGuard.BoundaryPolicy.Contract do
  @moduledoc """
  Sink-aware output contracts and their transforms.

  A contract is a per-sink guarantee applied to content the final verdict lets
  cross a boundary: a byte cap, a credential re-scan, PII digesting, and an
  allowed-content-class check. `parse/1` compiles the `[contracts]` lines of a
  boundary-policy file into a `%{sink => %Contract{}}` map; each sink may appear
  in at most one contract.

  The three transforms are pure:

  - `truncate/2` keeps the longest UTF-8 prefix within `max_size` and appends
    the 11-byte `[TRUNCATED]` marker.
  - `hash/1` replaces a span with `"sha256:" <> hex` (71 bytes).
  - `mask/1` replaces every codepoint of a span with `*`.

  Parsing rejects duplicate sinks, unknown fields, invalid classes, and a
  `max_size` below 64 with `:invalid_output_contract`; a `credential_transform`
  other than `mask`/`hash` fails with `:unknown_transform`.
  """

  @min_max_size 64
  @marker "[TRUNCATED]"

  @content_classes %{"text" => :text, "structured" => :structured}
  @transforms %{"mask" => :mask, "hash" => :hash}
  @contract_keys ~w(sink max_size no_raw_credentials digest_only_pii classes credential_transform)

  @typedoc "A credential-violation transform."
  @type transform :: :mask | :hash

  @typedoc "An allowed outbound content class from the SP.01 payload class."
  @type content_class :: :text | :structured

  @typedoc "Outbound content: UTF-8 `text` binary or a `structured` map/list."
  @type content :: binary() | map() | list()

  @typedoc """
  A compiled per-sink output contract. `max_size` `nil` is unlimited; `classes`
  `nil` allows every class.
  """
  @type t :: %__MODULE__{
          max_size: pos_integer() | nil,
          no_raw_credentials: boolean(),
          digest_only_pii: boolean(),
          classes: [content_class()] | nil,
          credential_transform: transform()
        }

  defstruct max_size: nil,
            no_raw_credentials: false,
            digest_only_pii: false,
            classes: nil,
            credential_transform: :mask

  @type parse_error :: :invalid_output_contract | :unknown_transform

  @doc """
  Compile folded `[contracts]` lines into a `%{sink => %Contract{}}` map.

  Each line is `contract sink:<csv> { field }`. A sink already claimed by an
  earlier contract fails `:invalid_output_contract`.
  """
  @spec parse([String.t()]) :: {:ok, %{optional(String.t()) => t()}} | {:error, parse_error()}
  def parse(lines) when is_list(lines) do
    Enum.reduce_while(lines, {:ok, %{}}, fn line, {:ok, acc} ->
      case parse_line(line, acc) do
        {:ok, acc} -> {:cont, {:ok, acc}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  @doc """
  Apply the `sink` contract to outbound `content` in the normative order.

  Evaluation order (SP.04): content class check, then `credential_transform`
  replacements, then `digest_only_pii` replacements, then `max_size`
  truncation. A disallowed content class is not transformable and escalates:
  `enforce/4` returns `{:block, "contract.<sink>.class"}`. A `:verdict` of
  `:block` or `:quarantine` skips the contract entirely - nothing crosses, so
  there is nothing to transform.

  The credential and PII scans are the host's: pass the outbound-scan matches
  as `:credentials` and `:pii` (lists of matched substrings). `no_raw_credentials`
  replaces each `:credentials` match with the contract transform; `digest_only_pii`
  replaces each `:pii` match with `hash/1`. Text transforms apply only to `text`
  content; a `structured` payload that passes the class check crosses unchanged.

  Options: `:verdict` (default `:allow`), `:credentials` (default `[]`),
  `:pii` (default `[]`).
  """
  @spec enforce(t() | nil, String.t(), content(), keyword()) ::
          {:ok, content()} | {:block, String.t()}
  def enforce(contract, sink, content, opts \\ [])

  def enforce(nil, _, content, _), do: {:ok, content}

  def enforce(%__MODULE__{} = contract, sink, content, opts) do
    case Keyword.get(opts, :verdict, :allow) do
      verdict when verdict in [:block, :quarantine] -> {:ok, content}
      _ -> run(contract, sink, content, opts)
    end
  end

  @doc """
  Cap `content` at `max_size` bytes, appending the `[TRUNCATED]` marker.

  Content already within `max_size` is returned unchanged. Otherwise the result
  is the longest UTF-8-valid prefix of at most `max_size - 11` bytes plus the
  11-byte marker: always valid UTF-8 and never above `max_size` bytes.

  ## Examples

      iex> SigilGuard.BoundaryPolicy.Contract.truncate("fits", 64)
      "fits"

      iex> byte_size(SigilGuard.BoundaryPolicy.Contract.truncate(String.duplicate("x", 200), 64))
      64

  """
  @spec truncate(binary(), pos_integer()) :: binary()
  def truncate(content, max_size) when is_binary(content) and is_integer(max_size) do
    if byte_size(content) <= max_size do
      content
    else
      valid_prefix(content, max_size - byte_size(@marker)) <> @marker
    end
  end

  @doc """
  Replace a span with `"sha256:" <> hex`, the lowercase-hex SHA-256 of its bytes.

  ## Examples

      iex> SigilGuard.BoundaryPolicy.Contract.hash("secret")
      "sha256:2bb80d537b1da3e38bd30361aa855686bde0eacd7162fef6a25fe97bf527a25b"

  """
  @spec hash(binary()) :: String.t()
  def hash(span) when is_binary(span) do
    "sha256:" <> Base.encode16(:crypto.hash(:sha256, span), case: :lower)
  end

  @doc """
  Replace every Unicode codepoint of a span with `*`, preserving codepoint count.

  ## Examples

      iex> SigilGuard.BoundaryPolicy.Contract.mask("tkn")
      "***"

  """
  @spec mask(binary()) :: binary()
  def mask(span) when is_binary(span) do
    String.duplicate("*", length(String.codepoints(span)))
  end

  defp run(contract, sink, content, opts) do
    if class_allowed?(contract, content) do
      {:ok, transform_content(contract, content, opts)}
    else
      {:block, "contract.#{sink}.class"}
    end
  end

  defp class_allowed?(%__MODULE__{classes: nil}, _), do: true

  defp class_allowed?(%__MODULE__{classes: classes}, content) do
    content_class(content) in classes
  end

  defp content_class(content) when is_binary(content), do: :text
  defp content_class(_), do: :structured

  defp transform_content(contract, content, opts) when is_binary(content) do
    content
    |> apply_credentials(contract, opts)
    |> apply_pii(contract, opts)
    |> apply_truncate(contract)
  end

  defp transform_content(_, content, _), do: content

  defp apply_credentials(text, %__MODULE__{no_raw_credentials: false}, _), do: text

  defp apply_credentials(text, %__MODULE__{no_raw_credentials: true} = contract, opts) do
    replace_spans(Keyword.get(opts, :credentials, []), text, credential_fun(contract))
  end

  defp apply_pii(text, %__MODULE__{digest_only_pii: false}, _), do: text

  defp apply_pii(text, %__MODULE__{digest_only_pii: true}, opts) do
    replace_spans(Keyword.get(opts, :pii, []), text, &hash/1)
  end

  defp apply_truncate(text, %__MODULE__{max_size: nil}), do: text
  defp apply_truncate(text, %__MODULE__{max_size: max_size}), do: truncate(text, max_size)

  defp credential_fun(%__MODULE__{credential_transform: :hash}), do: &hash/1
  defp credential_fun(%__MODULE__{credential_transform: :mask}), do: &mask/1

  defp replace_spans(matches, text, fun) do
    matches
    |> Enum.uniq()
    |> Enum.reject(&(&1 == ""))
    |> Enum.reduce(text, fn value, acc -> String.replace(acc, value, fun.(value)) end)
  end

  defp valid_prefix(_, max_bytes) when max_bytes <= 0, do: ""

  defp valid_prefix(binary, max_bytes) do
    binary
    |> binary_part(0, min(max_bytes, byte_size(binary)))
    |> trim_to_valid()
  end

  defp trim_to_valid(slice) do
    if String.valid?(slice) do
      slice
    else
      trim_to_valid(binary_part(slice, 0, byte_size(slice) - 1))
    end
  end

  defp parse_line(line, acc) do
    case String.split(line, " ", trim: true) do
      ["contract" | fields] when fields != [] ->
        with {:ok, raw} <- collect_fields(fields),
             {:ok, sinks, contract} <- build(raw) do
          add_sinks(acc, sinks, contract)
        end

      _ ->
        {:error, :invalid_output_contract}
    end
  end

  defp collect_fields(fields) do
    Enum.reduce_while(fields, {:ok, %{}}, fn token, {:ok, raw} ->
      case String.split(token, ":", parts: 2) do
        [key, value] -> collect_field(key, value, raw)
        _ -> {:halt, {:error, :invalid_output_contract}}
      end
    end)
  end

  defp collect_field(key, value, raw) do
    cond do
      key not in @contract_keys -> {:halt, {:error, :invalid_output_contract}}
      Map.has_key?(raw, key) -> {:halt, {:error, :invalid_output_contract}}
      true -> {:cont, {:ok, Map.put(raw, key, value)}}
    end
  end

  defp build(raw) do
    with {:ok, sinks} <- build_sinks(raw),
         {:ok, max_size} <- build_max_size(raw),
         {:ok, classes} <- build_classes(raw),
         {:ok, transform} <- build_transform(raw),
         {:ok, no_raw} <- build_bool(raw, "no_raw_credentials"),
         {:ok, pii} <- build_bool(raw, "digest_only_pii") do
      {:ok, sinks,
       %__MODULE__{
         max_size: max_size,
         no_raw_credentials: no_raw,
         digest_only_pii: pii,
         classes: classes,
         credential_transform: transform
       }}
    end
  end

  defp build_sinks(raw) do
    case Map.fetch(raw, "sink") do
      {:ok, value} -> non_empty_csv(value)
      :error -> {:error, :invalid_output_contract}
    end
  end

  defp build_max_size(raw) do
    case Map.fetch(raw, "max_size") do
      :error ->
        {:ok, nil}

      {:ok, value} ->
        case Integer.parse(value) do
          {n, ""} when n >= @min_max_size -> {:ok, n}
          _ -> {:error, :invalid_output_contract}
        end
    end
  end

  defp build_classes(raw) do
    case Map.fetch(raw, "classes") do
      :error ->
        {:ok, nil}

      {:ok, value} ->
        with {:ok, parts} <- non_empty_csv(value),
             classes when is_list(classes) <- map_classes(parts) do
          {:ok, classes}
        else
          _ -> {:error, :invalid_output_contract}
        end
    end
  end

  defp map_classes(parts) do
    if Enum.all?(parts, &Map.has_key?(@content_classes, &1)) do
      parts
      |> Enum.map(&Map.fetch!(@content_classes, &1))
      |> Enum.uniq()
    else
      :error
    end
  end

  defp build_transform(raw) do
    case Map.fetch(raw, "credential_transform") do
      :error ->
        {:ok, :mask}

      {:ok, value} ->
        case Map.fetch(@transforms, value) do
          {:ok, atom} -> {:ok, atom}
          :error -> {:error, :unknown_transform}
        end
    end
  end

  defp build_bool(raw, key) do
    case Map.fetch(raw, key) do
      :error -> {:ok, false}
      {:ok, "true"} -> {:ok, true}
      {:ok, "false"} -> {:ok, false}
      {:ok, _} -> {:error, :invalid_output_contract}
    end
  end

  defp non_empty_csv(value) do
    parts = String.split(value, ",", trim: false)
    if Enum.all?(parts, &(&1 != "")), do: {:ok, parts}, else: {:error, :invalid_output_contract}
  end

  defp add_sinks(acc, sinks, contract) do
    Enum.reduce_while(sinks, {:ok, acc}, fn sink, {:ok, acc} ->
      if Map.has_key?(acc, sink) do
        {:halt, {:error, :invalid_output_contract}}
      else
        {:cont, {:ok, Map.put(acc, sink, contract)}}
      end
    end)
  end
end
