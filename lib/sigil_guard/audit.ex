defmodule SigilGuard.Audit do
  @moduledoc """
  Tamper-evident audit logging for SigilGuard runtime decisions.

  Provides structured audit events with HMAC-SHA256 chain integrity.
  Each event's HMAC incorporates the previous event's HMAC, forming a
  hash chain that detects any tampering, insertion, or deletion of events.

  ## Chain Integrity

  The HMAC chain works as follows:

  1. First event: `HMAC(key, canonical_bytes(event) <> "genesis")`
  2. Subsequent events: `HMAC(key, canonical_bytes(event) <> prev_hmac)`

  Verification walks the chain, enforcing that each event links to its
  actual predecessor (the first event's `prev_hmac` must be `nil`, every
  later event's must equal the previous event's `hmac`) and recomputing
  each HMAC. Within the verified sequence this detects modification,
  insertion, deletion, and reordering of events.

  ### What the chain cannot detect

  Truncation of the chain *tail* is undetectable from the events alone:
  a chain with its last events removed is still a valid chain. To defend
  against truncation, persist the most recent `hmac` out of band and
  compare it to the last event's, or verify continuation segments
  against a stored tip via the `:prev_hmac` option of `verify_chain/3`.
  For portable truncation evidence, export signed Merkle checkpoints with
  `SigilGuard.Audit.Checkpoint`, or use `SigilGuard.Audit.Export` to package
  a signed checkpoint and external anchor record for append-only or WORM
  storage.

  ## Audit Logger Behaviour

  Implement `SigilGuard.Audit.Logger` to persist audit events to your
  preferred backend (database, file, external service):

      defmodule MyApp.AuditLogger do
        @behaviour SigilGuard.Audit.Logger

        @impl true
        def log(event) do
          MyApp.Repo.insert!(event_to_schema(event))
          :ok
        end
      end

  """

  alias SigilGuard.Telemetry

  @type event_type :: String.t()

  @type t :: %__MODULE__{
          id: String.t(),
          type: event_type(),
          actor: String.t(),
          action: String.t(),
          result: String.t(),
          metadata: map(),
          timestamp: String.t(),
          prev_hmac: String.t() | nil,
          hmac: String.t() | nil,
          event_type: SigilGuard.Audit.EventType.t() | nil,
          actor_info: SigilGuard.Audit.Actor.t() | nil,
          action_info: SigilGuard.Audit.Action.t() | nil,
          result_info: SigilGuard.Audit.ExecutionResult.t() | nil
        }

  @enforce_keys [:id, :type, :actor, :action, :result, :timestamp]
  defstruct [
    :id,
    :type,
    :actor,
    :action,
    :result,
    :timestamp,
    :prev_hmac,
    :hmac,
    :event_type,
    :actor_info,
    :action_info,
    :result_info,
    metadata: %{}
  ]

  @genesis_marker "genesis"
  @field_hash_prefix "fh1:"
  @redacted_placeholder "redacted-v1"

  @doc """
  Return the privacy-hashed form of a field value.

  `hash_field(value, field_hash_key)` returns
  `"fh1:" <> lowercase-hex HMAC-SHA256(field_hash_key, value)`. The field-hash
  key is host-supplied per call and MUST differ from the chain HMAC key. When no
  key (or an empty/non-binary key or value) is supplied the value fails closed to
  the fixed `"redacted-v1"` placeholder - never a silent clear value.

  ## Examples

      SigilGuard.Audit.hash_field("did:web:alice", field_hash_key)
      # => "fh1:9a0b..."

      SigilGuard.Audit.hash_field("did:web:alice", nil)
      # => "redacted-v1"

  """
  @spec hash_field(String.t(), binary() | nil) :: String.t()
  def hash_field(value, field_hash_key)

  def hash_field(value, field_hash_key)
      when is_binary(value) and is_binary(field_hash_key) and field_hash_key != "" do
    @field_hash_prefix <>
      Base.encode16(:crypto.mac(:hmac, :sha256, field_hash_key, value), case: :lower)
  end

  def hash_field(_, _), do: @redacted_placeholder

  @doc """
  Apply per-field privacy classification to an event's signed fields.

  The `hashed`-class `actor` field is replaced by its `hash_field/2` form; the
  `clear`-class fields (`id`, `type`, `action`, `result`, `timestamp`) are left
  verbatim. `metadata` is outside the chain preimage (host-classified) and is not
  transformed. Apply `classify/2` **before** `sign_event/3` so the chain HMAC and
  Merkle root cover the hashed actor - destroying the field-hash key
  (crypto-erasure) then leaves every chain and proof verification green.

  Options:

    * `:field_hash_key` - HMAC key for hashing the actor (host-supplied).
    * `:chain_key` - when equal to `:field_hash_key`, the actor fails closed to
      `"redacted-v1"` (the field-hash key MUST differ from the chain key).

  An already-classified `actor` (`"fh1:"`-prefixed or the redacted placeholder)
  is left unchanged, so `classify/2` is idempotent.
  """
  @spec classify(t(), keyword()) :: t()
  def classify(event, opts \\ [])

  def classify(%__MODULE__{} = event, opts) when is_list(opts) do
    %{event | actor: classify_actor(event.actor, effective_field_hash_key(opts))}
  end

  defp effective_field_hash_key(opts) do
    field_hash_key = Keyword.get(opts, :field_hash_key)

    if is_binary(field_hash_key) and field_hash_key == Keyword.get(opts, :chain_key) do
      nil
    else
      field_hash_key
    end
  end

  defp classify_actor(@redacted_placeholder, _), do: @redacted_placeholder
  defp classify_actor(@field_hash_prefix <> _ = actor, _), do: actor
  defp classify_actor(actor, field_hash_key), do: hash_field(actor, field_hash_key)

  @doc """
  Create a new audit event (unsigned).

  The event gets a unique ID and timestamp but no HMAC yet.
  Call `sign_event/2` or `sign_event/3` to add chain integrity.

  ## Examples

      event = SigilGuard.Audit.new_event("mcp.tool_call", "did:web:alice", "read_file", "success")

  """
  @spec new_event(event_type(), String.t(), String.t(), String.t(), map()) :: t()
  def new_event(type, actor, action, result, metadata \\ %{}) do
    %__MODULE__{
      id: generate_event_id(),
      type: type,
      actor: actor,
      action: action,
      result: result,
      metadata: metadata,
      timestamp: generate_timestamp()
    }
  end

  @doc """
  Sign an event with an HMAC, linking it to the previous event in the chain.

  For the first event in a chain, pass `nil` as `prev_hmac`.

  ## Examples

      # First event in chain
      signed = SigilGuard.Audit.sign_event(event, secret_key)

      # Subsequent events
      signed = SigilGuard.Audit.sign_event(event, secret_key, prev_event.hmac)

  """
  @spec sign_event(t(), binary(), String.t() | nil) :: t()
  def sign_event(event, key, prev_hmac \\ nil) do
    chain_input = chain_input!(prev_hmac)
    canonical = canonical_iodata(event)
    hmac = compute_hmac(key, [canonical, chain_input])

    Telemetry.emit(
      [:sigil_guard, :audit, :logged],
      %{system_time: System.system_time()},
      %{event_type: event.type, actor: event.actor, action: event.action, result: event.result}
    )

    %{event | hmac: hmac, prev_hmac: prev_hmac}
  end

  @doc """
  Verify the integrity of an audit event chain.

  Returns `:ok` if the chain is contiguous and every HMAC is valid, or
  `{:broken, index}` identifying the first event that fails.

  An event fails verification if its `prev_hmac` does not link to its
  actual predecessor's `hmac` (or to the `:prev_hmac` anchor/genesis for
  the first event), or if its recomputed HMAC does not match. This
  detects tampered, deleted, inserted, and reordered events. Truncation
  of the chain tail cannot be detected — see the module documentation.

  ## Options

    * `:prev_hmac` — verify a segment that continues from a known tip
      rather than from genesis. Pass the `hmac` of the event immediately
      preceding the segment (default: `nil`, the chain starts at genesis).

  ## Examples

      :ok = SigilGuard.Audit.verify_chain(events, secret_key)

      {:broken, 3} = SigilGuard.Audit.verify_chain(tampered_events, secret_key)

      # Verify a continuation segment against a persisted tip
      :ok = SigilGuard.Audit.verify_chain(segment, secret_key, prev_hmac: stored_tip)

  """
  @spec verify_chain([t()], binary(), keyword()) :: :ok | {:broken, non_neg_integer()}
  def verify_chain(events, key, opts \\ []) do
    anchor = Keyword.get(opts, :prev_hmac)

    case chain_input(anchor) do
      {:ok, _} -> verify_chain_events(events, key, anchor)
      :error -> {:broken, 0}
    end
  end

  @doc """
  Build a chain of signed events from a list of unsigned events.

  Signs each event in sequence, linking each to the previous via HMAC.

  ## Examples

      unsigned = [event1, event2, event3]
      signed = SigilGuard.Audit.build_chain(unsigned, secret_key)
      :ok = SigilGuard.Audit.verify_chain(signed, secret_key)

  """
  @spec build_chain([t()], binary()) :: [t()]
  def build_chain(events, key) do
    {signed, _} =
      Enum.map_reduce(events, nil, fn event, prev_hmac ->
        signed = sign_event(event, key, prev_hmac)
        {signed, signed.hmac}
      end)

    signed
  end

  @doc """
  Produce the canonical byte representation of an event for HMAC computation.

  Fields are serialized as compact JSON with lexicographic key order.
  Only `id`, `type`, `actor`, `action`, `result`, `timestamp` are included
  (not `hmac`, `prev_hmac`, or `metadata`).
  """
  @spec canonical_bytes(t()) :: binary()
  def canonical_bytes(%__MODULE__{} = event) do
    IO.iodata_to_binary(canonical_iodata(event))
  end

  @typedoc "The chain tip's coordinates (`tip/1`)."
  @type tip :: %{
          index: non_neg_integer(),
          event_id: String.t(),
          hmac: String.t(),
          timestamp: String.t()
        }

  @typedoc "One checkpoint's located event span (`checkpoint_boundaries/2`)."
  @type boundary :: %{
          checkpoint_digest: String.t(),
          tree_size: non_neg_integer(),
          first_index: non_neg_integer() | nil,
          last_index: non_neg_integer() | nil
        }

  @query_keys [:from_index, :to_index, :id, :type, :from_time, :to_time]

  @doc """
  Return the last event's coordinates without verifying the chain.

  A pure read: it never writes and emits no telemetry (verification stays in
  `verify_chain/3`). An empty list fails `:empty_chain`; an unsigned last event
  fails `:unsigned_event`.
  """
  @spec tip([t()]) :: {:ok, tip()} | {:error, :empty_chain | :unsigned_event}
  def tip([]), do: {:error, :empty_chain}

  def tip(events) when is_list(events) do
    case List.last(events) do
      %__MODULE__{hmac: hmac} = event when is_binary(hmac) and hmac != "" ->
        {:ok,
         %{index: length(events) - 1, event_id: event.id, hmac: hmac, timestamp: event.timestamp}}

      _ ->
        {:error, :unsigned_event}
    end
  end

  @doc """
  Return the events matching a closed set of filters, in chain order.

  A pure read: no writes, no telemetry. The options `:from_index`, `:to_index`,
  `:id`, `:type`, `:from_time`, and `:to_time` compose with AND. Options must be
  a keyword list; a malformed list, unknown key, or unparsable time fails
  `:invalid_query`. An index outside `0..length-1` (or `:to_index` below
  `:from_index`) fails `:out_of_range`. An empty match is `{:ok, []}`, never an
  error.
  """
  @spec query([t()], keyword()) :: {:ok, [t()]} | {:error, :out_of_range | :invalid_query}
  def query(events, opts \\ [])

  def query(events, opts) when is_list(events) and is_list(opts) do
    with :ok <- validate_query_keys(opts),
         {:ok, from_index, to_index} <- query_index_range(opts, length(events)),
         {:ok, from_time, to_time} <- query_time_range(opts) do
      bounds = {from_index, to_index, from_time, to_time}

      matched =
        events
        |> Enum.with_index()
        |> Enum.filter(&query_match?(&1, opts, bounds))
        |> Enum.map(fn {event, _} -> event end)

      {:ok, matched}
    end
  end

  def query(_, _), do: {:error, :invalid_query}

  @doc """
  Locate each checkpoint's event span within `events`.

  A pure read: no writes, no telemetry. For each checkpoint it finds the
  `first_event_id`/`last_event_id` in `events` and checks the span length
  against `event_count`; any mismatch fails `:checkpoint_mismatch`. An empty
  checkpoint yields `nil` indices, and a non-checkpoint term fails
  `:invalid_query`.
  """
  @spec checkpoint_boundaries([t()], [SigilGuard.Audit.Checkpoint.t()]) ::
          {:ok, [boundary()]} | {:error, :checkpoint_mismatch | :invalid_query}
  def checkpoint_boundaries(events, checkpoints)
      when is_list(events) and is_list(checkpoints) do
    index_by_id = Map.new(Enum.with_index(events), fn {event, index} -> {event.id, index} end)

    result =
      Enum.reduce_while(checkpoints, {:ok, []}, fn checkpoint, {:ok, acc} ->
        case checkpoint_boundary(checkpoint, index_by_id) do
          {:ok, boundary} -> {:cont, {:ok, [boundary | acc]}}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)

    case result do
      {:ok, boundaries} -> {:ok, Enum.reverse(boundaries)}
      error -> error
    end
  end

  def checkpoint_boundaries(_, _), do: {:error, :invalid_query}

  defp validate_query_keys(opts) do
    if Keyword.keyword?(opts) and Enum.all?(Keyword.keys(opts), &(&1 in @query_keys)),
      do: :ok,
      else: {:error, :invalid_query}
  end

  defp query_index_range(opts, count) do
    with {:ok, from} <- validate_from_index(Keyword.get(opts, :from_index), count),
         {:ok, to} <- validate_to_index(Keyword.get(opts, :to_index), count, from) do
      {:ok, from, to}
    end
  end

  defp validate_from_index(nil, _), do: {:ok, 0}

  defp validate_from_index(from, count) when is_integer(from) and from >= 0 do
    if from >= count, do: {:error, :out_of_range}, else: {:ok, from}
  end

  defp validate_from_index(_, _), do: {:error, :invalid_query}

  defp validate_to_index(nil, count, _), do: {:ok, count - 1}

  defp validate_to_index(to, count, from) when is_integer(to) and to >= 0 do
    if to >= count or to < from, do: {:error, :out_of_range}, else: {:ok, to}
  end

  defp validate_to_index(_, _, _), do: {:error, :invalid_query}

  defp query_time_range(opts) do
    with {:ok, from} <- parse_query_time(Keyword.get(opts, :from_time)),
         {:ok, to} <- parse_query_time(Keyword.get(opts, :to_time)) do
      {:ok, from, to}
    end
  end

  defp parse_query_time(nil), do: {:ok, nil}

  defp parse_query_time(value) when is_binary(value) do
    case DateTime.from_iso8601(value) do
      {:ok, datetime, _} -> {:ok, datetime}
      _ -> {:error, :invalid_query}
    end
  end

  defp parse_query_time(_), do: {:error, :invalid_query}

  defp query_match?({event, index}, opts, {from_index, to_index, from_time, to_time}) do
    index >= from_index and index <= to_index and
      option_match?(Keyword.get(opts, :id), event.id) and
      option_match?(Keyword.get(opts, :type), event.type) and
      within_time?(event.timestamp, from_time, to_time)
  end

  defp option_match?(nil, _), do: true
  defp option_match?(expected, value), do: expected == value

  defp within_time?(_, nil, nil), do: true

  defp within_time?(timestamp, from, to) do
    case DateTime.from_iso8601(timestamp) do
      {:ok, datetime, _} ->
        after_or_equal?(datetime, from) and before_or_equal?(datetime, to)

      _ ->
        false
    end
  end

  defp after_or_equal?(_, nil), do: true
  defp after_or_equal?(datetime, from), do: DateTime.compare(datetime, from) != :lt

  defp before_or_equal?(_, nil), do: true
  defp before_or_equal?(datetime, to), do: DateTime.compare(datetime, to) != :gt

  defp checkpoint_boundary(checkpoint, index_by_id) when is_map(checkpoint) do
    case Map.get(checkpoint, "event_count") do
      count when is_integer(count) and count >= 0 ->
        build_boundary(checkpoint, count, index_by_id)

      _ ->
        {:error, :invalid_query}
    end
  end

  defp checkpoint_boundary(_, _), do: {:error, :invalid_query}

  defp build_boundary(checkpoint, count, index_by_id) do
    case locate_span(checkpoint, count, index_by_id) do
      {:ok, first_index, last_index} ->
        {:ok,
         %{
           checkpoint_digest: SigilGuard.Audit.Checkpoint.digest(checkpoint),
           tree_size: count,
           first_index: first_index,
           last_index: last_index
         }}

      error ->
        error
    end
  end

  defp locate_span(_, 0, _), do: {:ok, nil, nil}

  defp locate_span(checkpoint, count, index_by_id) do
    first = Map.get(index_by_id, Map.get(checkpoint, "first_event_id"))
    last = Map.get(index_by_id, Map.get(checkpoint, "last_event_id"))

    if is_integer(first) and is_integer(last) and first <= last and last - first + 1 == count do
      {:ok, first, last}
    else
      {:error, :checkpoint_mismatch}
    end
  end

  defp canonical_iodata(%__MODULE__{} = event) do
    [
      "{\"action\":",
      Jason.encode!(event.action),
      ",\"actor\":",
      Jason.encode!(event.actor),
      ",\"id\":",
      Jason.encode!(event.id),
      ",\"result\":",
      Jason.encode!(event.result),
      ",\"timestamp\":",
      Jason.encode!(event.timestamp),
      ",\"type\":",
      Jason.encode!(event.type),
      "}"
    ]
  end

  defp compute_hmac(key, data) do
    Base.encode16(:crypto.mac(:hmac, :sha256, key, data), case: :lower)
  end

  defp verify_chain_events(events, key, anchor) do
    result =
      events
      |> Enum.with_index()
      |> Enum.reduce_while({:ok, anchor}, fn {event, index}, {:ok, expected_prev} ->
        verify_chain_event(event, index, key, expected_prev)
      end)

    case result do
      {:ok, _} -> :ok
      broken -> broken
    end
  end

  defp verify_chain_event(event, index, key, expected_prev) do
    canonical = canonical_iodata(event)
    expected_hmac = compute_hmac(key, [canonical, chain_input!(expected_prev)])

    # Contiguity uses plain == — prev_hmac values are public chain
    # data, not secrets; only the HMAC comparison needs constant time.
    if event.prev_hmac == expected_prev and secure_compare(expected_hmac, event.hmac) do
      {:cont, {:ok, event.hmac}}
    else
      {:halt, {:broken, index}}
    end
  end

  defp chain_input!(prev_hmac) do
    case chain_input(prev_hmac) do
      {:ok, chain_input} -> chain_input
      :error -> raise ArgumentError, "prev_hmac must be a binary or nil"
    end
  end

  defp chain_input(nil), do: {:ok, @genesis_marker}
  defp chain_input(prev_hmac) when is_binary(prev_hmac), do: {:ok, prev_hmac}
  defp chain_input(_), do: :error

  defp generate_event_id do
    Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)
  end

  defp generate_timestamp do
    DateTime.to_iso8601(DateTime.utc_now(:millisecond))
  end

  # Constant-time comparison to prevent timing attacks on HMAC
  # verification. Regular == short-circuits on the first differing
  # byte, leaking information about matching prefix length.
  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    secure_compare(a, b, 0)
  end

  defp secure_compare(_, _), do: false

  defp secure_compare(<<a, rest_a::binary>>, <<b, rest_b::binary>>, diff) do
    secure_compare(rest_a, rest_b, Bitwise.bor(diff, Bitwise.bxor(a, b)))
  end

  defp secure_compare(<<>>, <<>>, diff), do: diff == 0
end
