defmodule SigilGuard.Audit do
  @moduledoc """
  Tamper-evident audit logging for the SIGIL protocol.

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
    chain_input = prev_hmac || @genesis_marker
    canonical = canonical_bytes(event)
    hmac = compute_hmac(key, canonical <> chain_input)

    Telemetry.emit(
      [:sigil_guard, :audit, :logged],
      %{system_time: System.system_time()},
      %{event_type: event.type, actor: event.actor}
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

    events
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, anchor}, fn {event, index}, {:ok, expected_prev} ->
      canonical = canonical_bytes(event)
      expected_hmac = compute_hmac(key, canonical <> (expected_prev || @genesis_marker))

      # Contiguity uses plain == — prev_hmac values are public chain
      # data, not secrets; only the HMAC comparison needs constant time.
      if event.prev_hmac == expected_prev and secure_compare(expected_hmac, event.hmac) do
        {:cont, {:ok, event.hmac}}
      else
        {:halt, {:broken, index}}
      end
    end)
    |> case do
      {:ok, _} -> :ok
      broken -> broken
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
    fields = %{
      "action" => event.action,
      "actor" => event.actor,
      "id" => event.id,
      "result" => event.result,
      "timestamp" => event.timestamp,
      "type" => event.type
    }

    inner =
      ~w(action actor id result timestamp type)
      |> Enum.map_join(",", fn key -> ~s("#{key}":#{Jason.encode!(fields[key])}) end)

    "{#{inner}}"
  end

  # -- Private --

  defp compute_hmac(key, data) do
    Base.encode16(:crypto.mac(:hmac, :sha256, key, data), case: :lower)
  end

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
    diff =
      a
      |> :binary.bin_to_list()
      |> Enum.zip(:binary.bin_to_list(b))
      |> Enum.reduce(0, fn {x, y}, acc ->
        Bitwise.bor(acc, Bitwise.bxor(x, y))
      end)

    diff == 0
  end

  defp secure_compare(_, _), do: false
end
