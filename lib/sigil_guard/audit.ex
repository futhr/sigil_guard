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

  Verification walks the chain and recomputes each HMAC. If any event
  has been modified, the chain breaks at that point.

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

  Returns `:ok` if all HMACs are valid, or `{:broken, index}` indicating
  the first event whose HMAC doesn't match the expected value.

  ## Examples

      :ok = SigilGuard.Audit.verify_chain(events, secret_key)

      {:broken, 3} = SigilGuard.Audit.verify_chain(tampered_events, secret_key)

  """
  @spec verify_chain([t()], binary()) :: :ok | {:broken, non_neg_integer()}
  def verify_chain(events, key) do
    events
    |> Enum.with_index()
    |> Enum.reduce_while(:ok, fn {event, index}, :ok ->
      chain_input = event.prev_hmac || @genesis_marker
      canonical = canonical_bytes(event)
      expected_hmac = compute_hmac(key, canonical <> chain_input)

      if secure_compare(expected_hmac, event.hmac) do
        {:cont, :ok}
      else
        {:halt, {:broken, index}}
      end
    end)
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

    ~w(action actor id result timestamp type)
    |> Enum.map_join(",", fn key -> ~s("#{key}":#{Jason.encode!(fields[key])}) end)
    |> then(fn inner -> "{#{inner}}" end)
  end

  # -- Private --

  defp compute_hmac(key, data) do
    :crypto.mac(:hmac, :sha256, key, data)
    |> Base.encode16(case: :lower)
  end

  defp generate_event_id do
    :crypto.strong_rand_bytes(16)
    |> Base.encode16(case: :lower)
  end

  defp generate_timestamp do
    DateTime.utc_now(:millisecond)
    |> DateTime.to_iso8601()
  end

  # Constant-time comparison to prevent timing attacks on HMAC
  # verification. Regular == short-circuits on the first differing
  # byte, leaking information about matching prefix length.
  defp secure_compare(a, b) when byte_size(a) == byte_size(b) do
    a
    |> :binary.bin_to_list()
    |> Enum.zip(:binary.bin_to_list(b))
    |> Enum.reduce(0, fn {x, y}, acc ->
      Bitwise.bor(acc, Bitwise.bxor(x, y))
    end)
    |> Kernel.==(0)
  end

  defp secure_compare(_, _), do: false
end
