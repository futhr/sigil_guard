defmodule SigilGuard.Audit.EventType do
  @moduledoc """
  Audit event types defined by the SIGIL protocol.

  These match the `AuditEventType` enum from the `sigil-protocol` Rust crate (v0.1.5).
  Use these atoms as the `type` field when creating audit events for protocol compliance.

  ## Event Types

  | Atom | Description |
  |------|-------------|
  | `:command_execution` | An agent tool/command was executed |
  | `:file_access` | A file was accessed |
  | `:config_change` | Configuration was changed |
  | `:auth_success` | Authentication succeeded |
  | `:auth_failure` | Authentication failed |
  | `:policy_violation` | A security policy was violated |
  | `:security_event` | A general security event |
  | `:sigil_interception` | Sensitive content was intercepted by the scanner |
  | `:mcp_tool_gated` | An MCP tool call was gated |
  | `:delegation_crossing` | An agent-to-agent delegation boundary was crossed |

  ## Example

      event = SigilGuard.Audit.new_event(
        SigilGuard.Audit.EventType.to_string(:mcp_tool_gated),
        "did:web:alice",
        "read_file",
        "success"
      )

  """

  @type t ::
          :command_execution
          | :file_access
          | :config_change
          | :auth_success
          | :auth_failure
          | :policy_violation
          | :security_event
          | :sigil_interception
          | :mcp_tool_gated
          | :delegation_crossing

  @event_types [
    :command_execution,
    :file_access,
    :config_change,
    :auth_success,
    :auth_failure,
    :policy_violation,
    :security_event,
    :sigil_interception,
    :mcp_tool_gated,
    :delegation_crossing
  ]

  @doc "Return all valid event types."
  @spec values() :: [t(), ...]
  def values, do: @event_types

  @doc "Check if an atom is a valid event type."
  @spec valid?(atom()) :: boolean()
  def valid?(type), do: type in @event_types

  @doc "Convert an event type atom to its protocol string representation."
  @spec to_string(t()) :: String.t()
  def to_string(:command_execution), do: "CommandExecution"
  def to_string(:file_access), do: "FileAccess"
  def to_string(:config_change), do: "ConfigChange"
  def to_string(:auth_success), do: "AuthSuccess"
  def to_string(:auth_failure), do: "AuthFailure"
  def to_string(:policy_violation), do: "PolicyViolation"
  def to_string(:security_event), do: "SecurityEvent"
  def to_string(:sigil_interception), do: "SigilInterception"
  def to_string(:mcp_tool_gated), do: "McpToolGated"
  def to_string(:delegation_crossing), do: "DelegationCrossing"

  @doc "Parse a protocol string into an event type atom."
  @spec from_string(String.t()) :: {:ok, t()} | :error
  def from_string("CommandExecution"), do: {:ok, :command_execution}
  def from_string("FileAccess"), do: {:ok, :file_access}
  def from_string("ConfigChange"), do: {:ok, :config_change}
  def from_string("AuthSuccess"), do: {:ok, :auth_success}
  def from_string("AuthFailure"), do: {:ok, :auth_failure}
  def from_string("PolicyViolation"), do: {:ok, :policy_violation}
  def from_string("SecurityEvent"), do: {:ok, :security_event}
  def from_string("SigilInterception"), do: {:ok, :sigil_interception}
  def from_string("McpToolGated"), do: {:ok, :mcp_tool_gated}
  def from_string("DelegationCrossing"), do: {:ok, :delegation_crossing}
  def from_string(_other), do: :error
end
