defmodule SigilGuard.Signer.Ed25519 do
  @moduledoc """
  Default Ed25519 signer using OTP `:crypto`.

  For production use, consider implementing `SigilGuard.Signer` with an
  HSM or KMS backend instead.

  ## Usage

  Process-free, passing the signer struct explicitly:

      {_pub, priv} = SigilGuard.Signer.generate_keypair()
      signer = SigilGuard.Signer.Ed25519.new(priv)
      signature = SigilGuard.Signer.Ed25519.sign_with(signer, message)

  Or as a module-based signer (the form `SigilGuard.Envelope.sign/3`
  expects in its `:signer` option) via `start_link/1`:

      {:ok, _pid} = SigilGuard.Signer.Ed25519.start_link(private_key: priv)
      signature = SigilGuard.Signer.Ed25519.sign(message)

  ## Process Model

  `start_link/1` registers a singleton Agent under `#{inspect(__MODULE__)}`
  holding the keypair — one keypair per node. Supervise it in your
  application's tree; `sign/1` and `public_key/0` exit if it is not
  running. For multiple keypairs in one node, use `new/1` + `sign_with/2`
  or implement `SigilGuard.Signer` in your own module.
  """

  @behaviour SigilGuard.Signer

  use Agent

  @private_key_bytes 32
  @start_schema [
    private_key: [
      type: {:custom, __MODULE__, :validate_private_key_option, []},
      required: true,
      doc: "Raw 32-byte Ed25519 seed."
    ]
  ]

  @type t :: %__MODULE__{
          private_key: binary(),
          public_key: binary()
        }

  defstruct [:private_key, :public_key]

  @doc """
  Create a signer struct from a private key (seed).

  Accepts the raw 32-byte Ed25519 seed as returned by `:crypto.generate_key/2`.
  Derives the public key from the seed.
  """
  @spec new(binary()) :: t()
  def new(private_key) when byte_size(private_key) == 32 do
    {public_key, _} = :crypto.generate_key(:eddsa, :ed25519, private_key)

    %__MODULE__{
      private_key: private_key,
      public_key: public_key
    }
  end

  @doc """
  Start a named agent holding the keypair for module-based callback usage.
  """
  @spec start_link(keyword()) :: Agent.on_start()
  def start_link(opts) do
    with {:ok, validated} <- validate_start_options(opts),
         {:ok, private_key} <- validate_private_key(validated[:private_key]) do
      signer = new(private_key)
      Agent.start_link(fn -> signer end, name: __MODULE__)
    end
  end

  @doc """
  Return generated documentation for start options.
  """
  @spec start_options_docs() :: String.t()
  def start_options_docs do
    NimbleOptions.docs(@start_schema)
  end

  @doc false
  @spec validate_private_key_option(term()) :: {:ok, binary()} | {:error, String.t()}
  def validate_private_key_option(private_key) when is_binary(private_key), do: {:ok, private_key}
  def validate_private_key_option(_), do: {:error, "expected a binary Ed25519 seed"}

  @impl SigilGuard.Signer
  def sign(message) do
    signer = Agent.get(__MODULE__, & &1)
    sign_with(signer, message)
  end

  @impl SigilGuard.Signer
  def public_key do
    Agent.get(__MODULE__, & &1.public_key)
  end

  @doc "Sign a message using a signer struct (without requiring the Agent)."
  @spec sign_with(t(), binary()) :: binary()
  def sign_with(%__MODULE__{private_key: priv}, message) do
    :crypto.sign(:eddsa, :none, message, [priv, :ed25519])
  end

  @doc "Verify a signature using a raw public key."
  @spec verify(binary(), binary(), binary()) :: boolean()
  def verify(message, signature, public_key) do
    :crypto.verify(:eddsa, :none, message, signature, [public_key, :ed25519])
  end

  defp validate_start_options(opts) when is_list(opts) do
    if Keyword.keyword?(opts) do
      validate_start_keyword_options(opts)
    else
      {:error, :invalid_options}
    end
  end

  defp validate_start_options(_), do: {:error, :invalid_options}

  defp validate_start_keyword_options(opts) do
    case NimbleOptions.validate(opts, @start_schema) do
      {:ok, validated} ->
        {:ok, validated}

      {:error, %NimbleOptions.ValidationError{key: :private_key, message: message}} ->
        if String.contains?(message, "required") do
          {:error, :missing_private_key}
        else
          {:error, :invalid_private_key}
        end

      {:error, %NimbleOptions.ValidationError{}} ->
        {:error, :invalid_options}
    end
  end

  defp validate_private_key(private_key)
       when is_binary(private_key) and byte_size(private_key) == @private_key_bytes do
    {:ok, private_key}
  end

  defp validate_private_key(_), do: {:error, :invalid_private_key}
end
