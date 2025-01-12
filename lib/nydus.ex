defmodule Nydus do
  @moduledoc """
  Functionality for reading and decoding PROXY protocol headers off of `:gen_tcp` sockets.
  """

  alias Nydus.V1
  alias Nydus.V2

  require Nydus.V1
  require Nydus.V2

  @doc """
  Attempts to receive and decode a proxy protocol header from a `:gen_tcp` socket.

  `decode/2` may be called directly if you wish to provide `bin` directly isntead of `socket`.

  ## Options

  - `:version_config` - Specifies which proxy protocol versions to accept. May be `1`, `2`, or
    `:all`. Defaults to `2`.
  - `:first_timeout` - Specifies a time-out in milliseconds for the first receive. If exceeded,
    this function immediately returns an error. Defaults to `1_000`.
  - `:second_timeout` - Specifies a time-out in milliseconds for receiving the rest of the
    protocol's data after the first receive and decode have completed successfully. If exceeded,
    this function immediately returns an error. Defaults to `1_000`.

  ## Receives and timeouts

  This function will perform two `:gen_tcp.recv/3` calls on `socket`. The first call is to
  identify the version of the protocol. The second call is to acquire the remaining bytes of the
  protocol, which is informed by what was found in the first call.

  Use cases that require only a single receive call may perform the receive themselves and then
  call `decode/2` directly.
  """
  def receive_and_decode(socket, opts \\ []) do
    state = %{
      version_config: Keyword.get(opts, :version_config, 2),
      first_timeout: Keyword.get(opts, :first_timeout, 1_000),
      second_timeout: Keyword.get(opts, :second_timeout, 1_000),
      socket: socket
    }

    with {:ok, state} <- first_receive(state),
         {:ok, state} <- first_decode(state),
         {:ok, state} <- second_receive(state),
         {:ok, state} <- second_decode(state) do
      {:ok, proxy_protocol_data(state)}
    end
  end

  @doc """
  Attempts to decode a proxy protocol header from `bin`.

  `receive_and_decode/2` may be called directly if you wish to provide `socket` instead of `bin`
  such that Nydus manages the receive calls for you.

  ## Options

  - `:version_config` - Specifies which proxy protocol versions to accept. May be `1`, `2`, or
    `:all`. Defaults to `2`.
  """
  def decode(bin, opts \\ []) do
    state = %{fr_bin: bin, version_config: Keyword.get(opts, :version_config, 2)}

    with {:ok, state} <- first_decode(state),
         state <- Map.put(state, :sr_bin, state.fr_bin_trailing),
         {:ok, state} <- second_decode(state) do
      {:ok, proxy_protocol_data(state)}
    end
  end

  defp first_receive(state) do
    # The goal of the first receive is to get enough information such that we can identify:
    #
    #   A) the protocol by its version-specific signature
    #   B) how much more bytes there are to receive

    length =
      case state.version_config do
        1 -> V1.signature_length()
        2 -> V2.fixed_length()
        :all -> V2.fixed_length()
      end

    case :gen_tcp.recv(state.socket, length, state.first_timeout) do
      {:ok, bin} -> {:ok, Map.put(state, :fr_bin, bin)}
      {:error, e} -> {:error, {{:first_receive, e}, state}}
    end
  end

  defp first_decode(state) do
    # This function attempts to identify the version of the protocol by signature. Note that it
    # supports `fr_bin` containing trailing bytes beyond the expected signature, and that in that
    # case it will return those trailing bytes for later use.

    case {state.version_config, state.fr_bin} do
      {version_config, <<V1.signature(), bin::binary>>} when version_config in [1, :all] ->
        # The signature is for version 1, and the version_config allows for that. Since the
        # first_read receives 16 bytes, and this is version 1, we only have enough data to decode
        # signature.
        state = Map.merge(state, %{signature: 1, version: nil, fr_bin_trailing: bin, tlvs: ""})
        {:ok, state}

      {version_config,
       <<V2.signature(), version_and_command::binary-1,
         address_family_and_socket_protocol::binary-1, length::16, bin::binary>>}
      when version_config in [2, :all] ->
        # The signature is for version 2, and the version_config allows for that. Since the
        # first_read receives 16 bytes, and this is version 2, we have enough data to decode
        # signature, version, command, address family, and socket protocol.

        with {:ok, {version, command}} <- V2.decode_version_and_command(version_and_command),
             {:ok, {address_family, socket_protocol}} <-
               V2.decode_address_family_and_socket_protocol(address_family_and_socket_protocol) do
          state =
            Map.merge(state, %{
              address_family: address_family,
              addresses_and_tlvs_length: length,
              command: command,
              fr_bin_trailing: bin,
              socket_protocol: socket_protocol,
              signature: 2,
              version: version
            })

          {:ok, state}
        else
          {:error, e} -> {:error, {e, state}}
        end

      _ ->
        {:error, :bad_signature}
    end
  end

  defp second_receive(%{signature: 1, version: nil} = state) do
    # Ensure the socket is in line read mode. If we have to change it to line mode, remember the
    # prior setting so that we can set it back before returning from this function.
    old_packet =
      case :inet.getopts(state.socket, [:packet]) do
        {:ok, [{:packet, :line}]} ->
          :line

        {:ok, [{:packet, other}]} ->
          :ok = :inet.setopts(state.socket, [{:packet, :line}])
          other
      end

    # Receive the rest of the header.
    ret =
      case :gen_tcp.recv(state.socket, 0, state.second_timeout) do
        {:ok, bin} -> {:ok, Map.put(state, :sr_bin, state.fr_bin_trailing <> bin)}
        {:error, e} -> {:error, {{:second_receive, e}, state}}
      end

    # Maybe reset packet option to old value.
    case old_packet do
      :line -> :ok
      other -> :ok = :inet.setopts(state.socket, [{:packet, other}])
    end

    ret
  end

  defp second_receive(%{signature: 2, version: 2, addresses_and_tlvs_length: 0} = state) do
    addresses_block = ""
    state = Map.put(state, :sr_bin, addresses_block)
    {:ok, state}
  end

  defp second_receive(%{signature: 2, version: 2} = state) do
    # Receive the rest of the header.
    case :gen_tcp.recv(state.socket, state.addresses_and_tlvs_length, state.second_timeout) do
      {:ok, bin} ->
        state = Map.put(state, :sr_bin, bin)
        {:ok, state}

      {:error, e} ->
        {:error, {{:second_receive, e}, state}}
    end
  end

  defp second_decode(%{signature: 1, version: nil} = state) do
    address_family_and_socket_protocol =
      case state.sr_bin do
        <<" TCP4 ", rest::binary>> -> {:ok, {:inet, :stream, rest}}
        <<" TCP6 ", rest::binary>> -> {:ok, {:inet6, :stream, rest}}
        <<" UNKNOWN ", rest::binary>> -> {:ok, {:unspec, :unspec, rest}}
        <<" UNKNOWN\r\n">> -> {:ok, {:unspec, :unspec, "\r\n"}}
        _ -> {:error, :bad_protocol_and_family}
      end

    with {:ok, {address_family, socket_protocol, rest}} <- address_family_and_socket_protocol,
         {:error, true} <- {:error, String.ends_with?(rest, "\r\n") || :bad_line},
         rest = String.trim_trailing(rest, "\r\n"),
         {:ok, addresses} <- V1.decode_addresses(address_family, rest) do
      addresses_and_tlvs =
        case addresses do
          addresses when is_binary(addresses) -> addresses
          addresses -> %{addresses: addresses, tlvs: ""}
        end

      state =
        Map.merge(state, %{
          address_family: address_family,
          socket_protocol: socket_protocol,
          addresses_and_tlvs: addresses_and_tlvs
        })

      {:ok, state}
    else
      {:error, e} -> {:error, {e, state}}
    end
  end

  defp second_decode(%{signature: 2, version: 2} = state) do
    with {:ok, addresses_and_tlvs} <-
           V2.decode_addresses_and_tlvs(state.address_family, state.sr_bin) do
      state = Map.merge(state, %{addresses_and_tlvs: addresses_and_tlvs})
      {:ok, state}
    else
      {:error, e} -> {:error, {e, state}}
    end
  end

  defp second_decode(state) do
    {:error, {:second_decode, :bad_version, state}}
  end

  defp proxy_protocol_data(state) do
    Map.take(
      state,
      [
        :signature,
        :version,
        :command,
        :address_family,
        :socket_protocol,
        :addresses_and_tlvs
      ]
    )
  end
end
