defmodule Nydus.V2 do
  @moduledoc """
  Utility functions for encoding and decoding proxy protocol v2 structures.
  """

  @address_family_unspec 0
  @address_family_inet 1
  @address_family_inet6 2
  @address_family_unix 3

  @socket_protocol_unspec 0
  @socket_protocol_stream 1
  @socket_protocol_dgram 2

  defmacro signature() do
    quote do
      <<0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A>>
    end
  end

  def signature_length(), do: 12

  # Length of the fixed beginning portion of the v2 header.
  def fixed_length(), do: 16

  def encode(%{
        signature: signature,
        version: version,
        command: command,
        address_family: address_family,
        socket_protocol: socket_protocol,
        addresses_and_tlvs: addresses_and_tlvs
      }) do
    with {:ok, signature} <- encode_signature(signature),
         {:ok, version_and_command} <- encode_version_and_command({version, command}),
         {:ok, address_family_and_socket_protocol} <-
           encode_address_family_and_socket_protocol({address_family, socket_protocol}),
         {:ok, addresses_and_tlvs} <-
           encode_addresses_and_tlvs(address_family, addresses_and_tlvs),
         length <- byte_size(addresses_and_tlvs) do
      header = <<
        signature::binary-12,
        version_and_command::binary,
        address_family_and_socket_protocol::binary,
        length::16,
        addresses_and_tlvs::binary
      >>

      {:ok, header}
    end
  end

  def encode(proxy_protocol_data) do
    expected = [
      :address_family,
      :addresses_and_tlvs,
      :command,
      :signature,
      :socket_protocol,
      :version
    ]

    actual = Map.keys(proxy_protocol_data)
    missing_keys = expected -- actual
    {:error, {:bad_proxy_protocol_data, {:missing_keys, missing_keys}}}
  end

  def encode_signature(2), do: {:ok, signature()}
  def encode_signature(_), do: {:error, :bad_signature}

  def decode_signature(signature()), do: {:ok, 2}
  def decode_signature(_), do: {:error, :bad_signature}

  def encode_version_and_command({version, command}) do
    with {:ok, version} <- encode_version(version),
         {:ok, command} <- encode_command(command) do
      {:ok, <<version::4, command::4>>}
    end
  end

  def encode_version_and_command(_), do: {:error, :bad_version_and_command}

  def decode_version_and_command(<<version::4, command::4>>) do
    case {version, command} do
      {2, 0} -> {:ok, {2, :local}}
      {2, 1} -> {:ok, {2, :proxy}}
      {2, _} -> {:error, :bad_command}
      _ -> {:error, :bad_version}
    end
  end

  def encode_version(2), do: {:ok, 2}
  def encode_version(_), do: {:error, :bad_version}

  def decode_version(2), do: {:ok, 2}
  def decode_version(_), do: {:error, :bad_version}

  def encode_command(:local), do: {:ok, 0}
  def encode_command(:proxy), do: {:ok, 1}
  def encode_command(_), do: {:error, :bad_command}

  def decode_command(0), do: :local
  def decode_command(1), do: :proxy

  def encode_address_family_and_socket_protocol({address_family, socket_protocol}) do
    with {:ok, address_family} <- encode_address_family(address_family),
         {:ok, socket_protocol} <- encode_socket_protocol(socket_protocol) do
      {:ok, <<address_family::4, socket_protocol::4>>}
    end
  end

  def encode_address_family_and_socket_protocol(_) do
    {:error, :bad_address_family_and_socket_protocol}
  end

  def decode_address_family_and_socket_protocol(<<address_family::4, socket_protocol::4>>) do
    with {:ok, address_family} <- decode_address_family(address_family),
         {:ok, socket_protocol} <- decode_socket_protocol(socket_protocol) do
      {:ok, {address_family, socket_protocol}}
    end
  end

  def encode_addresses_and_tlvs(:unspec, addresses_and_tlvs) when is_binary(addresses_and_tlvs) do
    {:ok, addresses_and_tlvs}
  end

  def encode_addresses_and_tlvs(:inet, %{addresses: addresses, tlvs: tlvs}) do
    {:ok, source_address} = encode_address(addresses.source_address)
    {:ok, destination_address} = encode_address(addresses.destination_address)

    with {:ok, tlvs} <- encode_tlvs(tlvs) do
      bin =
        <<
          source_address::binary-4,
          destination_address::binary-4,
          addresses.source_port::16,
          addresses.destination_port::16,
          tlvs::binary
        >>

      {:ok, bin}
    end
  end

  def encode_addresses_and_tlvs(:inet6, %{addresses: addresses, tlvs: tlvs}) do
    {:ok, source_address} = encode_address(addresses.source_address)
    {:ok, destination_address} = encode_address(addresses.destination_address)

    with {:ok, tlvs} <- encode_tlvs(tlvs) do
      bin =
        <<
          source_address::binary-16,
          destination_address::binary-16,
          addresses.source_port::16,
          addresses.destination_port::16,
          tlvs::binary
        >>

      {:ok, bin}
    end
  end

  def decode_addresses_and_tlvs(
        :inet,
        <<
          src_address::binary-4,
          dst_address::binary-4,
          src_port::16,
          dst_port::16,
          tlvs::binary
        >>
      ) do
    addresses = %{
      source_address: decode_address(src_address),
      destination_address: decode_address(dst_address),
      source_port: src_port,
      destination_port: dst_port
    }

    {:ok, %{addresses: addresses, tlvs: tlvs}}
  end

  def decode_addresses_and_tlvs(
        :inet6,
        <<
          src_address::binary-16,
          dst_address::binary-16,
          src_port::16,
          dst_port::16,
          tlvs::binary
        >>
      ) do
    addresses = %{
      source_address: decode_address(src_address),
      destination_address: decode_address(dst_address),
      source_port: src_port,
      destination_port: dst_port
    }

    {:ok, %{addresses: addresses, tlvs: tlvs}}
  end

  def decode_addresses_and_tlvs(:unix, <<src_path::108, dst_path::108, tlvs::binary>>) do
    addresses = %{
      src_path: String.trim_trailing(src_path, <<0>>),
      dst_path: String.trim_trailing(dst_path, <<0>>)
    }

    {:ok, %{addresses: addresses, tlvs: tlvs}}
  end

  def decode_addresses_and_tlvs(:unspec, bin), do: {:ok, bin}

  def decode_addresses_and_tlvs(_, _), do: {:error, :bad_addresses_and_tlvs}

  def encode_address({a, b, c, d}), do: {:ok, <<a, b, c, d>>}

  def encode_address({a, b, c, d, e, f, g, h}) do
    {:ok, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}
  end

  def decode_address(<<a, b, c, d>>), do: {a, b, c, d}

  def decode_address(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>) do
    {a, b, c, d, e, f, g, h}
  end

  def encode_tlvs(nil), do: {:ok, ""}
  def encode_tlvs(bin) when is_binary(bin), do: {:ok, bin}
  def encode_tlvs(_), do: {:error, :bad_tlvs}

  def decode_tlvs(""), do: {:ok, nil}

  def encode_address_family(:unspec), do: {:ok, @address_family_unspec}
  def encode_address_family(:inet), do: {:ok, @address_family_inet}
  def encode_address_family(:inet6), do: {:ok, @address_family_inet6}
  def encode_address_family(:unix), do: {:ok, @address_family_unix}
  def encode_address_family(_), do: {:error, :bad_address_family}

  def decode_address_family(@address_family_unspec), do: {:ok, :unspec}
  def decode_address_family(@address_family_inet), do: {:ok, :inet}
  def decode_address_family(@address_family_inet6), do: {:ok, :inet6}
  def decode_address_family(@address_family_unix), do: {:ok, :unix}
  def decode_address_family(_), do: {:error, :bad_address_family}

  def encode_socket_protocol(:unspec), do: {:ok, @socket_protocol_unspec}
  def encode_socket_protocol(:stream), do: {:ok, @socket_protocol_stream}
  def encode_socket_protocol(:dgram), do: {:ok, @socket_protocol_dgram}
  def encode_socket_protocol(_), do: {:error, :bad_socket_protocol}

  def decode_socket_protocol(@socket_protocol_unspec), do: {:ok, :unspec}
  def decode_socket_protocol(@socket_protocol_stream), do: {:ok, :stream}
  def decode_socket_protocol(@socket_protocol_dgram), do: {:ok, :dgram}
  def decode_socket_protocol(_), do: {:error, :bad_socket_protocol}
end
