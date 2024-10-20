defmodule NydusV2InetStreamTest do
  use ExUnit.Case

  alias Nydus.V2

  doctest Nydus

  setup do
    {:ok, server_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(server_socket)
    {:ok, client_socket} = :gen_tcp.connect(:localhost, port, [:binary, active: false])
    {:ok, server_socket} = :gen_tcp.accept(server_socket)

    expected = %{
      address_family: :inet,
      addresses_and_tlvs: %{
        addresses: %{
          destination_address: {100, 100, 100, 100},
          destination_port: 10000,
          source_address: {200, 200, 200, 200},
          source_port: 20000
        },
        tlvs: ""
      },
      signature: 2,
      socket_protocol: :stream,
      version: 2,
      command: :proxy
    }

    {:ok, header} = V2.encode(expected)

    %{
      expected: expected,
      header: header,
      client_socket: client_socket,
      server_socket: server_socket,
      opts: [version_config: 2]
    }
  end

  describe "gen_tcp - version_config 2 - bad first receive" do
    test "timeout", context do
      header = ""
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :first_timeout, 10)

      assert {:error, {{:first_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end
  end

  describe "gen_tcp - version_config 2 - bad signature" do
    test "missing", context do
      header = mangle(context.header, 0, 12 * 8, "")
      :gen_tcp.send(context.client_socket, header)

      assert {:error, :bad_signature} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed", context do
      header = mangle(context.header, 0, 12 * 8, "abcdefghijkl")
      :gen_tcp.send(context.client_socket, header)

      assert {:error, :bad_signature} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end
  end

  describe "gen_tcp - version_config 2 - bad version or command" do
    test "missing version and command", context do
      header = binary_part(context.header, 0, 12)
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :first_timeout, 10)

      assert {:error, {{:first_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end

    test "malformed both", context do
      header = mangle(context.header, 12 * 8, 8, <<255>>)
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_version, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed version", context do
      header = mangle(context.header, 12 * 8, 4, <<255::4>>)
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_version, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed command", context do
      header = mangle(context.header, 12 * 8 + 4, 4, <<255::4>>)
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_command, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end
  end

  describe "gen_tcp - version_config 2 - bad address family or socket protocol" do
    test "missing address family and socket protocol", context do
      header = binary_part(context.header, 0, 13)
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :first_timeout, 10)

      assert {:error, {{:first_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end

    test "malformed both", context do
      header = mangle(context.header, 13 * 8, 8, <<255>>)
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_address_family, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed address family", context do
      header = mangle(context.header, 13 * 8, 4, <<255::4>>)
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_address_family, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed socket protocol", context do
      header = mangle(context.header, 13 * 8 + 4, 4, <<255::4>>)
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_socket_protocol, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end
  end

  describe "gen_tcp - version_config 2 - bad length" do
    test "missing length", context do
      header = binary_part(context.header, 0, 14)
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :first_timeout, 10)

      assert {:error, {{:first_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end
  end

  describe "gen_tcp - version_config 2 - bad addresses" do
    test "missing one address", context do
      header = mangle(context.header, 16 * 8, 32, "")
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :second_timeout, 10)

      assert {:error, {{:second_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end

    test "missing both addresses", context do
      header = mangle(context.header, 16 * 8, 64, "")
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :second_timeout, 10)

      assert {:error, {{:second_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end
  end

  describe "gen_tcp - version_config 2 - bad ports" do
    test "missing one port", context do
      header = mangle(context.header, 20 * 8, 16, "")
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :second_timeout, 10)

      assert {:error, {{:second_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end

    test "missing both ports", context do
      header = mangle(context.header, 20 * 8, 32, "")
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :second_timeout, 10)

      assert {:error, {{:second_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end
  end

  describe "gen_tcp - version_config 2 - ok" do
    test "case 1", context do
      expected = context.expected
      :gen_tcp.send(context.client_socket, context.header)
      assert {:ok, actual} = Nydus.receive_and_decode(context.server_socket, context.opts)
      assert expected == actual
    end
  end

  defp mangle(original, offset, length, bin) do
    # Split the binary into three parts: before, the section to be replaced, and rest
    <<before::bitstring-size(offset), _to_remove::bitstring-size(length), rest::bitstring>> =
      original

    # Concatenate before + bin + rest
    <<before::bitstring, bin::bitstring, rest::bitstring>>
  end
end
