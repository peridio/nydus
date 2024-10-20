defmodule NydusV1InetStreamTest do
  use ExUnit.Case

  doctest Nydus

  setup do
    {:ok, server_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(server_socket)
    {:ok, client_socket} = :gen_tcp.connect(:localhost, port, [:binary, active: false])
    {:ok, server_socket} = :gen_tcp.accept(server_socket)

    %{
      client_socket: client_socket,
      server_socket: server_socket,
      opts: [version_config: 1]
    }
  end

  describe "gen_tcp - version_config 1 - bad first receive" do
    test "timeout", context do
      header = ""
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :first_timeout, 10)

      assert {:error, {{:first_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end
  end

  describe "gen_tcp - version_config 1 - bad signature" do
    test "missing", context do
      header = "TCP4 200.200.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, :bad_signature} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed", context do
      header = "pROXY TCP4 200.200.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, :bad_signature} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end
  end

  describe "gen_tcp - version_config 1 - bad address family or socket protocol" do
    test "missing address family and socket protocol", context do
      header = "PROXY 200.200.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_protocol_and_family, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "missing address family", context do
      header = "PROXY TCP 200.200.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_protocol_and_family, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "missing socket protocol", context do
      header = "PROXY 4 200.200.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_protocol_and_family, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed both", context do
      header = "PROXY tCP9 200.200.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_protocol_and_family, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed address family", context do
      header = "PROXY TCP9 200.200.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_protocol_and_family, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed socket protocol", context do
      header = "PROXY tCP4 200.200.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_protocol_and_family, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end
  end

  describe "gen_tcp - version_config 1 - bad addresses" do
    test "missing one address", context do
      header = "PROXY TCP4 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_line, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "missing both addresses", context do
      header = "PROXY TCP4 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_line, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed source address", context do
      header = "PROXY TCP4 200.foo.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {{:bad_src_addr, :einval}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed destination address", context do
      header = "PROXY TCP4 200.200.200.200 100.100.100.bar 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {{:bad_dst_addr, :einval}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end
  end

  describe "gen_tcp - version_config 1 - bad ports" do
    test "missing one port", context do
      header = "PROXY TCP4 200.200.200.200 100.100.100.100 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_line, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "missing both ports", context do
      header = "PROXY TCP4 200.200.200.200 100.100.100.100\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_line, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed source port", context do
      header = "PROXY TCP4 200.200.200.200 100.100.100.100 2f000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_src_port, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end

    test "malformed destination port", context do
      header = "PROXY TCP4 200.200.200.200 100.100.100.100 20000 1f000\r\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_dst_port, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end
  end

  describe "gen_tcp - version_config 1 - bad line end" do
    test "missing line end", context do
      header = "PROXY TCP4 200.200.200.200 100.100.100.100 20000 10000"
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :second_timeout, 10)

      assert {:error, {{:second_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end

    test "malformed line end - only a carriage return", context do
      header = "PROXY TCP4 200.200.200.200 100.100.100.100 20000 10000\r"
      :gen_tcp.send(context.client_socket, header)
      opts = Keyword.put(context.opts, :second_timeout, 10)

      assert {:error, {{:second_receive, :timeout}, %{}}} =
               Nydus.receive_and_decode(context.server_socket, opts)
    end

    test "malformed line end - only a new line", context do
      header = "PROXY TCP4 200.200.200.200 100.100.100.100 20000 10000\n"
      :gen_tcp.send(context.client_socket, header)

      assert {:error, {:bad_line, %{}}} =
               Nydus.receive_and_decode(context.server_socket, context.opts)
    end
  end

  describe "gen_tcp - version_config 1 - ok" do
    test "case 1", context do
      header = "PROXY TCP4 200.200.200.200 100.100.100.100 20000 10000\r\n"
      :gen_tcp.send(context.client_socket, header)
      assert {:ok, actual} = Nydus.receive_and_decode(context.server_socket, context.opts)

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
        signature: 1,
        socket_protocol: :stream,
        version: nil
      }

      assert expected == actual
    end
  end
end
