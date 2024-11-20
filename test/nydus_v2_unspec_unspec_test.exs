defmodule NydusV2UnspecUnspecTest do
  use ExUnit.Case

  alias Nydus.V2

  doctest Nydus

  setup do
    {:ok, server_socket} = :gen_tcp.listen(0, [:binary, active: false, reuseaddr: true])
    {:ok, port} = :inet.port(server_socket)
    {:ok, client_socket} = :gen_tcp.connect(:localhost, port, [:binary, active: false])
    {:ok, server_socket} = :gen_tcp.accept(server_socket)

    %{
      client_socket: client_socket,
      server_socket: server_socket,
      opts: [version_config: 2]
    }
  end

  describe "gen_tcp - version_config 2 - ok" do
    test "local unspec unspec", context do
      expected = %{
        address_family: :unspec,
        addresses_and_tlvs: "",
        signature: 2,
        socket_protocol: :unspec,
        version: 2,
        command: :local
      }

      {:ok, header} = V2.encode(expected)
      :gen_tcp.send(context.client_socket, header)
      assert {:ok, actual} = Nydus.receive_and_decode(context.server_socket, context.opts)
      assert expected == actual
    end
  end
end
