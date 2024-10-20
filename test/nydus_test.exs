defmodule NydusTest do
  @moduledoc """
  Tests for `Nydus.decode/2` are defined in this module.

  Tests for `Nydus.receive_and_decode/2` are split out into separate modules:

    - `NydusV1Inet6StreamTest`
    - `NydusV1InetStreamTest`
    - `NydusV2Inet6StreamTest`
    - `NydusV2InetStreamTest`
  """

  use ExUnit.Case

  alias Nydus.V2

  doctest Nydus

  describe "decode/2 v1" do
    setup do
      %{opts: [version_config: 1]}
    end

    test "inet stream", context do
      bin = "PROXY TCP4 101.102.103.104 201.202.203.204 15614 28249\r\n"

      expected = %{
        version: nil,
        signature: 1,
        address_family: :inet,
        socket_protocol: :stream,
        addresses_and_tlvs: %{
          addresses: %{
            destination_address: {201, 202, 203, 204},
            destination_port: 28249,
            source_address: {101, 102, 103, 104},
            source_port: 15614
          },
          tlvs: ""
        }
      }

      assert {:ok, expected} == Nydus.decode(bin, context.opts)
    end

    test "inet6 stream", context do
      bin =
        "PROXY TCP6 4889:4f3a:7802:7b3a:6ed1:1497:49a5:07a2 59ac:c7ea:6b2e:ab22:4b43:4d78:feff:1f1f 23456 12345\r\n"

      expected = %{
        version: nil,
        signature: 1,
        address_family: :inet6,
        socket_protocol: :stream,
        addresses_and_tlvs: %{
          addresses: %{
            destination_address: {22956, 51178, 27438, 43810, 19267, 19832, 65279, 7967},
            destination_port: 12345,
            source_address: {18569, 20282, 30722, 31546, 28369, 5271, 18853, 1954},
            source_port: 23456
          },
          tlvs: ""
        }
      }

      assert {:ok, expected} == Nydus.decode(bin, context.opts)
    end

    test "unknown unknown (short form)", context do
      bin = "PROXY UNKNOWN\r\n"

      expected = %{
        version: nil,
        signature: 1,
        address_family: :unspec,
        socket_protocol: :unspec,
        addresses_and_tlvs: ""
      }

      assert {:ok, expected} == Nydus.decode(bin, context.opts)
    end

    test "unknown unknown (long form)", context do
      bin =
        "PROXY UNKNOWN ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535\r\n"

      expected = %{
        version: nil,
        signature: 1,
        address_family: :unspec,
        socket_protocol: :unspec,
        addresses_and_tlvs:
          "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535"
      }

      assert {:ok, expected} == Nydus.decode(bin, context.opts)
    end
  end

  describe "decode/2 v2" do
    setup do
      %{opts: [version_config: 2]}
    end

    test "inet stream", context do
      expected = %{
        version: 2,
        command: :proxy,
        signature: 2,
        address_family: :inet,
        socket_protocol: :stream,
        addresses_and_tlvs: %{
          addresses: %{
            destination_address: {201, 202, 203, 204},
            destination_port: 28249,
            source_address: {101, 102, 103, 104},
            source_port: 15614
          },
          tlvs: ""
        }
      }

      {:ok, bin} = V2.encode(expected)
      assert {:ok, expected} == Nydus.decode(bin, context.opts)
    end

    test "inet6 stream", context do
      expected = %{
        version: 2,
        command: :proxy,
        signature: 2,
        address_family: :inet6,
        socket_protocol: :stream,
        addresses_and_tlvs: %{
          addresses: %{
            destination_address: {22956, 51178, 27438, 43810, 19267, 19832, 65279, 7967},
            destination_port: 12345,
            source_address: {18569, 20282, 30722, 31546, 28369, 5271, 18853, 1954},
            source_port: 23456
          },
          tlvs: ""
        }
      }

      {:ok, bin} = V2.encode(expected)
      assert {:ok, expected} == Nydus.decode(bin, context.opts)
    end

    test "unknown unknown (no data)", context do
      expected = %{
        version: 2,
        command: :proxy,
        signature: 2,
        address_family: :unspec,
        socket_protocol: :unspec,
        addresses_and_tlvs: ""
      }

      {:ok, bin} = V2.encode(expected)
      assert {:ok, expected} == Nydus.decode(bin, context.opts)
    end

    test "unknown unknown (some data)", context do
      expected = %{
        version: 2,
        command: :proxy,
        signature: 2,
        address_family: :unspec,
        socket_protocol: :unspec,
        addresses_and_tlvs: "data from some unspec'd protocol"
      }

      {:ok, bin} = V2.encode(expected)
      assert {:ok, expected} == Nydus.decode(bin, context.opts)
    end

    test "unknown unknown (long form)", context do
      expected = %{
        version: 2,
        command: :proxy,
        signature: 2,
        address_family: :unspec,
        socket_protocol: :unspec,
        addresses_and_tlvs:
          "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff 65535 65535"
      }

      {:ok, bin} = V2.encode(expected)
      assert {:ok, expected} == Nydus.decode(bin, context.opts)
    end
  end
end
