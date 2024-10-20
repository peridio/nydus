defmodule Nydus.V1 do
  @moduledoc """
  Utility functions for encoding and decoding proxy protocol v1 structures.
  """

  defmacro signature() do
    quote do
      "PROXY"
    end
  end

  def signature_length(), do: 5

  def decode_addresses(:unspec, addresses), do: {:ok, addresses}

  def decode_addresses(address_family, addresses) do
    with {:ok, [source_address, destination_address, source_port, destination_port]} <-
           split_addresses(addresses),
         {:ok, source_address} <- decode_address(:src, address_family, source_address),
         {:ok, source_port} <- decode_port(:src, source_port),
         {:ok, destination_address} <- decode_address(:dst, address_family, destination_address),
         {:ok, destination_port} <- decode_port(:dst, destination_port) do
      addresses = %{
        destination_address: destination_address,
        destination_port: destination_port,
        source_address: source_address,
        source_port: source_port
      }

      {:ok, addresses}
    end
  end

  def decode_address(src_or_dst, address_family, addr) do
    addr
    |> to_charlist()
    |> :inet.parse_address()
    |> case do
      {:ok, addr} ->
        case {address_family, addr} do
          {:inet, {_, _, _, _}} -> {:ok, addr}
          {:inet6, {_, _, _, _, _, _, _, _}} -> {:ok, addr}
          _ -> {:error, {:"bad_#{src_or_dst}_addr", :mismatched_address_family}}
        end

      {:error, e} ->
        {:error, {:"bad_#{src_or_dst}_addr", e}}
    end
  end

  def decode_port(src_or_dst, port) do
    case {src_or_dst, Integer.parse(port)} do
      {:src, {port, ""}} -> {:ok, port}
      {:dst, {port, ""}} -> {:ok, port}
      {_, {_port, _}} -> {:error, :"bad_#{src_or_dst}_port"}
      {_, :error} -> {:error, :"bad_#{src_or_dst}_port"}
    end
  end

  def split_addresses(addresses) do
    case String.split(addresses, " ") do
      [_, _, _, _] = addresses -> {:ok, addresses}
      _ -> {:error, :bad_line}
    end
  end
end
