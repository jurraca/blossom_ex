defmodule BlossomTest do
  use ExUnit.Case
  doctest Blossom

  test "greets the world" do
    assert Blossom.hello() == :world
  end
end
