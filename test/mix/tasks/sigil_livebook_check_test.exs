defmodule Mix.Tasks.Sigil.LivebookCheckTest do
  @moduledoc false

  use ExUnit.Case, async: false

  import ExUnit.CaptureIO

  alias Mix.Tasks.Sigil.LivebookCheck

  describe "run/1" do
    test "prints success for clean notebooks" do
      root =
        fixture_root(%{
          "notebooks/clean.livemd" => livebook(["value = 41", "42 = value + 1"])
        })

      output =
        capture_io(fn ->
          File.cd!(root, fn ->
            assert :ok = LivebookCheck.run([])
          end)
        end)

      assert output =~ "Livebook check passed"
    end

    test "raises when a cell fails" do
      root =
        fixture_root(%{
          "notebooks/failing.livemd" => livebook(["1 = 2"])
        })

      assert_raise Mix.Error, ~r/notebooks\/failing\.livemd failed/, fn ->
        File.cd!(root, fn -> LivebookCheck.run([]) end)
      end
    end
  end

  describe "check/2" do
    test "validates selected notebooks" do
      root =
        fixture_root(%{
          "notebooks/clean.livemd" => livebook(["message = \"ok\"", "\"ok\" = message"])
        })

      assert :ok = LivebookCheck.check(["notebooks/clean.livemd"], root: root)
    end

    test "forces the offline AI path and clears Livebook provider settings" do
      root =
        fixture_root(%{
          "notebooks/offline.livemd" =>
            livebook([
              "\"scripted\" = System.fetch_env!(\"SIGILGUARD_AI_MODE\")",
              "nil = System.get_env(\"LB_OPENAI_API_KEY\")",
              "nil = System.get_env(\"LB_SIGILGUARD_MODEL\")",
              "\"1\" = System.fetch_env!(\"HEX_OFFLINE\")",
              "\"1\" = System.fetch_env!(\"REBAR_OFFLINE\")"
            ])
        })

      assert :ok = LivebookCheck.check(["notebooks/offline.livemd"], root: root)
    end

    test "returns failures without raising" do
      root =
        fixture_root(%{
          "notebooks/failing.livemd" => livebook(["raise \"boom\""])
        })

      assert {:error, [failure]} = LivebookCheck.check([], root: root)
      assert failure =~ "notebooks/failing.livemd failed"
      assert failure =~ "boom"
    end

    test "rejects missing selected notebooks" do
      root = fixture_root(%{})

      assert_raise Mix.Error, ~r/Livebook not found/, fn ->
        LivebookCheck.check(["notebooks/missing.livemd"], root: root)
      end
    end
  end

  test "extracts only elixir cells" do
    markdown = """
    # Example

    ```elixir
    one = 1
    ```

    ```text
    ignored
    ```

    ```elixir
    two = 2
    ```
    """

    assert LivebookCheck.elixir_cells(markdown) == ["one = 1", "two = 2"]
  end

  defp livebook(cells) do
    body =
      Enum.map_join(cells, "\n\n", fn cell ->
        """
        ```elixir
        #{cell}
        ```
        """
      end)

    "# Fixture\n\n" <> body
  end

  defp fixture_root(files) do
    root =
      Path.join(System.tmp_dir!(), "sigil_livebook_check_#{System.unique_integer([:positive])}")

    File.rm_rf!(root)

    Enum.each(files, fn {relative, body} ->
      path = Path.join(root, relative)
      File.mkdir_p!(Path.dirname(path))
      File.write!(path, body)
    end)

    root
  end
end
