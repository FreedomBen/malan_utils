defmodule MalanUtils do
  @doc ~S"""
  Macro that makes a function public in test, private in non-test

  See:  https://stackoverflow.com/a/47598190/2062384
  """
  defmacro defp_testable(head, body \\ nil) do
    if Mix.env() == :test do
      quote do
        def unquote(head) do
          unquote(body[:do])
        end
      end
    else
      quote do
        defp unquote(head) do
          unquote(body[:do])
        end
      end
    end
  end

  @doc ~S"""
  Easy drop-in to a pipe to inspect the return value of the previous function.

  ## Examples

      conn
      |> put_status(:not_found)
      |> put_view(MalanWeb.ErrorView)
      |> render(:"404")
      |> pry_pipe()

  ## Alternatives

  You may also wish to consider using `IO.inspect/3` in pipelines.  `IO.inspect/3`
  will print and return the value unchanged.  Example:

      conn
      |> put_status(:not_found)
      |> IO.inspect(label: "after status")
      |> render(:"404")

  """
  def pry_pipe(retval, arg1 \\ nil, arg2 \\ nil, arg3 \\ nil, arg4 \\ nil) do
    require IEx
    IEx.pry()
    retval
  end

  @doc ~S"""
  Retrieve syntax colors for embedding into `:syntax_colors` of `Inspect.Opts`

  You probably don't want this directly.  You probably want `inspect_format`
  """
  def inspect_syntax_colors do
    [
      number: :yellow,
      atom: :cyan,
      string: :green,
      boolean: :magenta,
      nil: :magenta
    ]
  end

  @doc ~S"""
  Get `Inspect.Opts` for `Kernel.inspect` or `IO.inspect`

  If `opaque_struct` is false, then structs will be printed as `Map`s, which
  allows you to see any opaque fields they might have set

  `limit` is the max number of stuff printed out.  Can be an integer or `:infinity`
  """
  def inspect_format(opaque_struct \\ true, limit \\ 50) do
    [
      structs: opaque_struct,
      limit: limit,
      syntax_colors: inspect_syntax_colors(),
      width: 80
    ]
  end

  @doc ~S"""
  Runs `IO.inspect/2` with pretty printing, colors, and unlimited size.

  If `opaque_struct` is false, then structs will be printed as `Map`s, which
  allows you to see any opaque fields they might have set
  """
  def inspect(val, opaque_struct \\ true, limit \\ 50) do
    Kernel.inspect(val, inspect_format(opaque_struct, limit))
  end

  @doc ~S"""
  Convert a map with `String` keys into a map with `Atom` keys.

  ## Examples

      iex> MalanUtils.map_string_keys_to_atoms(%{"one" => "one", "two" => "two"})
      %{one: "one", two: "two"}m

  """
  def map_string_keys_to_atoms(map) do
    for {key, val} <- map, into: %{} do
      {String.to_atom(key), val}
    end
  end

  @doc ~S"""
  Convert a map with `String` keys into a map with `Atom` keys.

  ## Examples

      iex> MalanUtils.map_atom_keys_to_strings(%{one: "one", two: "two"})
      %{"one" => "one", "two" => "two"}

  """
  def map_atom_keys_to_strings(map) do
    for {key, val} <- map, into: %{} do
      {Atom.to_string(key), val}
    end
  end

  @doc ~S"""
  Converts a struct to a regular map by deleting the `:__meta__` key

  ## Examples

      MalanUtils.struct_to_map(%Something{hello: "world"})
      %{hello: "world"}

  """
  def struct_to_map(struct, mask_keys \\ []) do
    Map.from_struct(struct)
    |> Map.delete(:__meta__)
    |> mask_map_key_values(mask_keys)
  end

  @doc ~S"""
  Takes a map and a list of keys whose values should be masked

  ## Examples

      iex> MalanUtils.mask_map_key_values(%{name: "Ben, title: "Lord"}, [:title])
      %{name: "Ben", title: "****"}

      iex> MalanUtils.mask_map_key_values(%{name: "Ben, age: 39}, [:age])
      %{name: "Ben", age: "**"}
  """
  def mask_map_key_values(map, mask_keys) do
    map
    |> Enum.map(fn {key, val} ->
      case key in list_to_strings_and_atoms(mask_keys) do
        true -> {key, mask_str(val)}
        _ -> {key, val}
      end
    end)
    |> Enum.into(%{})
  end

  @doc ~S"""
  Generates a new random UUIDv4

  ## Examples

      MalanUtils.uuidgen()
      "4c2fd8d3-a6e3-4e4b-a2ce-3f21456eeb85"

  """
  def uuidgen(),
    do: bingenerate() |> encode()

  @doc ~S"""
  Quick regex check to see if the supplied `string` is a valid UUID

  Check is done by simple regular expression and is not overly sophisticated.

  Return true || false

  ## Examples

      iex> MalanUtils.is_uuid?(nil)
      false
      iex> MalanUtils.is_uuid?("hello world")
      false
      iex> MalanUtils.is_uuid?("4c2fd8d3-a6e3-4e4b-a2ce-3f21456eeb85")
      true

  """
  def is_uuid?(nil), do: false

  def is_uuid?(string),
    do:
      string =~ ~r/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

  def is_uuid_or_nil?(nil), do: true
  def is_uuid_or_nil?(string), do: is_uuid?(string)

  # def nil_or_empty?(nil), do: true
  # def nil_or_empty?(str) when is_string(str), do: "" == str |> String.trim()

  @doc """
  Checks if the passed item is nil or empty string.

  The param will be passed to `Kernel.to_string()`
  and then `String.trim()` and checked for empty string

  ## Examples

      iex> MalanUtils.nil_or_empty?("hello")
      false
      iex> MalanUtils.nil_or_empty?("")
      true
      iex> MalanUtils.nil_or_empty?(nil)
      true

  """
  def nil_or_empty?(str_or_nil) do
    "" == str_or_nil |> Kernel.to_string() |> String.trim()
  end

  def not_nil_or_empty?(str_or_nil), do: not nil_or_empty?(str_or_nil)

  @doc """
  if `value` (value of the argument) is nil, this will raise `MalanUtils.CantBeNil`

  `argn` (name of the argument) will be passed to allow for more helpful error
  messages that tell you the name of the variable that was `nil`

  ## Examples

      iex> MalanUtils.raise_if_nil!("somevar", "someval")
      "someval"
      iex> MalanUtils.raise_if_nil!("somevar", nil)
      ** (MalanUtils.CantBeNil) variable 'somevar' was nil but cannot be
          (malan 0.1.0) lib/malan/utils.ex:135: MalanUtils.raise_if_nil!/2

  """
  def raise_if_nil!(varname, value) do
    case is_nil(value) do
      true -> raise MalanUtils.CantBeNil, varname: varname
      false -> value
    end
  end

  @doc """
  if `value` (value of the argument) is nil, this will raise `MalanUtils.CantBeNil`

  `argn` (name of the argument) will be passed to allow for more helpful error
  messages that tell you the name of the variable that was `nil`

  ## Examples

      iex> MalanUtils.raise_if_nil!("someval")
      "someval"
      iex> MalanUtils.raise_if_nil!(nil)
      ** (MalanUtils.CantBeNil) variable 'somevar' was nil but cannot be
          (malan 0.1.0) lib/malan/utils.ex:142: MalanUtils.raise_if_nil!/1

  """
  def raise_if_nil!(value) do
    case is_nil(value) do
      true -> raise MalanUtils.CantBeNil
      false -> value
    end
  end

  @doc ~S"""
  Replaces the caracters in `str` with asterisks `"*"`, thus "masking" the value.

  If argument is `nil` nothing will change `nil` will be returned.
  If argument is not a `binary()`, it will be coerced to a binary then masked.
  """
  def mask_str(nil), do: nil
  def mask_str(str) when is_binary(str), do: String.replace(str, ~r/./, "*")
  def mask_str(val), do: Kernel.inspect(val) |> mask_str()

  @doc """
  Convert a list to a `String`, suitable for printing

  Will raise a `String.chars` error if can't coerce part to a `String`

  `mask_keys` is used to mask the values in any keys that are in maps in the `list`
  """
  @spec list_to_string(list :: list() | String.Chars.t(), mask_keys :: list(binary())) :: binary()
  def list_to_string(list, mask_keys \\ []) do
    list
    |> Enum.map(fn val ->
      case val do
        %{} -> map_to_string(val, mask_keys)
        l when is_list(l) -> list_to_string(l, mask_keys)
        t when is_tuple(t) -> tuple_to_string(t, mask_keys)
        _ -> Kernel.to_string(val)
      end
    end)
    |> Enum.join(", ")
  end

  @doc """
  Convert a tuple to a `String`, suitable for printing

  Will raise a `String.chars` error if can't coerce part to a `String`

  `mask_keys` is used to mask the values in any keys that are in maps in the `tuple`
  """
  @spec tuple_to_string(tuple :: tuple() | String.Chars.t(), mask_keys :: list(binary())) ::
          binary()
  def tuple_to_string(tuple, mask_keys \\ []) do
    tuple
    |> Tuple.to_list()
    |> list_to_string(mask_keys)
  end

  @doc """
  Convert a map to a `String`, suitable for printing.

  Optionally pass a list of keys to mask.

  ## Examples

      iex> map_to_string(%{michael: "knight"})
      "michael: 'knight'"

      iex> map_to_string(%{michael: "knight", kitt: "karr"})
      "kitt: 'karr', michael: 'knight'"

      iex> map_to_string(%{michael: "knight", kitt: "karr"}, [:kitt])
      "kitt: '****', michael: 'knight'"

      iex> map_to_string(%{michael: "knight", kitt: "karr"}, [:kitt, :michael])
      "kitt: '****', michael: '******'"

      iex> map_to_string(%{"michael" => "knight", "kitt" => "karr", "carr" => "hart"}, ["kitt", "michael"])
      "carr: 'hart', kitt: '****', michael: '******'"

  """
  @spec map_to_string(map :: map() | String.Chars.t(), mask_keys :: list(binary())) :: binary()
  def map_to_string(map, mask_keys \\ [])

  def map_to_string(%{} = map, mask_keys) do
    Map.to_list(map)
    |> Enum.reverse()
    |> Enum.map(fn {key, val} ->
      case val do
        %{} -> {key, map_to_string(val, mask_keys)}
        l when is_list(l) -> {key, list_to_string(l, mask_keys)}
        t when is_tuple(t) -> {key, tuple_to_string(t, mask_keys)}
        _ -> {key, val}
      end
    end)
    |> Enum.map(fn {key, val} ->
      case key in list_to_strings_and_atoms(mask_keys) do
        true -> {key, mask_str(val)}
        _ -> {key, val}
      end
    end)
    |> Enum.map(fn {key, val} -> "#{key}: '#{val}'" end)
    |> Enum.join(", ")
  end

  def map_to_string(not_a_map, _mask_keys), do: Kernel.to_string(not_a_map)

  @doc ~S"""
  Convert the value, map, or list to a string, suitable for printing or storing.

  If the value is not a map or list, it must be a type that implements the
  `String.Chars` protocol, otherwise this will fail.

  The reason to offer this util function rather than implementing `String.Chars`
  for maps and lists is that we want to make sure that we never accidentally
  convert those to a string.  This conversion is somewhat destructive and is
  irreversable, so it should only be done intentionally.
  """
  @spec to_string(input :: map() | list() | String.Chars.t(), mask_keys :: list(binary())) ::
          binary()
  def to_string(value, mask_keys \\ [])
  def to_string(%{} = map, mask_keys), do: map_to_string(map, mask_keys)
  def to_string(list, mask_keys) when is_list(list), do: list_to_string(list, mask_keys)
  def to_string(tuple, mask_keys) when is_tuple(tuple), do: tuple_to_string(tuple, mask_keys)
  def to_string(value, _mask_keys), do: Kernel.to_string(value)

  defp atom_or_string_to_string_or_atom(atom) when is_atom(atom) do
    Atom.to_string(atom)
  end

  defp atom_or_string_to_string_or_atom(string) when is_binary(string) do
    String.to_atom(string)
  end

  @doc """
  Takes a list of strings or atoms and returns a list with string and atoms.

  ## Examples

      iex> list_to_strings_and_atoms([:circle])
      [:circle, "circle"]

      iex> list_to_strings_and_atoms([:circle, :square])
      [:square, "square", :circle, "circle"]

      iex> list_to_strings_and_atoms(["circle", "square"])
      ["square", :square, "circle", :circle]
  """
  def list_to_strings_and_atoms(list) do
    Enum.reduce(list, [], fn l, acc -> [l | [atom_or_string_to_string_or_atom(l) | acc]] end)
  end

  def trunc_str(str, length \\ 255), do: String.slice(str, 0, length)

  # Derived from `Ecto` library.  Apache 2.0 licensed.
  @typedoc """
  A raw binary representation of a UUID.
  """
  @type uuid_raw :: <<_::128>>

  # Derived from `Ecto` library.  Apache 2.0 licensed.
  @typedoc """
  A hex-encoded UUID string.
  """
  @type uuid :: <<_::288>>

  # Derived from `Ecto` library.  Apache 2.0 licensed.
  @spec bingenerate() :: uuid_raw
  defp bingenerate() do
    <<u0::48, _::4, u1::12, _::2, u2::62>> = :crypto.strong_rand_bytes(16)
    <<u0::48, 4::4, u1::12, 2::2, u2::62>>
  end

  # Derived from `Ecto` library.  Apache 2.0 licensed.
  @spec encode(uuid_raw) :: uuid
  defp encode(<< a1::4, a2::4, a3::4, a4::4,
                 a5::4, a6::4, a7::4, a8::4,
                 b1::4, b2::4, b3::4, b4::4,
                 c1::4, c2::4, c3::4, c4::4,
                 d1::4, d2::4, d3::4, d4::4,
                 e1::4, e2::4, e3::4, e4::4,
                 e5::4, e6::4, e7::4, e8::4,
                 e9::4, e10::4, e11::4, e12::4 >>) do
    << e(a1), e(a2), e(a3), e(a4), e(a5), e(a6), e(a7), e(a8), ?-,
       e(b1), e(b2), e(b3), e(b4), ?-,
       e(c1), e(c2), e(c3), e(c4), ?-,
       e(d1), e(d2), e(d3), e(d4), ?-,
       e(e1), e(e2), e(e3), e(e4), e(e5), e(e6), e(e7), e(e8), e(e9), e(e10), e(e11), e(e12) >>
    # << ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?-,
    #    e(b1), e(b2), e(b3), e(b4), ?-,
    #    e(c1), e(c2), e(c3), e(c4), ?-,
    #    e(d1), e(d2), e(d3), e(d4), ?-,
    #    e(e1), e(e2), e(e3), e(e4), e(e5), e(e6), e(e7), e(e8), e(e9), e(e10), e(e11), e(e12) >>
  end

  @compile {:inline, e: 1}

  # Derived from `Ecto` library.  Apache 2.0 licensed.
  defp e(0),  do: ?0
  defp e(1),  do: ?1
  defp e(2),  do: ?2
  defp e(3),  do: ?3
  defp e(4),  do: ?4
  defp e(5),  do: ?5
  defp e(6),  do: ?6
  defp e(7),  do: ?7
  defp e(8),  do: ?8
  defp e(9),  do: ?9
  defp e(10), do: ?a
  defp e(11), do: ?b
  defp e(12), do: ?c
  defp e(13), do: ?d
  defp e(14), do: ?e
  defp e(15), do: ?f
end

defmodule MalanUtils.CantBeNil do
  defexception [:message]

  def exception(opts) do
    varname = Keyword.get(opts, :varname, nil)

    msg =
      case varname do
        nil -> "value was set to nil but cannot be"
        _ -> "variable '#{varname}' was nil but cannot be"
      end

    %__MODULE__{message: msg}
  end
end

defmodule MalanUtils.Enum do
  @doc """
  will return true if all invocations of the function return false.  If one callback returns `true`, the end result will be `false`

  `Enum.all?` will return true if all invocations of the function return
  true. `MalanUtils.Enum.none?` is the opposite.
  """
  def none?(enum, func) do
    Enum.all?(enum, fn i -> !func.(i) end)
  end
end

defmodule MalanUtils.Crypto do
  def strong_random_string(length) do
    :crypto.strong_rand_bytes(length)
    |> Base.encode64(padding: false)
    |> String.replace(~r{\+}, "C")
    |> String.replace(~r{/}, "z")
    |> binary_part(0, length)
  end

  def hash_password(password) do
    Pbkdf2.hash_pwd_salt(password)
  end

  def verify_password(given_pass, password_hash) do
    Pbkdf2.verify_pass(given_pass, password_hash)
  end

  def fake_verify_password() do
    Pbkdf2.no_user_verify()
  end

  def hash_token(api_token) do
    :crypto.hash(:sha256, api_token)
    |> Base.encode64()
  end
end

defmodule MalanUtils.DateTime do
  def utc_now_trunc(),
    do: DateTime.truncate(DateTime.utc_now(), :second)

  @doc "Return a DateTime about 200 years into the future"
  def distant_future() do
    round(52.5 * 200 * 7 * 24 * 60 * 60)
    |> adjust_cur_time_trunc(:seconds)
  end

  # New implementation, needs testing
  # def distant_future(),
  #   do: adjust_cur_time(200, :years)

  @doc """
  Add the specified number of units to the current time.

  Supplying a negative number will adjust the time backwards by the
  specified units, while supplying a positive will adjust the time
  forwards by the specified units.
  """
  def adjust_cur_time(num_years, :years),
    do: adjust_cur_time(round(num_years * 52.5), :weeks)

  def adjust_cur_time(num_weeks, :weeks),
    do: adjust_cur_time(num_weeks * 7, :days)

  def adjust_cur_time(num_days, :days),
    do: adjust_cur_time(num_days * 24, :hours)

  def adjust_cur_time(num_hours, :hours),
    do: adjust_cur_time(num_hours * 60, :minutes)

  def adjust_cur_time(num_minutes, :minutes),
    do: adjust_cur_time(num_minutes * 60, :seconds)

  def adjust_cur_time(num_seconds, :seconds),
    do: adjust_time(DateTime.utc_now(), num_seconds, :seconds)

  def adjust_cur_time_trunc(num_weeks, :weeks),
    do: adjust_cur_time_trunc(num_weeks * 7, :days)

  def adjust_cur_time_trunc(num_days, :days),
    do: adjust_cur_time_trunc(num_days * 24, :hours)

  def adjust_cur_time_trunc(num_hours, :hours),
    do: adjust_cur_time_trunc(num_hours * 60, :minutes)

  def adjust_cur_time_trunc(num_minutes, :minutes),
    do: adjust_cur_time_trunc(num_minutes * 60, :seconds)

  def adjust_cur_time_trunc(num_seconds, :seconds),
    do: adjust_time(utc_now_trunc(), num_seconds, :seconds)

  def adjust_time(time, num_weeks, :weeks),
    do: adjust_time(time, num_weeks * 7, :days)

  def adjust_time(time, num_days, :days),
    do: adjust_time(time, num_days * 24, :hours)

  def adjust_time(time, num_hours, :hours),
    do: adjust_time(time, num_hours * 60, :minutes)

  def adjust_time(time, num_minutes, :minutes),
    do: adjust_time(time, num_minutes * 60, :seconds)

  def adjust_time(time, num_seconds, :seconds),
    do: DateTime.add(time, num_seconds, :second)

  @doc "Check if `past_time` occurs before `current_time`.  Equal date returns true"
  @spec in_the_past?(DateTime.t(), DateTime.t()) :: boolean()

  def in_the_past?(past_time, current_time),
    do: DateTime.compare(past_time, current_time) != :gt

  @doc "Check if `past_time` occurs before the current time"
  @spec in_the_past?(DateTime.t()) :: boolean()

  def in_the_past?(nil),
    do: raise(ArgumentError, message: "past_time time must not be nil!")

  def in_the_past?(past_time),
    do: in_the_past?(past_time, DateTime.utc_now())

  def expired?(expires_at, current_time),
    do: in_the_past?(expires_at, current_time)

  def expired?(nil),
    do: raise(ArgumentError, message: "expires_at time must not be nil!")

  def expired?(expires_at),
    do: in_the_past?(expires_at, DateTime.utc_now())
end

defmodule MalanUtils.IPv4 do
  def to_s(ip_tuple) do
    ip_tuple
    |> :inet_parse.ntoa()
    |> Kernel.to_string()
  end
end

defmodule MalanUtils.FromEnv do
  def log_str(env, :mfa), do: "[#{mfa_str(env)}]"
  def log_str(env, :func_only), do: "[#{func_str(env)}]"
  def log_str(env), do: log_str(env, :mfa)

  def mfa_str(env), do: mod_str(env) <> "." <> func_str(env)

  def func_str({func, arity}), do: "##{func}/#{arity}"
  def func_str(env), do: func_str(env.function)

  def mod_str(env), do: Kernel.to_string(env.module)
end
