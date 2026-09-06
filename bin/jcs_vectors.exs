:rand.seed(:exsss, {42, 123, 789})

vectors =
  for _ <- 1..50_000, reduce: [] do
    acc ->
      bits = :rand.uniform(0x7FEFFFFFFFFFFFFF)
      <<number::float-64>> = <<bits::64>>
      {:ok, encoded} = SigilGuard.Canonical.JCS.encode(number)
      [[Base.encode16(<<bits::64>>, case: :lower), encoded] | acc]
  end

File.write!(List.first(System.argv()), Jason.encode!(vectors))
