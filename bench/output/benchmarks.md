Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 21:54:33.488648Z
Backend: native Elixir


## System

Benchmark suite executing on the following system:

<table style="width: 1%">
  <tr>
    <th style="width: 1%; white-space: nowrap">Operating System</th>
    <td>macOS</td>
  </tr><tr>
    <th style="white-space: nowrap">CPU Information</th>
    <td style="white-space: nowrap">Apple M4 Max</td>
  </tr><tr>
    <th style="white-space: nowrap">Number of Available Cores</th>
    <td style="white-space: nowrap">16</td>
  </tr><tr>
    <th style="white-space: nowrap">Available Memory</th>
    <td style="white-space: nowrap">128 GB</td>
  </tr><tr>
    <th style="white-space: nowrap">Elixir Version</th>
    <td style="white-space: nowrap">1.20.2</td>
  </tr><tr>
    <th style="white-space: nowrap">Erlang Version</th>
    <td style="white-space: nowrap">29.0.2</td>
  </tr>
</table>

## Configuration

Benchmark suite executing with the following configuration:

<table style="width: 1%">
  <tr>
    <th style="width: 1%">:time</th>
    <td style="white-space: nowrap">5 s</td>
  </tr><tr>
    <th>:parallel</th>
    <td style="white-space: nowrap">1</td>
  </tr><tr>
    <th>:warmup</th>
    <td style="white-space: nowrap">2 s</td>
  </tr>
</table>

## Statistics



Run Time

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Average</th>
    <th style="text-align: right">Devitation</th>
    <th style="text-align: right">Median</th>
    <th style="text-align: right">99th&nbsp;%</th>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3628.60 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1251.03%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap; text-align: right">3610.76 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1699.55%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1348.11 K</td>
    <td style="white-space: nowrap; text-align: right">0.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;803.50%</td>
    <td style="white-space: nowrap; text-align: right">0.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">285.87 K</td>
    <td style="white-space: nowrap; text-align: right">3.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;131.68%</td>
    <td style="white-space: nowrap; text-align: right">3.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">226.13 K</td>
    <td style="white-space: nowrap; text-align: right">4.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;123.57%</td>
    <td style="white-space: nowrap; text-align: right">4.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">108.12 K</td>
    <td style="white-space: nowrap; text-align: right">9.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;86.27%</td>
    <td style="white-space: nowrap; text-align: right">8.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">102.43 K</td>
    <td style="white-space: nowrap; text-align: right">9.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;94.00%</td>
    <td style="white-space: nowrap; text-align: right">8.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">99.07 K</td>
    <td style="white-space: nowrap; text-align: right">10.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.87%</td>
    <td style="white-space: nowrap; text-align: right">9.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.78 K</td>
    <td style="white-space: nowrap; text-align: right">10.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.69%</td>
    <td style="white-space: nowrap; text-align: right">10.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">88.43 K</td>
    <td style="white-space: nowrap; text-align: right">11.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;53.57%</td>
    <td style="white-space: nowrap; text-align: right">10.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">86.99 K</td>
    <td style="white-space: nowrap; text-align: right">11.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.24%</td>
    <td style="white-space: nowrap; text-align: right">10.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.74 K</td>
    <td style="white-space: nowrap; text-align: right">11.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;56.80%</td>
    <td style="white-space: nowrap; text-align: right">11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">82.00 K</td>
    <td style="white-space: nowrap; text-align: right">12.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;55.90%</td>
    <td style="white-space: nowrap; text-align: right">11.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">30.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">80.87 K</td>
    <td style="white-space: nowrap; text-align: right">12.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.00%</td>
    <td style="white-space: nowrap; text-align: right">11.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">66.42 K</td>
    <td style="white-space: nowrap; text-align: right">15.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;47.11%</td>
    <td style="white-space: nowrap; text-align: right">14.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">31.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">59.86 K</td>
    <td style="white-space: nowrap; text-align: right">16.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;38.57%</td>
    <td style="white-space: nowrap; text-align: right">15.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.90 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">58.90 K</td>
    <td style="white-space: nowrap; text-align: right">16.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;32.15%</td>
    <td style="white-space: nowrap; text-align: right">16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">55.77 K</td>
    <td style="white-space: nowrap; text-align: right">17.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.88%</td>
    <td style="white-space: nowrap; text-align: right">17.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.30 K</td>
    <td style="white-space: nowrap; text-align: right">22.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.64%</td>
    <td style="white-space: nowrap; text-align: right">21.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">54.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.32 K</td>
    <td style="white-space: nowrap; text-align: right">24.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.71%</td>
    <td style="white-space: nowrap; text-align: right">23.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">46.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">38.32 K</td>
    <td style="white-space: nowrap; text-align: right">26.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.26%</td>
    <td style="white-space: nowrap; text-align: right">24.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.53 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.89 K</td>
    <td style="white-space: nowrap; text-align: right">35.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.19%</td>
    <td style="white-space: nowrap; text-align: right">34.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">51.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">27.74 K</td>
    <td style="white-space: nowrap; text-align: right">36.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.09%</td>
    <td style="white-space: nowrap; text-align: right">34.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.14 K</td>
    <td style="white-space: nowrap; text-align: right">38.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.68%</td>
    <td style="white-space: nowrap; text-align: right">34.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">76.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">24.90 K</td>
    <td style="white-space: nowrap; text-align: right">40.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.87%</td>
    <td style="white-space: nowrap; text-align: right">36.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">78.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">24.67 K</td>
    <td style="white-space: nowrap; text-align: right">40.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.74%</td>
    <td style="white-space: nowrap; text-align: right">39.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.85 K</td>
    <td style="white-space: nowrap; text-align: right">43.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.02%</td>
    <td style="white-space: nowrap; text-align: right">43.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">56.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.49 K</td>
    <td style="white-space: nowrap; text-align: right">51.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.78%</td>
    <td style="white-space: nowrap; text-align: right">49.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">80.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.62 K</td>
    <td style="white-space: nowrap; text-align: right">53.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.69%</td>
    <td style="white-space: nowrap; text-align: right">52.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">71.80 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.66 K</td>
    <td style="white-space: nowrap; text-align: right">60.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.94%</td>
    <td style="white-space: nowrap; text-align: right">59.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">78.39 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">16.35 K</td>
    <td style="white-space: nowrap; text-align: right">61.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.87%</td>
    <td style="white-space: nowrap; text-align: right">59.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">83.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.21 K</td>
    <td style="white-space: nowrap; text-align: right">65.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.08%</td>
    <td style="white-space: nowrap; text-align: right">65.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">82.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.33 K</td>
    <td style="white-space: nowrap; text-align: right">75.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.82%</td>
    <td style="white-space: nowrap; text-align: right">74.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">93.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.14 K</td>
    <td style="white-space: nowrap; text-align: right">76.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.60%</td>
    <td style="white-space: nowrap; text-align: right">74.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">100.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.14 K</td>
    <td style="white-space: nowrap; text-align: right">98.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.49%</td>
    <td style="white-space: nowrap; text-align: right">97.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">129.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.24 K</td>
    <td style="white-space: nowrap; text-align: right">108.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.22%</td>
    <td style="white-space: nowrap; text-align: right">107.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">137.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.65 K</td>
    <td style="white-space: nowrap; text-align: right">115.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.76%</td>
    <td style="white-space: nowrap; text-align: right">114.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">142.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.18 K</td>
    <td style="white-space: nowrap; text-align: right">122.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.22%</td>
    <td style="white-space: nowrap; text-align: right">121.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">155.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.55 K</td>
    <td style="white-space: nowrap; text-align: right">180.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.62%</td>
    <td style="white-space: nowrap; text-align: right">178.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">246.77 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.09 K</td>
    <td style="white-space: nowrap; text-align: right">244.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.41%</td>
    <td style="white-space: nowrap; text-align: right">241.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">306.88 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap;text-align: right">3628.60 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap; text-align: right">3610.76 K</td>
    <td style="white-space: nowrap; text-align: right">1.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1348.11 K</td>
    <td style="white-space: nowrap; text-align: right">2.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">285.87 K</td>
    <td style="white-space: nowrap; text-align: right">12.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">226.13 K</td>
    <td style="white-space: nowrap; text-align: right">16.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">108.12 K</td>
    <td style="white-space: nowrap; text-align: right">33.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">102.43 K</td>
    <td style="white-space: nowrap; text-align: right">35.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">99.07 K</td>
    <td style="white-space: nowrap; text-align: right">36.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.78 K</td>
    <td style="white-space: nowrap; text-align: right">38.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">88.43 K</td>
    <td style="white-space: nowrap; text-align: right">41.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">86.99 K</td>
    <td style="white-space: nowrap; text-align: right">41.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.74 K</td>
    <td style="white-space: nowrap; text-align: right">42.32x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">82.00 K</td>
    <td style="white-space: nowrap; text-align: right">44.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">80.87 K</td>
    <td style="white-space: nowrap; text-align: right">44.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">66.42 K</td>
    <td style="white-space: nowrap; text-align: right">54.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">59.86 K</td>
    <td style="white-space: nowrap; text-align: right">60.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">58.90 K</td>
    <td style="white-space: nowrap; text-align: right">61.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">55.77 K</td>
    <td style="white-space: nowrap; text-align: right">65.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.30 K</td>
    <td style="white-space: nowrap; text-align: right">81.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.32 K</td>
    <td style="white-space: nowrap; text-align: right">90.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">38.32 K</td>
    <td style="white-space: nowrap; text-align: right">94.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.89 K</td>
    <td style="white-space: nowrap; text-align: right">130.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">27.74 K</td>
    <td style="white-space: nowrap; text-align: right">130.79x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.14 K</td>
    <td style="white-space: nowrap; text-align: right">138.81x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">24.90 K</td>
    <td style="white-space: nowrap; text-align: right">145.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">24.67 K</td>
    <td style="white-space: nowrap; text-align: right">147.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.85 K</td>
    <td style="white-space: nowrap; text-align: right">158.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.49 K</td>
    <td style="white-space: nowrap; text-align: right">186.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.62 K</td>
    <td style="white-space: nowrap; text-align: right">194.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.66 K</td>
    <td style="white-space: nowrap; text-align: right">217.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">16.35 K</td>
    <td style="white-space: nowrap; text-align: right">221.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.21 K</td>
    <td style="white-space: nowrap; text-align: right">238.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.33 K</td>
    <td style="white-space: nowrap; text-align: right">272.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.14 K</td>
    <td style="white-space: nowrap; text-align: right">276.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.14 K</td>
    <td style="white-space: nowrap; text-align: right">357.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.24 K</td>
    <td style="white-space: nowrap; text-align: right">392.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.65 K</td>
    <td style="white-space: nowrap; text-align: right">419.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.18 K</td>
    <td style="white-space: nowrap; text-align: right">443.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.55 K</td>
    <td style="white-space: nowrap; text-align: right">654.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.09 K</td>
    <td style="white-space: nowrap; text-align: right">888.07x</td>
  </tr>

</table>



Memory Usage

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">Average</th>
    <th style="text-align: right">Factor</th>
  </tr>
  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap">0.0234 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap">0.188 KB</td>
    <td>8.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap">1.34 KB</td>
    <td>57.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap">4.38 KB</td>
    <td>187.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap">11.18 KB</td>
    <td>477.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap">9.55 KB</td>
    <td>407.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.71 KB</td>
    <td>201.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap">27.41 KB</td>
    <td>1169.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>1176.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.77 KB</td>
    <td>331.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.32 KB</td>
    <td>995.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.79 KB</td>
    <td>247.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap">10.98 KB</td>
    <td>468.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap">29.76 KB</td>
    <td>1269.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">8.34 KB</td>
    <td>356.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">12.02 KB</td>
    <td>512.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap">13.48 KB</td>
    <td>575.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.23 KB</td>
    <td>735.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">16.90 KB</td>
    <td>721.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>3077.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap">10.88 KB</td>
    <td>464.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">68.59 KB</td>
    <td>2926.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">51.73 KB</td>
    <td>2207.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap">40.66 KB</td>
    <td>1735.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap">40.95 KB</td>
    <td>1747.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap">55.74 KB</td>
    <td>2378.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>87.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.75 KB</td>
    <td>1525.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.74 KB</td>
    <td>117.06x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>768.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap">15.27 KB</td>
    <td>651.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap">62.88 KB</td>
    <td>2683.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>2364.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.29 KB</td>
    <td>1420.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap">74.30 KB</td>
    <td>3170.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap">68.34 KB</td>
    <td>2916.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.62 KB</td>
    <td>197.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap">115.90 KB</td>
    <td>4945.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap">171.92 KB</td>
    <td>7335.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap">720.41 KB</td>
    <td>30737.33x</td>
  </tr>
</table>