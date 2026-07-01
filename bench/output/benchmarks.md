Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-07-01 16:24:05.789177Z
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
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap; text-align: right">4326.21 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1573.46%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4025.67 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1186.85%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1481.04 K</td>
    <td style="white-space: nowrap; text-align: right">0.68 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1459.77%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / canonical bytes</td>
    <td style="white-space: nowrap; text-align: right">404.96 K</td>
    <td style="white-space: nowrap; text-align: right">2.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;173.37%</td>
    <td style="white-space: nowrap; text-align: right">2.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / digest</td>
    <td style="white-space: nowrap; text-align: right">368.24 K</td>
    <td style="white-space: nowrap; text-align: right">2.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;204.12%</td>
    <td style="white-space: nowrap; text-align: right">2.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">283.94 K</td>
    <td style="white-space: nowrap; text-align: right">3.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;122.81%</td>
    <td style="white-space: nowrap; text-align: right">3.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">255.02 K</td>
    <td style="white-space: nowrap; text-align: right">3.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;153.59%</td>
    <td style="white-space: nowrap; text-align: right">3.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">237.92 K</td>
    <td style="white-space: nowrap; text-align: right">4.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;124.55%</td>
    <td style="white-space: nowrap; text-align: right">3.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">235.54 K</td>
    <td style="white-space: nowrap; text-align: right">4.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;115.18%</td>
    <td style="white-space: nowrap; text-align: right">3.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">215.37 K</td>
    <td style="white-space: nowrap; text-align: right">4.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;227.88%</td>
    <td style="white-space: nowrap; text-align: right">4 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">9.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">159.61 K</td>
    <td style="white-space: nowrap; text-align: right">6.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;274.18%</td>
    <td style="white-space: nowrap; text-align: right">5.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">156.10 K</td>
    <td style="white-space: nowrap; text-align: right">6.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;266.76%</td>
    <td style="white-space: nowrap; text-align: right">5.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">14.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">112.29 K</td>
    <td style="white-space: nowrap; text-align: right">8.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;57.98%</td>
    <td style="white-space: nowrap; text-align: right">8.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">108.51 K</td>
    <td style="white-space: nowrap; text-align: right">9.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;55.75%</td>
    <td style="white-space: nowrap; text-align: right">8.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">106.60 K</td>
    <td style="white-space: nowrap; text-align: right">9.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;89.10%</td>
    <td style="white-space: nowrap; text-align: right">8.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.05 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">101.53 K</td>
    <td style="white-space: nowrap; text-align: right">9.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.80%</td>
    <td style="white-space: nowrap; text-align: right">9.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">97.86 K</td>
    <td style="white-space: nowrap; text-align: right">10.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;181.43%</td>
    <td style="white-space: nowrap; text-align: right">9.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">92.32 K</td>
    <td style="white-space: nowrap; text-align: right">10.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.61%</td>
    <td style="white-space: nowrap; text-align: right">10.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">90.82 K</td>
    <td style="white-space: nowrap; text-align: right">11.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;64.76%</td>
    <td style="white-space: nowrap; text-align: right">9.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">51.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">84.96 K</td>
    <td style="white-space: nowrap; text-align: right">11.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.13%</td>
    <td style="white-space: nowrap; text-align: right">10.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.78 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">84.84 K</td>
    <td style="white-space: nowrap; text-align: right">11.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.12%</td>
    <td style="white-space: nowrap; text-align: right">11.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">61.83 K</td>
    <td style="white-space: nowrap; text-align: right">16.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.15%</td>
    <td style="white-space: nowrap; text-align: right">14.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.37 K</td>
    <td style="white-space: nowrap; text-align: right">16.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.33%</td>
    <td style="white-space: nowrap; text-align: right">15.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">31.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">56.95 K</td>
    <td style="white-space: nowrap; text-align: right">17.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;60.89%</td>
    <td style="white-space: nowrap; text-align: right">16.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.75 K</td>
    <td style="white-space: nowrap; text-align: right">22.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.48%</td>
    <td style="white-space: nowrap; text-align: right">21.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.03 K</td>
    <td style="white-space: nowrap; text-align: right">24.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.06%</td>
    <td style="white-space: nowrap; text-align: right">23.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">35.60 K</td>
    <td style="white-space: nowrap; text-align: right">28.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.06%</td>
    <td style="white-space: nowrap; text-align: right">26.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">40 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">33.44 K</td>
    <td style="white-space: nowrap; text-align: right">29.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;86.32%</td>
    <td style="white-space: nowrap; text-align: right">28.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">31.17 K</td>
    <td style="white-space: nowrap; text-align: right">32.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.67%</td>
    <td style="white-space: nowrap; text-align: right">30.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.96 K</td>
    <td style="white-space: nowrap; text-align: right">35.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.34%</td>
    <td style="white-space: nowrap; text-align: right">32.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">27.25 K</td>
    <td style="white-space: nowrap; text-align: right">36.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.40%</td>
    <td style="white-space: nowrap; text-align: right">32.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">69.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.13 K</td>
    <td style="white-space: nowrap; text-align: right">41.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.28%</td>
    <td style="white-space: nowrap; text-align: right">41.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.37 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">23.41 K</td>
    <td style="white-space: nowrap; text-align: right">42.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.69%</td>
    <td style="white-space: nowrap; text-align: right">39.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.49 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / verify signed</td>
    <td style="white-space: nowrap; text-align: right">21.68 K</td>
    <td style="white-space: nowrap; text-align: right">46.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.12%</td>
    <td style="white-space: nowrap; text-align: right">45.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap; text-align: right">19.99 K</td>
    <td style="white-space: nowrap; text-align: right">50.03 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.87%</td>
    <td style="white-space: nowrap; text-align: right">49.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">67.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.97 K</td>
    <td style="white-space: nowrap; text-align: right">50.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.00%</td>
    <td style="white-space: nowrap; text-align: right">50.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">63.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">18.88 K</td>
    <td style="white-space: nowrap; text-align: right">52.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.63%</td>
    <td style="white-space: nowrap; text-align: right">52.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / sign</td>
    <td style="white-space: nowrap; text-align: right">18.52 K</td>
    <td style="white-space: nowrap; text-align: right">54.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.62%</td>
    <td style="white-space: nowrap; text-align: right">53.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">67.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">17.94 K</td>
    <td style="white-space: nowrap; text-align: right">55.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.99%</td>
    <td style="white-space: nowrap; text-align: right">54.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">84 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">17.70 K</td>
    <td style="white-space: nowrap; text-align: right">56.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.19%</td>
    <td style="white-space: nowrap; text-align: right">55.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">92.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.55 K</td>
    <td style="white-space: nowrap; text-align: right">56.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.09%</td>
    <td style="white-space: nowrap; text-align: right">56.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">71.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">17.00 K</td>
    <td style="white-space: nowrap; text-align: right">58.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.28%</td>
    <td style="white-space: nowrap; text-align: right">57.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.12 K</td>
    <td style="white-space: nowrap; text-align: right">62.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.49%</td>
    <td style="white-space: nowrap; text-align: right">60.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap; text-align: right">14.86 K</td>
    <td style="white-space: nowrap; text-align: right">67.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.09%</td>
    <td style="white-space: nowrap; text-align: right">65.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">88.26 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.94 K</td>
    <td style="white-space: nowrap; text-align: right">71.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.66%</td>
    <td style="white-space: nowrap; text-align: right">71.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">90.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">13.11 K</td>
    <td style="white-space: nowrap; text-align: right">76.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.40%</td>
    <td style="white-space: nowrap; text-align: right">74.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">94.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">11.92 K</td>
    <td style="white-space: nowrap; text-align: right">83.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.34%</td>
    <td style="white-space: nowrap; text-align: right">83.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">107.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.92 K</td>
    <td style="white-space: nowrap; text-align: right">100.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.57%</td>
    <td style="white-space: nowrap; text-align: right">98.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">124.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.74 K</td>
    <td style="white-space: nowrap; text-align: right">102.68 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.34%</td>
    <td style="white-space: nowrap; text-align: right">102.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">125.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.80 K</td>
    <td style="white-space: nowrap; text-align: right">113.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.57%</td>
    <td style="white-space: nowrap; text-align: right">111.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">149.98 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.66 K</td>
    <td style="white-space: nowrap; text-align: right">176.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.55%</td>
    <td style="white-space: nowrap; text-align: right">173.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">248.93 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.36 K</td>
    <td style="white-space: nowrap; text-align: right">229.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.71%</td>
    <td style="white-space: nowrap; text-align: right">225.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">279.03 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap;text-align: right">4326.21 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4025.67 K</td>
    <td style="white-space: nowrap; text-align: right">1.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1481.04 K</td>
    <td style="white-space: nowrap; text-align: right">2.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / canonical bytes</td>
    <td style="white-space: nowrap; text-align: right">404.96 K</td>
    <td style="white-space: nowrap; text-align: right">10.68x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / digest</td>
    <td style="white-space: nowrap; text-align: right">368.24 K</td>
    <td style="white-space: nowrap; text-align: right">11.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">283.94 K</td>
    <td style="white-space: nowrap; text-align: right">15.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">255.02 K</td>
    <td style="white-space: nowrap; text-align: right">16.96x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">237.92 K</td>
    <td style="white-space: nowrap; text-align: right">18.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">235.54 K</td>
    <td style="white-space: nowrap; text-align: right">18.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">215.37 K</td>
    <td style="white-space: nowrap; text-align: right">20.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">159.61 K</td>
    <td style="white-space: nowrap; text-align: right">27.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">156.10 K</td>
    <td style="white-space: nowrap; text-align: right">27.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">112.29 K</td>
    <td style="white-space: nowrap; text-align: right">38.53x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">108.51 K</td>
    <td style="white-space: nowrap; text-align: right">39.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">106.60 K</td>
    <td style="white-space: nowrap; text-align: right">40.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">101.53 K</td>
    <td style="white-space: nowrap; text-align: right">42.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">97.86 K</td>
    <td style="white-space: nowrap; text-align: right">44.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">92.32 K</td>
    <td style="white-space: nowrap; text-align: right">46.86x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">90.82 K</td>
    <td style="white-space: nowrap; text-align: right">47.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">84.96 K</td>
    <td style="white-space: nowrap; text-align: right">50.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">84.84 K</td>
    <td style="white-space: nowrap; text-align: right">50.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">61.83 K</td>
    <td style="white-space: nowrap; text-align: right">69.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.37 K</td>
    <td style="white-space: nowrap; text-align: right">72.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">56.95 K</td>
    <td style="white-space: nowrap; text-align: right">75.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.75 K</td>
    <td style="white-space: nowrap; text-align: right">98.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.03 K</td>
    <td style="white-space: nowrap; text-align: right">105.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">35.60 K</td>
    <td style="white-space: nowrap; text-align: right">121.53x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">33.44 K</td>
    <td style="white-space: nowrap; text-align: right">129.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">31.17 K</td>
    <td style="white-space: nowrap; text-align: right">138.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.96 K</td>
    <td style="white-space: nowrap; text-align: right">154.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">27.25 K</td>
    <td style="white-space: nowrap; text-align: right">158.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.13 K</td>
    <td style="white-space: nowrap; text-align: right">179.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">23.41 K</td>
    <td style="white-space: nowrap; text-align: right">184.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / verify signed</td>
    <td style="white-space: nowrap; text-align: right">21.68 K</td>
    <td style="white-space: nowrap; text-align: right">199.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap; text-align: right">19.99 K</td>
    <td style="white-space: nowrap; text-align: right">216.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.97 K</td>
    <td style="white-space: nowrap; text-align: right">216.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">18.88 K</td>
    <td style="white-space: nowrap; text-align: right">229.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / sign</td>
    <td style="white-space: nowrap; text-align: right">18.52 K</td>
    <td style="white-space: nowrap; text-align: right">233.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">17.94 K</td>
    <td style="white-space: nowrap; text-align: right">241.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">17.70 K</td>
    <td style="white-space: nowrap; text-align: right">244.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.55 K</td>
    <td style="white-space: nowrap; text-align: right">246.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">17.00 K</td>
    <td style="white-space: nowrap; text-align: right">254.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.12 K</td>
    <td style="white-space: nowrap; text-align: right">268.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap; text-align: right">14.86 K</td>
    <td style="white-space: nowrap; text-align: right">291.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.94 K</td>
    <td style="white-space: nowrap; text-align: right">310.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">13.11 K</td>
    <td style="white-space: nowrap; text-align: right">330.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">11.92 K</td>
    <td style="white-space: nowrap; text-align: right">362.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.92 K</td>
    <td style="white-space: nowrap; text-align: right">436.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.74 K</td>
    <td style="white-space: nowrap; text-align: right">444.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.80 K</td>
    <td style="white-space: nowrap; text-align: right">491.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.66 K</td>
    <td style="white-space: nowrap; text-align: right">764.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.36 K</td>
    <td style="white-space: nowrap; text-align: right">992.9x</td>
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
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap">0.188 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap">0.0234 KB</td>
    <td>0.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap">1.34 KB</td>
    <td>7.17x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor receipt / canonical bytes</td>
    <td style="white-space: nowrap">6.16 KB</td>
    <td>32.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor receipt / digest</td>
    <td style="white-space: nowrap">6.31 KB</td>
    <td>33.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap">6.21 KB</td>
    <td>33.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap">8.79 KB</td>
    <td>46.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap">8.60 KB</td>
    <td>45.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap">11.32 KB</td>
    <td>60.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.20 KB</td>
    <td>22.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.83 KB</td>
    <td>41.75x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.49 KB</td>
    <td>29.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap">9.80 KB</td>
    <td>52.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap">17.97 KB</td>
    <td>95.83x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">8.34 KB</td>
    <td>44.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>147.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap">27.41 KB</td>
    <td>146.21x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.51 KB</td>
    <td>125.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">12.37 KB</td>
    <td>65.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap">11.45 KB</td>
    <td>61.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap">29.88 KB</td>
    <td>159.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">19.02 KB</td>
    <td>101.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.45 KB</td>
    <td>93.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap">13.82 KB</td>
    <td>73.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.34 KB</td>
    <td>385.79x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap">12.63 KB</td>
    <td>67.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">64.90 KB</td>
    <td>346.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">60 KB</td>
    <td>320.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap">58.14 KB</td>
    <td>310.08x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap">40.66 KB</td>
    <td>216.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap">41.02 KB</td>
    <td>218.79x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>10.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.69 KB</td>
    <td>190.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor receipt / verify signed</td>
    <td style="white-space: nowrap">19.67 KB</td>
    <td>104.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap">28.49 KB</td>
    <td>151.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.76 KB</td>
    <td>14.72x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap">16.21 KB</td>
    <td>86.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor receipt / sign</td>
    <td style="white-space: nowrap">13.19 KB</td>
    <td>70.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.57 KB</td>
    <td>179.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap">32.71 KB</td>
    <td>174.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>96.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap">76.01 KB</td>
    <td>405.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap">63.23 KB</td>
    <td>337.25x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap">50.38 KB</td>
    <td>268.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap">64.98 KB</td>
    <td>346.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap">57.09 KB</td>
    <td>304.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap">67.15 KB</td>
    <td>358.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.20 KB</td>
    <td>22.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap">99.51 KB</td>
    <td>530.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap">174.24 KB</td>
    <td>929.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap">722.73 KB</td>
    <td>3854.54x</td>
  </tr>
</table>