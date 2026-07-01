Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-07-01 06:17:41.026794Z
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
    <td style="white-space: nowrap; text-align: right">4363.59 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1543.40%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4123.89 K</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1162.68%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1564.45 K</td>
    <td style="white-space: nowrap; text-align: right">0.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;615.06%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">322.95 K</td>
    <td style="white-space: nowrap; text-align: right">3.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;103.33%</td>
    <td style="white-space: nowrap; text-align: right">3 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">250.86 K</td>
    <td style="white-space: nowrap; text-align: right">3.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;109.42%</td>
    <td style="white-space: nowrap; text-align: right">3.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">115.76 K</td>
    <td style="white-space: nowrap; text-align: right">8.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.19%</td>
    <td style="white-space: nowrap; text-align: right">8.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">112.37 K</td>
    <td style="white-space: nowrap; text-align: right">8.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;66.31%</td>
    <td style="white-space: nowrap; text-align: right">8.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">109.65 K</td>
    <td style="white-space: nowrap; text-align: right">9.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;154.71%</td>
    <td style="white-space: nowrap; text-align: right">8.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">104.44 K</td>
    <td style="white-space: nowrap; text-align: right">9.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.67%</td>
    <td style="white-space: nowrap; text-align: right">9.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">96.60 K</td>
    <td style="white-space: nowrap; text-align: right">10.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;44.40%</td>
    <td style="white-space: nowrap; text-align: right">9.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.60 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">96.51 K</td>
    <td style="white-space: nowrap; text-align: right">10.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.05%</td>
    <td style="white-space: nowrap; text-align: right">9.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">95.25 K</td>
    <td style="white-space: nowrap; text-align: right">10.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.37%</td>
    <td style="white-space: nowrap; text-align: right">9.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">89.92 K</td>
    <td style="white-space: nowrap; text-align: right">11.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.74%</td>
    <td style="white-space: nowrap; text-align: right">10.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">85.55 K</td>
    <td style="white-space: nowrap; text-align: right">11.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.83%</td>
    <td style="white-space: nowrap; text-align: right">11.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">73.48 K</td>
    <td style="white-space: nowrap; text-align: right">13.61 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.23%</td>
    <td style="white-space: nowrap; text-align: right">12.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">66.40 K</td>
    <td style="white-space: nowrap; text-align: right">15.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.54%</td>
    <td style="white-space: nowrap; text-align: right">14.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">62.49 K</td>
    <td style="white-space: nowrap; text-align: right">16.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.28%</td>
    <td style="white-space: nowrap; text-align: right">15.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.17 K</td>
    <td style="white-space: nowrap; text-align: right">16.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.59%</td>
    <td style="white-space: nowrap; text-align: right">15.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">30.30 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">49.77 K</td>
    <td style="white-space: nowrap; text-align: right">20.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.95%</td>
    <td style="white-space: nowrap; text-align: right">18.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">38.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">44.72 K</td>
    <td style="white-space: nowrap; text-align: right">22.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.95%</td>
    <td style="white-space: nowrap; text-align: right">21.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.96 K</td>
    <td style="white-space: nowrap; text-align: right">23.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.91%</td>
    <td style="white-space: nowrap; text-align: right">23.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">31.14 K</td>
    <td style="white-space: nowrap; text-align: right">32.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.09%</td>
    <td style="white-space: nowrap; text-align: right">30.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">42.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">30.80 K</td>
    <td style="white-space: nowrap; text-align: right">32.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.09%</td>
    <td style="white-space: nowrap; text-align: right">31.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">28.46 K</td>
    <td style="white-space: nowrap; text-align: right">35.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.99%</td>
    <td style="white-space: nowrap; text-align: right">31.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">68.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">27.34 K</td>
    <td style="white-space: nowrap; text-align: right">36.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.18%</td>
    <td style="white-space: nowrap; text-align: right">34.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">48.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">27.17 K</td>
    <td style="white-space: nowrap; text-align: right">36.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.78%</td>
    <td style="white-space: nowrap; text-align: right">32.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">69.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.74 K</td>
    <td style="white-space: nowrap; text-align: right">40.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.60%</td>
    <td style="white-space: nowrap; text-align: right">40.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">51.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">21.41 K</td>
    <td style="white-space: nowrap; text-align: right">46.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.32%</td>
    <td style="white-space: nowrap; text-align: right">43.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.76 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.06 K</td>
    <td style="white-space: nowrap; text-align: right">49.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.18%</td>
    <td style="white-space: nowrap; text-align: right">50.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">61.37 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.72 K</td>
    <td style="white-space: nowrap; text-align: right">56.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.10%</td>
    <td style="white-space: nowrap; text-align: right">57.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">68.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.25 K</td>
    <td style="white-space: nowrap; text-align: right">57.97 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.71%</td>
    <td style="white-space: nowrap; text-align: right">58.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.28 K</td>
    <td style="white-space: nowrap; text-align: right">61.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.86%</td>
    <td style="white-space: nowrap; text-align: right">61.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">16.05 K</td>
    <td style="white-space: nowrap; text-align: right">62.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.15%</td>
    <td style="white-space: nowrap; text-align: right">61.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.57 K</td>
    <td style="white-space: nowrap; text-align: right">68.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.53%</td>
    <td style="white-space: nowrap; text-align: right">67.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">87.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.52 K</td>
    <td style="white-space: nowrap; text-align: right">68.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.47%</td>
    <td style="white-space: nowrap; text-align: right">67.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">92.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.49 K</td>
    <td style="white-space: nowrap; text-align: right">69.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.68%</td>
    <td style="white-space: nowrap; text-align: right">68.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">82.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.39 K</td>
    <td style="white-space: nowrap; text-align: right">80.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.79%</td>
    <td style="white-space: nowrap; text-align: right">79.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">96.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.95 K</td>
    <td style="white-space: nowrap; text-align: right">91.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.62%</td>
    <td style="white-space: nowrap; text-align: right">89.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">111.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.99 K</td>
    <td style="white-space: nowrap; text-align: right">100.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.52%</td>
    <td style="white-space: nowrap; text-align: right">98.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">120.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.37 K</td>
    <td style="white-space: nowrap; text-align: right">106.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.99%</td>
    <td style="white-space: nowrap; text-align: right">106.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">124.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.92 K</td>
    <td style="white-space: nowrap; text-align: right">112.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.90%</td>
    <td style="white-space: nowrap; text-align: right">109.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">131.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.76 K</td>
    <td style="white-space: nowrap; text-align: right">173.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.41%</td>
    <td style="white-space: nowrap; text-align: right">170.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">233.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.39 K</td>
    <td style="white-space: nowrap; text-align: right">227.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.43%</td>
    <td style="white-space: nowrap; text-align: right">222.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">276.69 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4363.59 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4123.89 K</td>
    <td style="white-space: nowrap; text-align: right">1.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1564.45 K</td>
    <td style="white-space: nowrap; text-align: right">2.79x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">322.95 K</td>
    <td style="white-space: nowrap; text-align: right">13.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">250.86 K</td>
    <td style="white-space: nowrap; text-align: right">17.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">115.76 K</td>
    <td style="white-space: nowrap; text-align: right">37.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">112.37 K</td>
    <td style="white-space: nowrap; text-align: right">38.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">109.65 K</td>
    <td style="white-space: nowrap; text-align: right">39.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">104.44 K</td>
    <td style="white-space: nowrap; text-align: right">41.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">96.60 K</td>
    <td style="white-space: nowrap; text-align: right">45.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">96.51 K</td>
    <td style="white-space: nowrap; text-align: right">45.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">95.25 K</td>
    <td style="white-space: nowrap; text-align: right">45.81x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">89.92 K</td>
    <td style="white-space: nowrap; text-align: right">48.53x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">85.55 K</td>
    <td style="white-space: nowrap; text-align: right">51.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">73.48 K</td>
    <td style="white-space: nowrap; text-align: right">59.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">66.40 K</td>
    <td style="white-space: nowrap; text-align: right">65.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">62.49 K</td>
    <td style="white-space: nowrap; text-align: right">69.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.17 K</td>
    <td style="white-space: nowrap; text-align: right">73.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">49.77 K</td>
    <td style="white-space: nowrap; text-align: right">87.68x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">44.72 K</td>
    <td style="white-space: nowrap; text-align: right">97.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.96 K</td>
    <td style="white-space: nowrap; text-align: right">103.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">31.14 K</td>
    <td style="white-space: nowrap; text-align: right">140.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">30.80 K</td>
    <td style="white-space: nowrap; text-align: right">141.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">28.46 K</td>
    <td style="white-space: nowrap; text-align: right">153.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">27.34 K</td>
    <td style="white-space: nowrap; text-align: right">159.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">27.17 K</td>
    <td style="white-space: nowrap; text-align: right">160.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.74 K</td>
    <td style="white-space: nowrap; text-align: right">176.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">21.41 K</td>
    <td style="white-space: nowrap; text-align: right">203.81x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.06 K</td>
    <td style="white-space: nowrap; text-align: right">217.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.72 K</td>
    <td style="white-space: nowrap; text-align: right">246.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.25 K</td>
    <td style="white-space: nowrap; text-align: right">252.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.28 K</td>
    <td style="white-space: nowrap; text-align: right">268.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">16.05 K</td>
    <td style="white-space: nowrap; text-align: right">271.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.57 K</td>
    <td style="white-space: nowrap; text-align: right">299.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.52 K</td>
    <td style="white-space: nowrap; text-align: right">300.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.49 K</td>
    <td style="white-space: nowrap; text-align: right">301.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.39 K</td>
    <td style="white-space: nowrap; text-align: right">352.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.95 K</td>
    <td style="white-space: nowrap; text-align: right">398.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.99 K</td>
    <td style="white-space: nowrap; text-align: right">436.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.37 K</td>
    <td style="white-space: nowrap; text-align: right">465.47x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.92 K</td>
    <td style="white-space: nowrap; text-align: right">489.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.76 K</td>
    <td style="white-space: nowrap; text-align: right">757.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.39 K</td>
    <td style="white-space: nowrap; text-align: right">993.07x</td>
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
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap">4.38 KB</td>
    <td>23.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap">11.18 KB</td>
    <td>59.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap">9.55 KB</td>
    <td>50.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.71 KB</td>
    <td>25.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap">27.41 KB</td>
    <td>146.21x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>147.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.79 KB</td>
    <td>30.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.77 KB</td>
    <td>41.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.32 KB</td>
    <td>124.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap">10.98 KB</td>
    <td>58.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap">29.76 KB</td>
    <td>158.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">8.34 KB</td>
    <td>44.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">12.18 KB</td>
    <td>64.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap">13.48 KB</td>
    <td>71.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.23 KB</td>
    <td>91.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">16.90 KB</td>
    <td>90.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>384.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap">10.88 KB</td>
    <td>58.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">51.73 KB</td>
    <td>275.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">68.59 KB</td>
    <td>365.79x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap">40.66 KB</td>
    <td>216.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap">55.74 KB</td>
    <td>297.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap">40.95 KB</td>
    <td>218.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>10.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.70 KB</td>
    <td>190.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.77 KB</td>
    <td>14.77x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>96.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap">15.27 KB</td>
    <td>81.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap">62.88 KB</td>
    <td>335.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap">75.55 KB</td>
    <td>402.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.29 KB</td>
    <td>177.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap">35.01 KB</td>
    <td>186.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap">63.34 KB</td>
    <td>337.83x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap">74.30 KB</td>
    <td>396.25x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap">68.34 KB</td>
    <td>364.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.62 KB</td>
    <td>24.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap">115.90 KB</td>
    <td>618.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap">171.92 KB</td>
    <td>916.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap">720.41 KB</td>
    <td>3842.17x</td>
  </tr>
</table>