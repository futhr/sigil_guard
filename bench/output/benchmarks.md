Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-07-01 05:35:24.539800Z
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
    <td style="white-space: nowrap; text-align: right">4252.03 K</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2050.50%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3878.90 K</td>
    <td style="white-space: nowrap; text-align: right">0.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1122.85%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1477.62 K</td>
    <td style="white-space: nowrap; text-align: right">0.68 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;607.47%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">303.60 K</td>
    <td style="white-space: nowrap; text-align: right">3.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;155.27%</td>
    <td style="white-space: nowrap; text-align: right">3.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">236.43 K</td>
    <td style="white-space: nowrap; text-align: right">4.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;107.27%</td>
    <td style="white-space: nowrap; text-align: right">3.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">110.02 K</td>
    <td style="white-space: nowrap; text-align: right">9.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;103.96%</td>
    <td style="white-space: nowrap; text-align: right">8.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">108.57 K</td>
    <td style="white-space: nowrap; text-align: right">9.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;75.06%</td>
    <td style="white-space: nowrap; text-align: right">8.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">105.62 K</td>
    <td style="white-space: nowrap; text-align: right">9.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.50%</td>
    <td style="white-space: nowrap; text-align: right">8.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">100.03 K</td>
    <td style="white-space: nowrap; text-align: right">10.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.19%</td>
    <td style="white-space: nowrap; text-align: right">9.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.87 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">95.91 K</td>
    <td style="white-space: nowrap; text-align: right">10.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;50.72%</td>
    <td style="white-space: nowrap; text-align: right">9.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">94.97 K</td>
    <td style="white-space: nowrap; text-align: right">10.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;50.33%</td>
    <td style="white-space: nowrap; text-align: right">9.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">89.53 K</td>
    <td style="white-space: nowrap; text-align: right">11.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.27%</td>
    <td style="white-space: nowrap; text-align: right">10.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">89.12 K</td>
    <td style="white-space: nowrap; text-align: right">11.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.08%</td>
    <td style="white-space: nowrap; text-align: right">10.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">73.46 K</td>
    <td style="white-space: nowrap; text-align: right">13.61 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.82%</td>
    <td style="white-space: nowrap; text-align: right">12.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">71.26 K</td>
    <td style="white-space: nowrap; text-align: right">14.03 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;284.00%</td>
    <td style="white-space: nowrap; text-align: right">12.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">65.50 K</td>
    <td style="white-space: nowrap; text-align: right">15.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;37.42%</td>
    <td style="white-space: nowrap; text-align: right">14.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">61.86 K</td>
    <td style="white-space: nowrap; text-align: right">16.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;32.94%</td>
    <td style="white-space: nowrap; text-align: right">14.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">31.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">56.15 K</td>
    <td style="white-space: nowrap; text-align: right">17.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.46%</td>
    <td style="white-space: nowrap; text-align: right">16.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">48.47 K</td>
    <td style="white-space: nowrap; text-align: right">20.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.60%</td>
    <td style="white-space: nowrap; text-align: right">19.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.55 K</td>
    <td style="white-space: nowrap; text-align: right">22.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.53%</td>
    <td style="white-space: nowrap; text-align: right">21.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">38.03 K</td>
    <td style="white-space: nowrap; text-align: right">26.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.81%</td>
    <td style="white-space: nowrap; text-align: right">24.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">30.04 K</td>
    <td style="white-space: nowrap; text-align: right">33.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.72%</td>
    <td style="white-space: nowrap; text-align: right">32.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">29.94 K</td>
    <td style="white-space: nowrap; text-align: right">33.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.86%</td>
    <td style="white-space: nowrap; text-align: right">32.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.96 K</td>
    <td style="white-space: nowrap; text-align: right">37.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.68%</td>
    <td style="white-space: nowrap; text-align: right">35.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">25.46 K</td>
    <td style="white-space: nowrap; text-align: right">39.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.74%</td>
    <td style="white-space: nowrap; text-align: right">36.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">81.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">25.04 K</td>
    <td style="white-space: nowrap; text-align: right">39.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.17%</td>
    <td style="white-space: nowrap; text-align: right">38.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">24.89 K</td>
    <td style="white-space: nowrap; text-align: right">40.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.29%</td>
    <td style="white-space: nowrap; text-align: right">37.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.37 K</td>
    <td style="white-space: nowrap; text-align: right">49.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.63%</td>
    <td style="white-space: nowrap; text-align: right">47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">71.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.14 K</td>
    <td style="white-space: nowrap; text-align: right">52.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.16%</td>
    <td style="white-space: nowrap; text-align: right">52.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.07 K</td>
    <td style="white-space: nowrap; text-align: right">58.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.86%</td>
    <td style="white-space: nowrap; text-align: right">57.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.45 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.45 K</td>
    <td style="white-space: nowrap; text-align: right">60.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.35%</td>
    <td style="white-space: nowrap; text-align: right">58.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">15.63 K</td>
    <td style="white-space: nowrap; text-align: right">64.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;51.94%</td>
    <td style="white-space: nowrap; text-align: right">61 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">179.80 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.45 K</td>
    <td style="white-space: nowrap; text-align: right">69.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.18%</td>
    <td style="white-space: nowrap; text-align: right">67.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">85.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.41 K</td>
    <td style="white-space: nowrap; text-align: right">69.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.51%</td>
    <td style="white-space: nowrap; text-align: right">67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">91.26 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">14.39 K</td>
    <td style="white-space: nowrap; text-align: right">69.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.58%</td>
    <td style="white-space: nowrap; text-align: right">68.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">98.61 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.49 K</td>
    <td style="white-space: nowrap; text-align: right">80.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.00%</td>
    <td style="white-space: nowrap; text-align: right">77.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">98.57 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.05 K</td>
    <td style="white-space: nowrap; text-align: right">99.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.09%</td>
    <td style="white-space: nowrap; text-align: right">97.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">129.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.34 K</td>
    <td style="white-space: nowrap; text-align: right">107.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.12%</td>
    <td style="white-space: nowrap; text-align: right">105.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">128.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.61 K</td>
    <td style="white-space: nowrap; text-align: right">116.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.83%</td>
    <td style="white-space: nowrap; text-align: right">112.87 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">165.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.35 K</td>
    <td style="white-space: nowrap; text-align: right">119.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.44%</td>
    <td style="white-space: nowrap; text-align: right">117.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">147.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.30 K</td>
    <td style="white-space: nowrap; text-align: right">188.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.58%</td>
    <td style="white-space: nowrap; text-align: right">184.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">245.82 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.49 K</td>
    <td style="white-space: nowrap; text-align: right">222.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.76%</td>
    <td style="white-space: nowrap; text-align: right">218.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">271.23 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4252.03 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3878.90 K</td>
    <td style="white-space: nowrap; text-align: right">1.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1477.62 K</td>
    <td style="white-space: nowrap; text-align: right">2.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">303.60 K</td>
    <td style="white-space: nowrap; text-align: right">14.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">236.43 K</td>
    <td style="white-space: nowrap; text-align: right">17.98x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">110.02 K</td>
    <td style="white-space: nowrap; text-align: right">38.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">108.57 K</td>
    <td style="white-space: nowrap; text-align: right">39.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">105.62 K</td>
    <td style="white-space: nowrap; text-align: right">40.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">100.03 K</td>
    <td style="white-space: nowrap; text-align: right">42.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">95.91 K</td>
    <td style="white-space: nowrap; text-align: right">44.33x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">94.97 K</td>
    <td style="white-space: nowrap; text-align: right">44.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">89.53 K</td>
    <td style="white-space: nowrap; text-align: right">47.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">89.12 K</td>
    <td style="white-space: nowrap; text-align: right">47.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">73.46 K</td>
    <td style="white-space: nowrap; text-align: right">57.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">71.26 K</td>
    <td style="white-space: nowrap; text-align: right">59.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">65.50 K</td>
    <td style="white-space: nowrap; text-align: right">64.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">61.86 K</td>
    <td style="white-space: nowrap; text-align: right">68.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">56.15 K</td>
    <td style="white-space: nowrap; text-align: right">75.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">48.47 K</td>
    <td style="white-space: nowrap; text-align: right">87.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.55 K</td>
    <td style="white-space: nowrap; text-align: right">97.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">38.03 K</td>
    <td style="white-space: nowrap; text-align: right">111.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">30.04 K</td>
    <td style="white-space: nowrap; text-align: right">141.53x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">29.94 K</td>
    <td style="white-space: nowrap; text-align: right">142.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.96 K</td>
    <td style="white-space: nowrap; text-align: right">157.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">25.46 K</td>
    <td style="white-space: nowrap; text-align: right">167.02x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">25.04 K</td>
    <td style="white-space: nowrap; text-align: right">169.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">24.89 K</td>
    <td style="white-space: nowrap; text-align: right">170.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.37 K</td>
    <td style="white-space: nowrap; text-align: right">208.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.14 K</td>
    <td style="white-space: nowrap; text-align: right">222.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.07 K</td>
    <td style="white-space: nowrap; text-align: right">249.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.45 K</td>
    <td style="white-space: nowrap; text-align: right">258.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">15.63 K</td>
    <td style="white-space: nowrap; text-align: right">272.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.45 K</td>
    <td style="white-space: nowrap; text-align: right">294.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.41 K</td>
    <td style="white-space: nowrap; text-align: right">295.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">14.39 K</td>
    <td style="white-space: nowrap; text-align: right">295.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.49 K</td>
    <td style="white-space: nowrap; text-align: right">340.33x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.05 K</td>
    <td style="white-space: nowrap; text-align: right">422.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.34 K</td>
    <td style="white-space: nowrap; text-align: right">455.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.61 K</td>
    <td style="white-space: nowrap; text-align: right">493.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.35 K</td>
    <td style="white-space: nowrap; text-align: right">509.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.30 K</td>
    <td style="white-space: nowrap; text-align: right">802.33x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.49 K</td>
    <td style="white-space: nowrap; text-align: right">946.04x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.71 KB</td>
    <td>25.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap">9.55 KB</td>
    <td>50.96x</td>
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
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">8.34 KB</td>
    <td>44.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap">29.76 KB</td>
    <td>158.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">12.02 KB</td>
    <td>64.08x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">68.59 KB</td>
    <td>365.79x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">51.73 KB</td>
    <td>275.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap">55.74 KB</td>
    <td>297.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap">40.66 KB</td>
    <td>216.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>10.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap">40.95 KB</td>
    <td>218.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.75 KB</td>
    <td>190.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.75 KB</td>
    <td>14.65x</td>
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
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>96.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.29 KB</td>
    <td>177.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap">75.65 KB</td>
    <td>403.46x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.62 KB</td>
    <td>24.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap">68.34 KB</td>
    <td>364.5x</td>
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