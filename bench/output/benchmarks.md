Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-07-01 05:58:48.059932Z
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
    <td style="white-space: nowrap; text-align: right">4237.72 K</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1538.39%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3967.68 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1179.66%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1471.82 K</td>
    <td style="white-space: nowrap; text-align: right">0.68 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;591.97%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">314.76 K</td>
    <td style="white-space: nowrap; text-align: right">3.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;97.66%</td>
    <td style="white-space: nowrap; text-align: right">3.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">247.03 K</td>
    <td style="white-space: nowrap; text-align: right">4.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;108.01%</td>
    <td style="white-space: nowrap; text-align: right">3.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">113.71 K</td>
    <td style="white-space: nowrap; text-align: right">8.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;60.05%</td>
    <td style="white-space: nowrap; text-align: right">8.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.83 K</td>
    <td style="white-space: nowrap; text-align: right">9.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;68.37%</td>
    <td style="white-space: nowrap; text-align: right">8.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">109.82 K</td>
    <td style="white-space: nowrap; text-align: right">9.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.75%</td>
    <td style="white-space: nowrap; text-align: right">8.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">103.09 K</td>
    <td style="white-space: nowrap; text-align: right">9.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.63%</td>
    <td style="white-space: nowrap; text-align: right">9.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.12 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">93.76 K</td>
    <td style="white-space: nowrap; text-align: right">10.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;46.58%</td>
    <td style="white-space: nowrap; text-align: right">9.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">93.29 K</td>
    <td style="white-space: nowrap; text-align: right">10.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.02%</td>
    <td style="white-space: nowrap; text-align: right">10.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">93.28 K</td>
    <td style="white-space: nowrap; text-align: right">10.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.59%</td>
    <td style="white-space: nowrap; text-align: right">10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">87.60 K</td>
    <td style="white-space: nowrap; text-align: right">11.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.86%</td>
    <td style="white-space: nowrap; text-align: right">10.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">83.99 K</td>
    <td style="white-space: nowrap; text-align: right">11.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.98%</td>
    <td style="white-space: nowrap; text-align: right">11.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">72.21 K</td>
    <td style="white-space: nowrap; text-align: right">13.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.06%</td>
    <td style="white-space: nowrap; text-align: right">12.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">65.43 K</td>
    <td style="white-space: nowrap; text-align: right">15.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;33.30%</td>
    <td style="white-space: nowrap; text-align: right">14.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">61.15 K</td>
    <td style="white-space: nowrap; text-align: right">16.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.71%</td>
    <td style="white-space: nowrap; text-align: right">15.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">38.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">58.23 K</td>
    <td style="white-space: nowrap; text-align: right">17.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.67%</td>
    <td style="white-space: nowrap; text-align: right">16.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">48.31 K</td>
    <td style="white-space: nowrap; text-align: right">20.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.33%</td>
    <td style="white-space: nowrap; text-align: right">19.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">40.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">42.93 K</td>
    <td style="white-space: nowrap; text-align: right">23.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.28%</td>
    <td style="white-space: nowrap; text-align: right">22.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.02 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.15 K</td>
    <td style="white-space: nowrap; text-align: right">24.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.23%</td>
    <td style="white-space: nowrap; text-align: right">23.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.80 K</td>
    <td style="white-space: nowrap; text-align: right">32.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.39%</td>
    <td style="white-space: nowrap; text-align: right">32.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">29.55 K</td>
    <td style="white-space: nowrap; text-align: right">33.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;61.34%</td>
    <td style="white-space: nowrap; text-align: right">32.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">50.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.84 K</td>
    <td style="white-space: nowrap; text-align: right">37.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.15%</td>
    <td style="white-space: nowrap; text-align: right">33.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.80 K</td>
    <td style="white-space: nowrap; text-align: right">37.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.82%</td>
    <td style="white-space: nowrap; text-align: right">36.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">50.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.81 K</td>
    <td style="white-space: nowrap; text-align: right">38.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.51%</td>
    <td style="white-space: nowrap; text-align: right">34.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.44 K</td>
    <td style="white-space: nowrap; text-align: right">40.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.99%</td>
    <td style="white-space: nowrap; text-align: right">41.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.86 K</td>
    <td style="white-space: nowrap; text-align: right">47.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.76%</td>
    <td style="white-space: nowrap; text-align: right">46.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.04 K</td>
    <td style="white-space: nowrap; text-align: right">49.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.35%</td>
    <td style="white-space: nowrap; text-align: right">49.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">63.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.52 K</td>
    <td style="white-space: nowrap; text-align: right">57.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.09%</td>
    <td style="white-space: nowrap; text-align: right">57.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.11 K</td>
    <td style="white-space: nowrap; text-align: right">58.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.38%</td>
    <td style="white-space: nowrap; text-align: right">58.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.98 K</td>
    <td style="white-space: nowrap; text-align: right">62.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.33%</td>
    <td style="white-space: nowrap; text-align: right">62.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">76.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">15.68 K</td>
    <td style="white-space: nowrap; text-align: right">63.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.79%</td>
    <td style="white-space: nowrap; text-align: right">62.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">81.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.45 K</td>
    <td style="white-space: nowrap; text-align: right">69.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.98%</td>
    <td style="white-space: nowrap; text-align: right">69.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">84.26 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.06 K</td>
    <td style="white-space: nowrap; text-align: right">71.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.56%</td>
    <td style="white-space: nowrap; text-align: right">70.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">92.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.00 K</td>
    <td style="white-space: nowrap; text-align: right">71.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.59%</td>
    <td style="white-space: nowrap; text-align: right">70.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">95.20 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.22 K</td>
    <td style="white-space: nowrap; text-align: right">81.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.21%</td>
    <td style="white-space: nowrap; text-align: right">80.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">100 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.65 K</td>
    <td style="white-space: nowrap; text-align: right">93.87 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.75%</td>
    <td style="white-space: nowrap; text-align: right">92.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">116.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.81 K</td>
    <td style="white-space: nowrap; text-align: right">101.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.58%</td>
    <td style="white-space: nowrap; text-align: right">100.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">126.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.03 K</td>
    <td style="white-space: nowrap; text-align: right">110.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.68%</td>
    <td style="white-space: nowrap; text-align: right">110.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">131.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.79 K</td>
    <td style="white-space: nowrap; text-align: right">113.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.48%</td>
    <td style="white-space: nowrap; text-align: right">111.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">136.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.56 K</td>
    <td style="white-space: nowrap; text-align: right">179.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.97%</td>
    <td style="white-space: nowrap; text-align: right">176.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">251.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.25 K</td>
    <td style="white-space: nowrap; text-align: right">235.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.78%</td>
    <td style="white-space: nowrap; text-align: right">231.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">283.98 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4237.72 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3967.68 K</td>
    <td style="white-space: nowrap; text-align: right">1.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1471.82 K</td>
    <td style="white-space: nowrap; text-align: right">2.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">314.76 K</td>
    <td style="white-space: nowrap; text-align: right">13.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">247.03 K</td>
    <td style="white-space: nowrap; text-align: right">17.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">113.71 K</td>
    <td style="white-space: nowrap; text-align: right">37.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.83 K</td>
    <td style="white-space: nowrap; text-align: right">38.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">109.82 K</td>
    <td style="white-space: nowrap; text-align: right">38.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">103.09 K</td>
    <td style="white-space: nowrap; text-align: right">41.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">93.76 K</td>
    <td style="white-space: nowrap; text-align: right">45.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">93.29 K</td>
    <td style="white-space: nowrap; text-align: right">45.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">93.28 K</td>
    <td style="white-space: nowrap; text-align: right">45.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">87.60 K</td>
    <td style="white-space: nowrap; text-align: right">48.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">83.99 K</td>
    <td style="white-space: nowrap; text-align: right">50.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">72.21 K</td>
    <td style="white-space: nowrap; text-align: right">58.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">65.43 K</td>
    <td style="white-space: nowrap; text-align: right">64.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">61.15 K</td>
    <td style="white-space: nowrap; text-align: right">69.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">58.23 K</td>
    <td style="white-space: nowrap; text-align: right">72.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">48.31 K</td>
    <td style="white-space: nowrap; text-align: right">87.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">42.93 K</td>
    <td style="white-space: nowrap; text-align: right">98.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.15 K</td>
    <td style="white-space: nowrap; text-align: right">102.98x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.80 K</td>
    <td style="white-space: nowrap; text-align: right">137.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">29.55 K</td>
    <td style="white-space: nowrap; text-align: right">143.42x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.84 K</td>
    <td style="white-space: nowrap; text-align: right">157.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.80 K</td>
    <td style="white-space: nowrap; text-align: right">158.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.81 K</td>
    <td style="white-space: nowrap; text-align: right">164.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.44 K</td>
    <td style="white-space: nowrap; text-align: right">173.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.86 K</td>
    <td style="white-space: nowrap; text-align: right">203.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.04 K</td>
    <td style="white-space: nowrap; text-align: right">211.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.52 K</td>
    <td style="white-space: nowrap; text-align: right">241.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.11 K</td>
    <td style="white-space: nowrap; text-align: right">247.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.98 K</td>
    <td style="white-space: nowrap; text-align: right">265.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">15.68 K</td>
    <td style="white-space: nowrap; text-align: right">270.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.45 K</td>
    <td style="white-space: nowrap; text-align: right">293.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.06 K</td>
    <td style="white-space: nowrap; text-align: right">301.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.00 K</td>
    <td style="white-space: nowrap; text-align: right">302.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.22 K</td>
    <td style="white-space: nowrap; text-align: right">346.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.65 K</td>
    <td style="white-space: nowrap; text-align: right">397.79x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.81 K</td>
    <td style="white-space: nowrap; text-align: right">431.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.03 K</td>
    <td style="white-space: nowrap; text-align: right">469.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.79 K</td>
    <td style="white-space: nowrap; text-align: right">482.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.56 K</td>
    <td style="white-space: nowrap; text-align: right">761.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.25 K</td>
    <td style="white-space: nowrap; text-align: right">997.13x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.79 KB</td>
    <td>30.88x</td>
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
    <td style="white-space: nowrap">35.75 KB</td>
    <td>190.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.74 KB</td>
    <td>14.62x</td>
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
    <td style="white-space: nowrap">75.65 KB</td>
    <td>403.46x</td>
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
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap">35.01 KB</td>
    <td>186.71x</td>
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