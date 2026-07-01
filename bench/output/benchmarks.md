Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-07-01 06:35:12.667654Z
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
    <td style="white-space: nowrap; text-align: right">4348.93 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2064.23%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4037.08 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1075.35%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1588.99 K</td>
    <td style="white-space: nowrap; text-align: right">0.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;642.48%</td>
    <td style="white-space: nowrap; text-align: right">0.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">322.14 K</td>
    <td style="white-space: nowrap; text-align: right">3.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;155.96%</td>
    <td style="white-space: nowrap; text-align: right">3 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">253.84 K</td>
    <td style="white-space: nowrap; text-align: right">3.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;110.78%</td>
    <td style="white-space: nowrap; text-align: right">3.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">6.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">114.64 K</td>
    <td style="white-space: nowrap; text-align: right">8.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;59.20%</td>
    <td style="white-space: nowrap; text-align: right">8.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">110.88 K</td>
    <td style="white-space: nowrap; text-align: right">9.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;69.19%</td>
    <td style="white-space: nowrap; text-align: right">8.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">108.97 K</td>
    <td style="white-space: nowrap; text-align: right">9.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.04%</td>
    <td style="white-space: nowrap; text-align: right">8.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">104.84 K</td>
    <td style="white-space: nowrap; text-align: right">9.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;38.90%</td>
    <td style="white-space: nowrap; text-align: right">9.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">96.08 K</td>
    <td style="white-space: nowrap; text-align: right">10.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.37%</td>
    <td style="white-space: nowrap; text-align: right">9.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">94.10 K</td>
    <td style="white-space: nowrap; text-align: right">10.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.29%</td>
    <td style="white-space: nowrap; text-align: right">10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">93.80 K</td>
    <td style="white-space: nowrap; text-align: right">10.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.94%</td>
    <td style="white-space: nowrap; text-align: right">9.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">88.73 K</td>
    <td style="white-space: nowrap; text-align: right">11.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.70%</td>
    <td style="white-space: nowrap; text-align: right">10.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">84.89 K</td>
    <td style="white-space: nowrap; text-align: right">11.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.93%</td>
    <td style="white-space: nowrap; text-align: right">11.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.87 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">73.25 K</td>
    <td style="white-space: nowrap; text-align: right">13.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.73%</td>
    <td style="white-space: nowrap; text-align: right">12.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">65.38 K</td>
    <td style="white-space: nowrap; text-align: right">15.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.56%</td>
    <td style="white-space: nowrap; text-align: right">14.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">63.96 K</td>
    <td style="white-space: nowrap; text-align: right">15.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.81%</td>
    <td style="white-space: nowrap; text-align: right">14.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">61.17 K</td>
    <td style="white-space: nowrap; text-align: right">16.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.24%</td>
    <td style="white-space: nowrap; text-align: right">15.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">48.41 K</td>
    <td style="white-space: nowrap; text-align: right">20.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.98%</td>
    <td style="white-space: nowrap; text-align: right">19.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">44.56 K</td>
    <td style="white-space: nowrap; text-align: right">22.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.71%</td>
    <td style="white-space: nowrap; text-align: right">21.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.03 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.47 K</td>
    <td style="white-space: nowrap; text-align: right">24.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.61%</td>
    <td style="white-space: nowrap; text-align: right">23.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.10 K</td>
    <td style="white-space: nowrap; text-align: right">33.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.17%</td>
    <td style="white-space: nowrap; text-align: right">32.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">46.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">29.93 K</td>
    <td style="white-space: nowrap; text-align: right">33.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.89%</td>
    <td style="white-space: nowrap; text-align: right">32.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">28.24 K</td>
    <td style="white-space: nowrap; text-align: right">35.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.10%</td>
    <td style="white-space: nowrap; text-align: right">32.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">27.27 K</td>
    <td style="white-space: nowrap; text-align: right">36.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.79%</td>
    <td style="white-space: nowrap; text-align: right">35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.83 K</td>
    <td style="white-space: nowrap; text-align: right">37.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.22%</td>
    <td style="white-space: nowrap; text-align: right">33.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.72 K</td>
    <td style="white-space: nowrap; text-align: right">40.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.81%</td>
    <td style="white-space: nowrap; text-align: right">40.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">51.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.37 K</td>
    <td style="white-space: nowrap; text-align: right">49.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.58%</td>
    <td style="white-space: nowrap; text-align: right">49.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">61.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.21 K</td>
    <td style="white-space: nowrap; text-align: right">49.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.42%</td>
    <td style="white-space: nowrap; text-align: right">47.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.67 K</td>
    <td style="white-space: nowrap; text-align: right">56.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.19%</td>
    <td style="white-space: nowrap; text-align: right">56.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">68.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.29 K</td>
    <td style="white-space: nowrap; text-align: right">57.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.89%</td>
    <td style="white-space: nowrap; text-align: right">57.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.23 K</td>
    <td style="white-space: nowrap; text-align: right">61.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.19%</td>
    <td style="white-space: nowrap; text-align: right">61.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">15.98 K</td>
    <td style="white-space: nowrap; text-align: right">62.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.29%</td>
    <td style="white-space: nowrap; text-align: right">61.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">78.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.57 K</td>
    <td style="white-space: nowrap; text-align: right">68.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.89%</td>
    <td style="white-space: nowrap; text-align: right">67.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">82.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.22 K</td>
    <td style="white-space: nowrap; text-align: right">70.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.69%</td>
    <td style="white-space: nowrap; text-align: right">69.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">90.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.20 K</td>
    <td style="white-space: nowrap; text-align: right">70.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.69%</td>
    <td style="white-space: nowrap; text-align: right">69.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">88.74 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.30 K</td>
    <td style="white-space: nowrap; text-align: right">81.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.16%</td>
    <td style="white-space: nowrap; text-align: right">80.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">97.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">11.01 K</td>
    <td style="white-space: nowrap; text-align: right">90.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.87%</td>
    <td style="white-space: nowrap; text-align: right">89.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">111.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">10.07 K</td>
    <td style="white-space: nowrap; text-align: right">99.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.78%</td>
    <td style="white-space: nowrap; text-align: right">97.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">120.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.37 K</td>
    <td style="white-space: nowrap; text-align: right">106.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.17%</td>
    <td style="white-space: nowrap; text-align: right">105.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">125.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.04 K</td>
    <td style="white-space: nowrap; text-align: right">110.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.25%</td>
    <td style="white-space: nowrap; text-align: right">107.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">131.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.67 K</td>
    <td style="white-space: nowrap; text-align: right">176.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.16%</td>
    <td style="white-space: nowrap; text-align: right">171.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">248.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.38 K</td>
    <td style="white-space: nowrap; text-align: right">228.39 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.64%</td>
    <td style="white-space: nowrap; text-align: right">223.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">288.27 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4348.93 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4037.08 K</td>
    <td style="white-space: nowrap; text-align: right">1.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1588.99 K</td>
    <td style="white-space: nowrap; text-align: right">2.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">322.14 K</td>
    <td style="white-space: nowrap; text-align: right">13.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">253.84 K</td>
    <td style="white-space: nowrap; text-align: right">17.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">114.64 K</td>
    <td style="white-space: nowrap; text-align: right">37.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">110.88 K</td>
    <td style="white-space: nowrap; text-align: right">39.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">108.97 K</td>
    <td style="white-space: nowrap; text-align: right">39.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">104.84 K</td>
    <td style="white-space: nowrap; text-align: right">41.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">96.08 K</td>
    <td style="white-space: nowrap; text-align: right">45.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">94.10 K</td>
    <td style="white-space: nowrap; text-align: right">46.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">93.80 K</td>
    <td style="white-space: nowrap; text-align: right">46.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">88.73 K</td>
    <td style="white-space: nowrap; text-align: right">49.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">84.89 K</td>
    <td style="white-space: nowrap; text-align: right">51.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">73.25 K</td>
    <td style="white-space: nowrap; text-align: right">59.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">65.38 K</td>
    <td style="white-space: nowrap; text-align: right">66.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">63.96 K</td>
    <td style="white-space: nowrap; text-align: right">68.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">61.17 K</td>
    <td style="white-space: nowrap; text-align: right">71.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">48.41 K</td>
    <td style="white-space: nowrap; text-align: right">89.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">44.56 K</td>
    <td style="white-space: nowrap; text-align: right">97.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.47 K</td>
    <td style="white-space: nowrap; text-align: right">104.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.10 K</td>
    <td style="white-space: nowrap; text-align: right">144.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">29.93 K</td>
    <td style="white-space: nowrap; text-align: right">145.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">28.24 K</td>
    <td style="white-space: nowrap; text-align: right">153.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">27.27 K</td>
    <td style="white-space: nowrap; text-align: right">159.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.83 K</td>
    <td style="white-space: nowrap; text-align: right">162.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.72 K</td>
    <td style="white-space: nowrap; text-align: right">175.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.37 K</td>
    <td style="white-space: nowrap; text-align: right">213.47x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.21 K</td>
    <td style="white-space: nowrap; text-align: right">215.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.67 K</td>
    <td style="white-space: nowrap; text-align: right">246.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.29 K</td>
    <td style="white-space: nowrap; text-align: right">251.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.23 K</td>
    <td style="white-space: nowrap; text-align: right">268.02x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">15.98 K</td>
    <td style="white-space: nowrap; text-align: right">272.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.57 K</td>
    <td style="white-space: nowrap; text-align: right">298.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.22 K</td>
    <td style="white-space: nowrap; text-align: right">305.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.20 K</td>
    <td style="white-space: nowrap; text-align: right">306.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.30 K</td>
    <td style="white-space: nowrap; text-align: right">353.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">11.01 K</td>
    <td style="white-space: nowrap; text-align: right">394.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">10.07 K</td>
    <td style="white-space: nowrap; text-align: right">431.81x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.37 K</td>
    <td style="white-space: nowrap; text-align: right">464.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.04 K</td>
    <td style="white-space: nowrap; text-align: right">480.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.67 K</td>
    <td style="white-space: nowrap; text-align: right">766.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.38 K</td>
    <td style="white-space: nowrap; text-align: right">993.25x</td>
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
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.32 KB</td>
    <td>124.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.91 KB</td>
    <td>31.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.95 KB</td>
    <td>42.38x</td>
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
    <td style="white-space: nowrap">12.32 KB</td>
    <td>65.71x</td>
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
    <td style="white-space: nowrap">16.97 KB</td>
    <td>90.5x</td>
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
    <td style="white-space: nowrap">51.87 KB</td>
    <td>276.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">69.45 KB</td>
    <td>370.42x</td>
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
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.77 KB</td>
    <td>14.77x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.70 KB</td>
    <td>190.42x</td>
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
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.76 KB</td>
    <td>180.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap">35.06 KB</td>
    <td>187.0x</td>
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