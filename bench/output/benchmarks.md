Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 22:21:01.414922Z
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
    <td style="white-space: nowrap; text-align: right">3971.66 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1631.33%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3622.06 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1153.25%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1331.75 K</td>
    <td style="white-space: nowrap; text-align: right">0.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;634.03%</td>
    <td style="white-space: nowrap; text-align: right">0.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">287.95 K</td>
    <td style="white-space: nowrap; text-align: right">3.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;107.53%</td>
    <td style="white-space: nowrap; text-align: right">3.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">218.70 K</td>
    <td style="white-space: nowrap; text-align: right">4.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;108.44%</td>
    <td style="white-space: nowrap; text-align: right">4.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">104.12 K</td>
    <td style="white-space: nowrap; text-align: right">9.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;67.07%</td>
    <td style="white-space: nowrap; text-align: right">8.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">100.32 K</td>
    <td style="white-space: nowrap; text-align: right">9.97 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;71.96%</td>
    <td style="white-space: nowrap; text-align: right">9.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">98.45 K</td>
    <td style="white-space: nowrap; text-align: right">10.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.12%</td>
    <td style="white-space: nowrap; text-align: right">9.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">92.14 K</td>
    <td style="white-space: nowrap; text-align: right">10.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.45%</td>
    <td style="white-space: nowrap; text-align: right">10.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">86.28 K</td>
    <td style="white-space: nowrap; text-align: right">11.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;46.06%</td>
    <td style="white-space: nowrap; text-align: right">10.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.91 K</td>
    <td style="white-space: nowrap; text-align: right">11.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;54.91%</td>
    <td style="white-space: nowrap; text-align: right">11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">83.49 K</td>
    <td style="white-space: nowrap; text-align: right">11.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.62%</td>
    <td style="white-space: nowrap; text-align: right">11.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">80.60 K</td>
    <td style="white-space: nowrap; text-align: right">12.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;47.24%</td>
    <td style="white-space: nowrap; text-align: right">11.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.61 K</td>
    <td style="white-space: nowrap; text-align: right">13.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.77%</td>
    <td style="white-space: nowrap; text-align: right">12.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">66.33 K</td>
    <td style="white-space: nowrap; text-align: right">15.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.12%</td>
    <td style="white-space: nowrap; text-align: right">14.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">59.93 K</td>
    <td style="white-space: nowrap; text-align: right">16.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.32%</td>
    <td style="white-space: nowrap; text-align: right">15.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">56.08 K</td>
    <td style="white-space: nowrap; text-align: right">17.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.29%</td>
    <td style="white-space: nowrap; text-align: right">16.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">52.07 K</td>
    <td style="white-space: nowrap; text-align: right">19.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.82%</td>
    <td style="white-space: nowrap; text-align: right">18.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">43.34 K</td>
    <td style="white-space: nowrap; text-align: right">23.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.74%</td>
    <td style="white-space: nowrap; text-align: right">21.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">42.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">39.99 K</td>
    <td style="white-space: nowrap; text-align: right">25.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.02%</td>
    <td style="white-space: nowrap; text-align: right">23.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">36.52 K</td>
    <td style="white-space: nowrap; text-align: right">27.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.63%</td>
    <td style="white-space: nowrap; text-align: right">26.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">27.22 K</td>
    <td style="white-space: nowrap; text-align: right">36.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.18%</td>
    <td style="white-space: nowrap; text-align: right">36.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">26.74 K</td>
    <td style="white-space: nowrap; text-align: right">37.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.72%</td>
    <td style="white-space: nowrap; text-align: right">36.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">24.06 K</td>
    <td style="white-space: nowrap; text-align: right">41.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.26%</td>
    <td style="white-space: nowrap; text-align: right">40.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">56.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">23.72 K</td>
    <td style="white-space: nowrap; text-align: right">42.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.16%</td>
    <td style="white-space: nowrap; text-align: right">38.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">79.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">23.03 K</td>
    <td style="white-space: nowrap; text-align: right">43.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.97%</td>
    <td style="white-space: nowrap; text-align: right">42.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">54.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">22.03 K</td>
    <td style="white-space: nowrap; text-align: right">45.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.24%</td>
    <td style="white-space: nowrap; text-align: right">41.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">93.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">18.88 K</td>
    <td style="white-space: nowrap; text-align: right">52.97 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.59%</td>
    <td style="white-space: nowrap; text-align: right">51.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.76 K</td>
    <td style="white-space: nowrap; text-align: right">53.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.13%</td>
    <td style="white-space: nowrap; text-align: right">52.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">67.10 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.39 K</td>
    <td style="white-space: nowrap; text-align: right">61.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.88%</td>
    <td style="white-space: nowrap; text-align: right">59.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">16.02 K</td>
    <td style="white-space: nowrap; text-align: right">62.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.50%</td>
    <td style="white-space: nowrap; text-align: right">60.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">78.40 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.14 K</td>
    <td style="white-space: nowrap; text-align: right">66.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.15%</td>
    <td style="white-space: nowrap; text-align: right">65.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">80.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.43 K</td>
    <td style="white-space: nowrap; text-align: right">74.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.15%</td>
    <td style="white-space: nowrap; text-align: right">73.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">90.09 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.17 K</td>
    <td style="white-space: nowrap; text-align: right">75.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.67%</td>
    <td style="white-space: nowrap; text-align: right">74.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">96.06 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">11.41 K</td>
    <td style="white-space: nowrap; text-align: right">87.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.60%</td>
    <td style="white-space: nowrap; text-align: right">86.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">106.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.95 K</td>
    <td style="white-space: nowrap; text-align: right">100.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.59%</td>
    <td style="white-space: nowrap; text-align: right">99.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">120.40 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.57 K</td>
    <td style="white-space: nowrap; text-align: right">116.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.46%</td>
    <td style="white-space: nowrap; text-align: right">115.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">141.14 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.45 K</td>
    <td style="white-space: nowrap; text-align: right">118.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.95%</td>
    <td style="white-space: nowrap; text-align: right">116.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">139.52 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.10 K</td>
    <td style="white-space: nowrap; text-align: right">123.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.02%</td>
    <td style="white-space: nowrap; text-align: right">122.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">144.59 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.81 K</td>
    <td style="white-space: nowrap; text-align: right">208.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.24%</td>
    <td style="white-space: nowrap; text-align: right">205.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">276.55 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.04 K</td>
    <td style="white-space: nowrap; text-align: right">247.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.23%</td>
    <td style="white-space: nowrap; text-align: right">244.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">293.00 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3971.66 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3622.06 K</td>
    <td style="white-space: nowrap; text-align: right">1.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1331.75 K</td>
    <td style="white-space: nowrap; text-align: right">2.98x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">287.95 K</td>
    <td style="white-space: nowrap; text-align: right">13.79x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">218.70 K</td>
    <td style="white-space: nowrap; text-align: right">18.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">104.12 K</td>
    <td style="white-space: nowrap; text-align: right">38.14x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">100.32 K</td>
    <td style="white-space: nowrap; text-align: right">39.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">98.45 K</td>
    <td style="white-space: nowrap; text-align: right">40.34x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">92.14 K</td>
    <td style="white-space: nowrap; text-align: right">43.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">86.28 K</td>
    <td style="white-space: nowrap; text-align: right">46.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.91 K</td>
    <td style="white-space: nowrap; text-align: right">46.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">83.49 K</td>
    <td style="white-space: nowrap; text-align: right">47.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">80.60 K</td>
    <td style="white-space: nowrap; text-align: right">49.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.61 K</td>
    <td style="white-space: nowrap; text-align: right">51.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">66.33 K</td>
    <td style="white-space: nowrap; text-align: right">59.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">59.93 K</td>
    <td style="white-space: nowrap; text-align: right">66.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">56.08 K</td>
    <td style="white-space: nowrap; text-align: right">70.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">52.07 K</td>
    <td style="white-space: nowrap; text-align: right">76.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">43.34 K</td>
    <td style="white-space: nowrap; text-align: right">91.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">39.99 K</td>
    <td style="white-space: nowrap; text-align: right">99.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">36.52 K</td>
    <td style="white-space: nowrap; text-align: right">108.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">27.22 K</td>
    <td style="white-space: nowrap; text-align: right">145.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">26.74 K</td>
    <td style="white-space: nowrap; text-align: right">148.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">24.06 K</td>
    <td style="white-space: nowrap; text-align: right">165.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">23.72 K</td>
    <td style="white-space: nowrap; text-align: right">167.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">23.03 K</td>
    <td style="white-space: nowrap; text-align: right">172.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">22.03 K</td>
    <td style="white-space: nowrap; text-align: right">180.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">18.88 K</td>
    <td style="white-space: nowrap; text-align: right">210.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.76 K</td>
    <td style="white-space: nowrap; text-align: right">211.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.39 K</td>
    <td style="white-space: nowrap; text-align: right">242.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">16.02 K</td>
    <td style="white-space: nowrap; text-align: right">247.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.14 K</td>
    <td style="white-space: nowrap; text-align: right">262.33x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.43 K</td>
    <td style="white-space: nowrap; text-align: right">295.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.17 K</td>
    <td style="white-space: nowrap; text-align: right">301.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">11.41 K</td>
    <td style="white-space: nowrap; text-align: right">348.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.95 K</td>
    <td style="white-space: nowrap; text-align: right">399.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.57 K</td>
    <td style="white-space: nowrap; text-align: right">463.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.45 K</td>
    <td style="white-space: nowrap; text-align: right">470.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.10 K</td>
    <td style="white-space: nowrap; text-align: right">490.55x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.81 K</td>
    <td style="white-space: nowrap; text-align: right">826.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.04 K</td>
    <td style="white-space: nowrap; text-align: right">983.11x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.79 KB</td>
    <td>30.88x</td>
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
    <td style="white-space: nowrap">2.74 KB</td>
    <td>14.63x</td>
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