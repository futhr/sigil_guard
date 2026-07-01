Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-07-01 06:06:32.638691Z
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
    <td style="white-space: nowrap; text-align: right">4239.52 K</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1602.85%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3939.39 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1148.57%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1497.48 K</td>
    <td style="white-space: nowrap; text-align: right">0.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;636.08%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">300.33 K</td>
    <td style="white-space: nowrap; text-align: right">3.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;187.49%</td>
    <td style="white-space: nowrap; text-align: right">3.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">250.43 K</td>
    <td style="white-space: nowrap; text-align: right">3.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;107.50%</td>
    <td style="white-space: nowrap; text-align: right">3.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">113.46 K</td>
    <td style="white-space: nowrap; text-align: right">8.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;65.40%</td>
    <td style="white-space: nowrap; text-align: right">8.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">108.84 K</td>
    <td style="white-space: nowrap; text-align: right">9.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.99%</td>
    <td style="white-space: nowrap; text-align: right">8.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">108.42 K</td>
    <td style="white-space: nowrap; text-align: right">9.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;69.71%</td>
    <td style="white-space: nowrap; text-align: right">8.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">102.41 K</td>
    <td style="white-space: nowrap; text-align: right">9.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.03%</td>
    <td style="white-space: nowrap; text-align: right">9.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">93.99 K</td>
    <td style="white-space: nowrap; text-align: right">10.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.04%</td>
    <td style="white-space: nowrap; text-align: right">9.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">93.30 K</td>
    <td style="white-space: nowrap; text-align: right">10.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;46.79%</td>
    <td style="white-space: nowrap; text-align: right">10.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">92.47 K</td>
    <td style="white-space: nowrap; text-align: right">10.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;53.75%</td>
    <td style="white-space: nowrap; text-align: right">9.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">87.39 K</td>
    <td style="white-space: nowrap; text-align: right">11.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;42.38%</td>
    <td style="white-space: nowrap; text-align: right">10.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">84.16 K</td>
    <td style="white-space: nowrap; text-align: right">11.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.16%</td>
    <td style="white-space: nowrap; text-align: right">11.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">72.16 K</td>
    <td style="white-space: nowrap; text-align: right">13.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.99%</td>
    <td style="white-space: nowrap; text-align: right">12.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">63.85 K</td>
    <td style="white-space: nowrap; text-align: right">15.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;33.46%</td>
    <td style="white-space: nowrap; text-align: right">14.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">60.81 K</td>
    <td style="white-space: nowrap; text-align: right">16.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;32.98%</td>
    <td style="white-space: nowrap; text-align: right">15.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">38.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.68 K</td>
    <td style="white-space: nowrap; text-align: right">16.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.90%</td>
    <td style="white-space: nowrap; text-align: right">15.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">47.77 K</td>
    <td style="white-space: nowrap; text-align: right">20.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.97%</td>
    <td style="white-space: nowrap; text-align: right">19.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">44.33 K</td>
    <td style="white-space: nowrap; text-align: right">22.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.76%</td>
    <td style="white-space: nowrap; text-align: right">21.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">40.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.72 K</td>
    <td style="white-space: nowrap; text-align: right">23.97 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.70%</td>
    <td style="white-space: nowrap; text-align: right">23.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.71 K</td>
    <td style="white-space: nowrap; text-align: right">32.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.94%</td>
    <td style="white-space: nowrap; text-align: right">31.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">30.52 K</td>
    <td style="white-space: nowrap; text-align: right">32.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.91%</td>
    <td style="white-space: nowrap; text-align: right">32.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.88 K</td>
    <td style="white-space: nowrap; text-align: right">35.87 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.12%</td>
    <td style="white-space: nowrap; text-align: right">32.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">69.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.99 K</td>
    <td style="white-space: nowrap; text-align: right">37.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.37%</td>
    <td style="white-space: nowrap; text-align: right">34.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.79 K</td>
    <td style="white-space: nowrap; text-align: right">37.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.41%</td>
    <td style="white-space: nowrap; text-align: right">36.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">50.31 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.52 K</td>
    <td style="white-space: nowrap; text-align: right">40.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.06%</td>
    <td style="white-space: nowrap; text-align: right">40.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.60 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">21.05 K</td>
    <td style="white-space: nowrap; text-align: right">47.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.53%</td>
    <td style="white-space: nowrap; text-align: right">44.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">69.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.94 K</td>
    <td style="white-space: nowrap; text-align: right">50.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.25%</td>
    <td style="white-space: nowrap; text-align: right">50.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">64.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.39 K</td>
    <td style="white-space: nowrap; text-align: right">57.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.59%</td>
    <td style="white-space: nowrap; text-align: right">57.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.09 K</td>
    <td style="white-space: nowrap; text-align: right">58.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.55%</td>
    <td style="white-space: nowrap; text-align: right">59.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.21 K</td>
    <td style="white-space: nowrap; text-align: right">61.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.18%</td>
    <td style="white-space: nowrap; text-align: right">61.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">15.67 K</td>
    <td style="white-space: nowrap; text-align: right">63.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.75%</td>
    <td style="white-space: nowrap; text-align: right">63.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">81.37 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.35 K</td>
    <td style="white-space: nowrap; text-align: right">69.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.79%</td>
    <td style="white-space: nowrap; text-align: right">69.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">85.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.21 K</td>
    <td style="white-space: nowrap; text-align: right">70.39 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.51%</td>
    <td style="white-space: nowrap; text-align: right">69.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">90.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.06 K</td>
    <td style="white-space: nowrap; text-align: right">71.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.54%</td>
    <td style="white-space: nowrap; text-align: right">70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">94.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.13 K</td>
    <td style="white-space: nowrap; text-align: right">82.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.76%</td>
    <td style="white-space: nowrap; text-align: right">81.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">101.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.73 K</td>
    <td style="white-space: nowrap; text-align: right">93.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.43%</td>
    <td style="white-space: nowrap; text-align: right">91.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">113.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.90 K</td>
    <td style="white-space: nowrap; text-align: right">100.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.59%</td>
    <td style="white-space: nowrap; text-align: right">99.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">123.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.07 K</td>
    <td style="white-space: nowrap; text-align: right">110.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.00%</td>
    <td style="white-space: nowrap; text-align: right">110.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">132.12 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.82 K</td>
    <td style="white-space: nowrap; text-align: right">113.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.41%</td>
    <td style="white-space: nowrap; text-align: right">110.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">137.95 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.73 K</td>
    <td style="white-space: nowrap; text-align: right">174.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.62%</td>
    <td style="white-space: nowrap; text-align: right">171.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">235.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.30 K</td>
    <td style="white-space: nowrap; text-align: right">232.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.83%</td>
    <td style="white-space: nowrap; text-align: right">226.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">294.67 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4239.52 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3939.39 K</td>
    <td style="white-space: nowrap; text-align: right">1.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1497.48 K</td>
    <td style="white-space: nowrap; text-align: right">2.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">300.33 K</td>
    <td style="white-space: nowrap; text-align: right">14.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">250.43 K</td>
    <td style="white-space: nowrap; text-align: right">16.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">113.46 K</td>
    <td style="white-space: nowrap; text-align: right">37.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">108.84 K</td>
    <td style="white-space: nowrap; text-align: right">38.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">108.42 K</td>
    <td style="white-space: nowrap; text-align: right">39.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">102.41 K</td>
    <td style="white-space: nowrap; text-align: right">41.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">93.99 K</td>
    <td style="white-space: nowrap; text-align: right">45.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">93.30 K</td>
    <td style="white-space: nowrap; text-align: right">45.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">92.47 K</td>
    <td style="white-space: nowrap; text-align: right">45.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">87.39 K</td>
    <td style="white-space: nowrap; text-align: right">48.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">84.16 K</td>
    <td style="white-space: nowrap; text-align: right">50.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">72.16 K</td>
    <td style="white-space: nowrap; text-align: right">58.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">63.85 K</td>
    <td style="white-space: nowrap; text-align: right">66.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">60.81 K</td>
    <td style="white-space: nowrap; text-align: right">69.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.68 K</td>
    <td style="white-space: nowrap; text-align: right">71.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">47.77 K</td>
    <td style="white-space: nowrap; text-align: right">88.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">44.33 K</td>
    <td style="white-space: nowrap; text-align: right">95.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">41.72 K</td>
    <td style="white-space: nowrap; text-align: right">101.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.71 K</td>
    <td style="white-space: nowrap; text-align: right">138.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">30.52 K</td>
    <td style="white-space: nowrap; text-align: right">138.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.88 K</td>
    <td style="white-space: nowrap; text-align: right">152.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.99 K</td>
    <td style="white-space: nowrap; text-align: right">157.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.79 K</td>
    <td style="white-space: nowrap; text-align: right">158.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.52 K</td>
    <td style="white-space: nowrap; text-align: right">172.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">21.05 K</td>
    <td style="white-space: nowrap; text-align: right">201.42x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.94 K</td>
    <td style="white-space: nowrap; text-align: right">212.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.39 K</td>
    <td style="white-space: nowrap; text-align: right">243.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.09 K</td>
    <td style="white-space: nowrap; text-align: right">248.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.21 K</td>
    <td style="white-space: nowrap; text-align: right">261.47x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">15.67 K</td>
    <td style="white-space: nowrap; text-align: right">270.53x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.35 K</td>
    <td style="white-space: nowrap; text-align: right">295.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.21 K</td>
    <td style="white-space: nowrap; text-align: right">298.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.06 K</td>
    <td style="white-space: nowrap; text-align: right">301.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.13 K</td>
    <td style="white-space: nowrap; text-align: right">349.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.73 K</td>
    <td style="white-space: nowrap; text-align: right">395.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.90 K</td>
    <td style="white-space: nowrap; text-align: right">428.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.07 K</td>
    <td style="white-space: nowrap; text-align: right">467.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.82 K</td>
    <td style="white-space: nowrap; text-align: right">480.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.73 K</td>
    <td style="white-space: nowrap; text-align: right">740.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.30 K</td>
    <td style="white-space: nowrap; text-align: right">985.26x</td>
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
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap">27.41 KB</td>
    <td>146.21x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.71 KB</td>
    <td>25.13x</td>
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
    <td style="white-space: nowrap">5.79 KB</td>
    <td>30.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.77 KB</td>
    <td>41.42x</td>
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
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap">40.95 KB</td>
    <td>218.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap">55.74 KB</td>
    <td>297.29x</td>
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