Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 21:33:47.230027Z
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
    <td style="white-space: nowrap; text-align: right">3895.22 K</td>
    <td style="white-space: nowrap; text-align: right">0.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1605.87%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3520.17 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1116.13%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1384.45 K</td>
    <td style="white-space: nowrap; text-align: right">0.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;641.39%</td>
    <td style="white-space: nowrap; text-align: right">0.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">281.85 K</td>
    <td style="white-space: nowrap; text-align: right">3.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;114.95%</td>
    <td style="white-space: nowrap; text-align: right">3.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">227.03 K</td>
    <td style="white-space: nowrap; text-align: right">4.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;115.12%</td>
    <td style="white-space: nowrap; text-align: right">4.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">105.99 K</td>
    <td style="white-space: nowrap; text-align: right">9.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;63.64%</td>
    <td style="white-space: nowrap; text-align: right">8.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">100.55 K</td>
    <td style="white-space: nowrap; text-align: right">9.95 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;66.76%</td>
    <td style="white-space: nowrap; text-align: right">9.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">99.10 K</td>
    <td style="white-space: nowrap; text-align: right">10.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.50%</td>
    <td style="white-space: nowrap; text-align: right">9.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.39 K</td>
    <td style="white-space: nowrap; text-align: right">10.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.74%</td>
    <td style="white-space: nowrap; text-align: right">10.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">87.34 K</td>
    <td style="white-space: nowrap; text-align: right">11.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;37.86%</td>
    <td style="white-space: nowrap; text-align: right">10.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">86.55 K</td>
    <td style="white-space: nowrap; text-align: right">11.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.53%</td>
    <td style="white-space: nowrap; text-align: right">10.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">86.15 K</td>
    <td style="white-space: nowrap; text-align: right">11.61 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;49.54%</td>
    <td style="white-space: nowrap; text-align: right">10.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">82.80 K</td>
    <td style="white-space: nowrap; text-align: right">12.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.25%</td>
    <td style="white-space: nowrap; text-align: right">11.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">78.32 K</td>
    <td style="white-space: nowrap; text-align: right">12.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.83%</td>
    <td style="white-space: nowrap; text-align: right">12.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">66.44 K</td>
    <td style="white-space: nowrap; text-align: right">15.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.01%</td>
    <td style="white-space: nowrap; text-align: right">14.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">60.11 K</td>
    <td style="white-space: nowrap; text-align: right">16.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;32.27%</td>
    <td style="white-space: nowrap; text-align: right">15.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">38.56 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">58.24 K</td>
    <td style="white-space: nowrap; text-align: right">17.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.88%</td>
    <td style="white-space: nowrap; text-align: right">16.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">37.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">54.79 K</td>
    <td style="white-space: nowrap; text-align: right">18.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.67%</td>
    <td style="white-space: nowrap; text-align: right">17.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.41 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.34 K</td>
    <td style="white-space: nowrap; text-align: right">22.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.38%</td>
    <td style="white-space: nowrap; text-align: right">21.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.46 K</td>
    <td style="white-space: nowrap; text-align: right">24.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.85%</td>
    <td style="white-space: nowrap; text-align: right">23.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.17 K</td>
    <td style="white-space: nowrap; text-align: right">26.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.96%</td>
    <td style="white-space: nowrap; text-align: right">26.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">28.00 K</td>
    <td style="white-space: nowrap; text-align: right">35.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.41%</td>
    <td style="white-space: nowrap; text-align: right">35.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.61 K</td>
    <td style="white-space: nowrap; text-align: right">36.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.65%</td>
    <td style="white-space: nowrap; text-align: right">35.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.27 K</td>
    <td style="white-space: nowrap; text-align: right">38.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.42%</td>
    <td style="white-space: nowrap; text-align: right">33.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.06 K</td>
    <td style="white-space: nowrap; text-align: right">39.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.69%</td>
    <td style="white-space: nowrap; text-align: right">35.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.84 K</td>
    <td style="white-space: nowrap; text-align: right">43.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.34%</td>
    <td style="white-space: nowrap; text-align: right">42.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">56.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.30 K</td>
    <td style="white-space: nowrap; text-align: right">51.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.81%</td>
    <td style="white-space: nowrap; text-align: right">49.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.77 K</td>
    <td style="white-space: nowrap; text-align: right">53.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.94%</td>
    <td style="white-space: nowrap; text-align: right">52.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">69.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.54 K</td>
    <td style="white-space: nowrap; text-align: right">60.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.26%</td>
    <td style="white-space: nowrap; text-align: right">59.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.10 K</td>
    <td style="white-space: nowrap; text-align: right">66.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.82%</td>
    <td style="white-space: nowrap; text-align: right">64.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">82.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">13.68 K</td>
    <td style="white-space: nowrap; text-align: right">73.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.26%</td>
    <td style="white-space: nowrap; text-align: right">71.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">91.07 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.43 K</td>
    <td style="white-space: nowrap; text-align: right">74.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.32%</td>
    <td style="white-space: nowrap; text-align: right">73.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">91.01 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.04 K</td>
    <td style="white-space: nowrap; text-align: right">76.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.28%</td>
    <td style="white-space: nowrap; text-align: right">75.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">97.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.05 K</td>
    <td style="white-space: nowrap; text-align: right">99.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.75%</td>
    <td style="white-space: nowrap; text-align: right">97.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">120.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.21 K</td>
    <td style="white-space: nowrap; text-align: right">108.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.51%</td>
    <td style="white-space: nowrap; text-align: right">107.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">132.10 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.66 K</td>
    <td style="white-space: nowrap; text-align: right">115.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.83%</td>
    <td style="white-space: nowrap; text-align: right">113.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">137.94 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.22 K</td>
    <td style="white-space: nowrap; text-align: right">121.62 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.07%</td>
    <td style="white-space: nowrap; text-align: right">119.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">144.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.19 K</td>
    <td style="white-space: nowrap; text-align: right">192.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.88%</td>
    <td style="white-space: nowrap; text-align: right">189.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">273.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.04 K</td>
    <td style="white-space: nowrap; text-align: right">247.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.52%</td>
    <td style="white-space: nowrap; text-align: right">244.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">296.56 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3895.22 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3520.17 K</td>
    <td style="white-space: nowrap; text-align: right">1.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1384.45 K</td>
    <td style="white-space: nowrap; text-align: right">2.81x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">281.85 K</td>
    <td style="white-space: nowrap; text-align: right">13.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">227.03 K</td>
    <td style="white-space: nowrap; text-align: right">17.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">105.99 K</td>
    <td style="white-space: nowrap; text-align: right">36.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">100.55 K</td>
    <td style="white-space: nowrap; text-align: right">38.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">99.10 K</td>
    <td style="white-space: nowrap; text-align: right">39.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.39 K</td>
    <td style="white-space: nowrap; text-align: right">41.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">87.34 K</td>
    <td style="white-space: nowrap; text-align: right">44.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">86.55 K</td>
    <td style="white-space: nowrap; text-align: right">45.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">86.15 K</td>
    <td style="white-space: nowrap; text-align: right">45.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">82.80 K</td>
    <td style="white-space: nowrap; text-align: right">47.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">78.32 K</td>
    <td style="white-space: nowrap; text-align: right">49.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">66.44 K</td>
    <td style="white-space: nowrap; text-align: right">58.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">60.11 K</td>
    <td style="white-space: nowrap; text-align: right">64.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">58.24 K</td>
    <td style="white-space: nowrap; text-align: right">66.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">54.79 K</td>
    <td style="white-space: nowrap; text-align: right">71.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.34 K</td>
    <td style="white-space: nowrap; text-align: right">87.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.46 K</td>
    <td style="white-space: nowrap; text-align: right">96.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.17 K</td>
    <td style="white-space: nowrap; text-align: right">104.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">28.00 K</td>
    <td style="white-space: nowrap; text-align: right">139.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.61 K</td>
    <td style="white-space: nowrap; text-align: right">141.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.27 K</td>
    <td style="white-space: nowrap; text-align: right">148.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.06 K</td>
    <td style="white-space: nowrap; text-align: right">155.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.84 K</td>
    <td style="white-space: nowrap; text-align: right">170.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.30 K</td>
    <td style="white-space: nowrap; text-align: right">201.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.77 K</td>
    <td style="white-space: nowrap; text-align: right">207.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.54 K</td>
    <td style="white-space: nowrap; text-align: right">235.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.10 K</td>
    <td style="white-space: nowrap; text-align: right">258.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">13.68 K</td>
    <td style="white-space: nowrap; text-align: right">284.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.43 K</td>
    <td style="white-space: nowrap; text-align: right">290.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.04 K</td>
    <td style="white-space: nowrap; text-align: right">298.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.05 K</td>
    <td style="white-space: nowrap; text-align: right">387.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.21 K</td>
    <td style="white-space: nowrap; text-align: right">422.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.66 K</td>
    <td style="white-space: nowrap; text-align: right">449.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.22 K</td>
    <td style="white-space: nowrap; text-align: right">473.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.19 K</td>
    <td style="white-space: nowrap; text-align: right">751.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.04 K</td>
    <td style="white-space: nowrap; text-align: right">964.45x</td>
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
    <td>14.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>96.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap">62.88 KB</td>
    <td>335.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap">15.74 KB</td>
    <td>83.96x</td>
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