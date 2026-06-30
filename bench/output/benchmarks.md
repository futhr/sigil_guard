Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 18:42:14.684370Z
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
    <td style="white-space: nowrap; text-align: right">3610.08 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1731.69%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3430.05 K</td>
    <td style="white-space: nowrap; text-align: right">0.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1100.01%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1256.31 K</td>
    <td style="white-space: nowrap; text-align: right">0.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;673.12%</td>
    <td style="white-space: nowrap; text-align: right">0.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">211.02 K</td>
    <td style="white-space: nowrap; text-align: right">4.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;115.77%</td>
    <td style="white-space: nowrap; text-align: right">4.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">103.35 K</td>
    <td style="white-space: nowrap; text-align: right">9.68 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;117.89%</td>
    <td style="white-space: nowrap; text-align: right">8.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">95.60 K</td>
    <td style="white-space: nowrap; text-align: right">10.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.57%</td>
    <td style="white-space: nowrap; text-align: right">9.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">88.18 K</td>
    <td style="white-space: nowrap; text-align: right">11.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.65%</td>
    <td style="white-space: nowrap; text-align: right">10.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.16 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.25 K</td>
    <td style="white-space: nowrap; text-align: right">11.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.50%</td>
    <td style="white-space: nowrap; text-align: right">10.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.91 K</td>
    <td style="white-space: nowrap; text-align: right">11.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;82.95%</td>
    <td style="white-space: nowrap; text-align: right">10.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">79.80 K</td>
    <td style="white-space: nowrap; text-align: right">12.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.45%</td>
    <td style="white-space: nowrap; text-align: right">11.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">72.48 K</td>
    <td style="white-space: nowrap; text-align: right">13.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.91%</td>
    <td style="white-space: nowrap; text-align: right">12.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">56.16 K</td>
    <td style="white-space: nowrap; text-align: right">17.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;56.50%</td>
    <td style="white-space: nowrap; text-align: right">16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">50.88 K</td>
    <td style="white-space: nowrap; text-align: right">19.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.41%</td>
    <td style="white-space: nowrap; text-align: right">18.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">46.61 K</td>
    <td style="white-space: nowrap; text-align: right">21.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;44.47%</td>
    <td style="white-space: nowrap; text-align: right">18.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">55.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">42.43 K</td>
    <td style="white-space: nowrap; text-align: right">23.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;33.30%</td>
    <td style="white-space: nowrap; text-align: right">21.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.92 K</td>
    <td style="white-space: nowrap; text-align: right">24.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.81%</td>
    <td style="white-space: nowrap; text-align: right">23.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">37.40 K</td>
    <td style="white-space: nowrap; text-align: right">26.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.73%</td>
    <td style="white-space: nowrap; text-align: right">26.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">37.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">36.04 K</td>
    <td style="white-space: nowrap; text-align: right">27.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.59%</td>
    <td style="white-space: nowrap; text-align: right">27.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">28.94 K</td>
    <td style="white-space: nowrap; text-align: right">34.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.38%</td>
    <td style="white-space: nowrap; text-align: right">32.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">62.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.76 K</td>
    <td style="white-space: nowrap; text-align: right">37.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.22%</td>
    <td style="white-space: nowrap; text-align: right">34.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">22.76 K</td>
    <td style="white-space: nowrap; text-align: right">43.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.50%</td>
    <td style="white-space: nowrap; text-align: right">41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">82.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.44 K</td>
    <td style="white-space: nowrap; text-align: right">44.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.89%</td>
    <td style="white-space: nowrap; text-align: right">43.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">59.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.20 K</td>
    <td style="white-space: nowrap; text-align: right">54.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.17%</td>
    <td style="white-space: nowrap; text-align: right">53.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.82 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">15.83 K</td>
    <td style="white-space: nowrap; text-align: right">63.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.55%</td>
    <td style="white-space: nowrap; text-align: right">61.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">80.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">14.82 K</td>
    <td style="white-space: nowrap; text-align: right">67.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.85%</td>
    <td style="white-space: nowrap; text-align: right">66.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">86.43 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.16 K</td>
    <td style="white-space: nowrap; text-align: right">75.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.46%</td>
    <td style="white-space: nowrap; text-align: right">75.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">94.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">10.58 K</td>
    <td style="white-space: nowrap; text-align: right">94.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.89%</td>
    <td style="white-space: nowrap; text-align: right">93.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">128.80 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.00 K</td>
    <td style="white-space: nowrap; text-align: right">111.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.68%</td>
    <td style="white-space: nowrap; text-align: right">109.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">148.57 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.81 K</td>
    <td style="white-space: nowrap; text-align: right">113.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.23%</td>
    <td style="white-space: nowrap; text-align: right">112.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">141.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.95 K</td>
    <td style="white-space: nowrap; text-align: right">202.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.67%</td>
    <td style="white-space: nowrap; text-align: right">200.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">284.37 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.25 K</td>
    <td style="white-space: nowrap; text-align: right">235.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.75%</td>
    <td style="white-space: nowrap; text-align: right">231.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">293.46 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3610.08 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3430.05 K</td>
    <td style="white-space: nowrap; text-align: right">1.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1256.31 K</td>
    <td style="white-space: nowrap; text-align: right">2.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">211.02 K</td>
    <td style="white-space: nowrap; text-align: right">17.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">103.35 K</td>
    <td style="white-space: nowrap; text-align: right">34.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">95.60 K</td>
    <td style="white-space: nowrap; text-align: right">37.76x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">88.18 K</td>
    <td style="white-space: nowrap; text-align: right">40.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.25 K</td>
    <td style="white-space: nowrap; text-align: right">41.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.91 K</td>
    <td style="white-space: nowrap; text-align: right">42.02x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">79.80 K</td>
    <td style="white-space: nowrap; text-align: right">45.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">72.48 K</td>
    <td style="white-space: nowrap; text-align: right">49.81x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">56.16 K</td>
    <td style="white-space: nowrap; text-align: right">64.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">50.88 K</td>
    <td style="white-space: nowrap; text-align: right">70.96x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">46.61 K</td>
    <td style="white-space: nowrap; text-align: right">77.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">42.43 K</td>
    <td style="white-space: nowrap; text-align: right">85.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.92 K</td>
    <td style="white-space: nowrap; text-align: right">88.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">37.40 K</td>
    <td style="white-space: nowrap; text-align: right">96.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">36.04 K</td>
    <td style="white-space: nowrap; text-align: right">100.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">28.94 K</td>
    <td style="white-space: nowrap; text-align: right">124.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.76 K</td>
    <td style="white-space: nowrap; text-align: right">134.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">22.76 K</td>
    <td style="white-space: nowrap; text-align: right">158.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.44 K</td>
    <td style="white-space: nowrap; text-align: right">160.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.20 K</td>
    <td style="white-space: nowrap; text-align: right">198.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">15.83 K</td>
    <td style="white-space: nowrap; text-align: right">228.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">14.82 K</td>
    <td style="white-space: nowrap; text-align: right">243.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.16 K</td>
    <td style="white-space: nowrap; text-align: right">274.32x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">10.58 K</td>
    <td style="white-space: nowrap; text-align: right">341.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.00 K</td>
    <td style="white-space: nowrap; text-align: right">400.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.81 K</td>
    <td style="white-space: nowrap; text-align: right">410.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.95 K</td>
    <td style="white-space: nowrap; text-align: right">729.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.25 K</td>
    <td style="white-space: nowrap; text-align: right">849.29x</td>
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
    <td style="white-space: nowrap">23.25 KB</td>
    <td>124.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap">29.76 KB</td>
    <td>158.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">11.03 KB</td>
    <td>58.83x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.23 KB</td>
    <td>91.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">14.19 KB</td>
    <td>75.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">16.66 KB</td>
    <td>88.83x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>384.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">41.30 KB</td>
    <td>220.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">38.46 KB</td>
    <td>205.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">30.41 KB</td>
    <td>162.17x</td>
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
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.76 KB</td>
    <td>14.72x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>96.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap">61.55 KB</td>
    <td>328.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">54 KB</td>
    <td>288.0x</td>
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