Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 19:59:17.947024Z
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
    <td style="white-space: nowrap; text-align: right">3926.03 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1753.64%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3656.62 K</td>
    <td style="white-space: nowrap; text-align: right">0.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1225.82%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1336.84 K</td>
    <td style="white-space: nowrap; text-align: right">0.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;620.27%</td>
    <td style="white-space: nowrap; text-align: right">0.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">277.82 K</td>
    <td style="white-space: nowrap; text-align: right">3.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;109.09%</td>
    <td style="white-space: nowrap; text-align: right">3.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">223.70 K</td>
    <td style="white-space: nowrap; text-align: right">4.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;120.70%</td>
    <td style="white-space: nowrap; text-align: right">4.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">101.14 K</td>
    <td style="white-space: nowrap; text-align: right">9.89 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.79%</td>
    <td style="white-space: nowrap; text-align: right">9.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.86 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">100.08 K</td>
    <td style="white-space: nowrap; text-align: right">9.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;56.00%</td>
    <td style="white-space: nowrap; text-align: right">9.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">98.07 K</td>
    <td style="white-space: nowrap; text-align: right">10.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;65.73%</td>
    <td style="white-space: nowrap; text-align: right">9.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.04 K</td>
    <td style="white-space: nowrap; text-align: right">10.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.31%</td>
    <td style="white-space: nowrap; text-align: right">10.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">84.89 K</td>
    <td style="white-space: nowrap; text-align: right">11.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;47.29%</td>
    <td style="white-space: nowrap; text-align: right">11.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">28.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">84.52 K</td>
    <td style="white-space: nowrap; text-align: right">11.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.28%</td>
    <td style="white-space: nowrap; text-align: right">11.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">84.30 K</td>
    <td style="white-space: nowrap; text-align: right">11.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;49.02%</td>
    <td style="white-space: nowrap; text-align: right">11.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">78.70 K</td>
    <td style="white-space: nowrap; text-align: right">12.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;43.04%</td>
    <td style="white-space: nowrap; text-align: right">11.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">31.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.10 K</td>
    <td style="white-space: nowrap; text-align: right">13.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.12%</td>
    <td style="white-space: nowrap; text-align: right">12.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">56.76 K</td>
    <td style="white-space: nowrap; text-align: right">17.62 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.10%</td>
    <td style="white-space: nowrap; text-align: right">16.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">55.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">55.02 K</td>
    <td style="white-space: nowrap; text-align: right">18.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.27%</td>
    <td style="white-space: nowrap; text-align: right">17.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">54.41 K</td>
    <td style="white-space: nowrap; text-align: right">18.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.97%</td>
    <td style="white-space: nowrap; text-align: right">17.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.28 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">51.98 K</td>
    <td style="white-space: nowrap; text-align: right">19.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;37.93%</td>
    <td style="white-space: nowrap; text-align: right">17.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">39.70 K</td>
    <td style="white-space: nowrap; text-align: right">25.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.34%</td>
    <td style="white-space: nowrap; text-align: right">24.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.51 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">38.81 K</td>
    <td style="white-space: nowrap; text-align: right">25.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.79%</td>
    <td style="white-space: nowrap; text-align: right">23.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">61.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">36.91 K</td>
    <td style="white-space: nowrap; text-align: right">27.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.64%</td>
    <td style="white-space: nowrap; text-align: right">26.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">29.86 K</td>
    <td style="white-space: nowrap; text-align: right">33.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.32%</td>
    <td style="white-space: nowrap; text-align: right">31.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">56.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">27.77 K</td>
    <td style="white-space: nowrap; text-align: right">36.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.52%</td>
    <td style="white-space: nowrap; text-align: right">35.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.25 K</td>
    <td style="white-space: nowrap; text-align: right">36.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.78%</td>
    <td style="white-space: nowrap; text-align: right">36.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">25.44 K</td>
    <td style="white-space: nowrap; text-align: right">39.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.24%</td>
    <td style="white-space: nowrap; text-align: right">34.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">76.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">24.19 K</td>
    <td style="white-space: nowrap; text-align: right">41.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.07%</td>
    <td style="white-space: nowrap; text-align: right">36.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">78.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.84 K</td>
    <td style="white-space: nowrap; text-align: right">43.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.70%</td>
    <td style="white-space: nowrap; text-align: right">42.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.12 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.88 K</td>
    <td style="white-space: nowrap; text-align: right">52.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.32%</td>
    <td style="white-space: nowrap; text-align: right">51.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">68.62 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.44 K</td>
    <td style="white-space: nowrap; text-align: right">60.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.23%</td>
    <td style="white-space: nowrap; text-align: right">59.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">76.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.24 K</td>
    <td style="white-space: nowrap; text-align: right">65.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.61%</td>
    <td style="white-space: nowrap; text-align: right">64.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">82.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.46 K</td>
    <td style="white-space: nowrap; text-align: right">74.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.24%</td>
    <td style="white-space: nowrap; text-align: right">72.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">91.40 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">10.63 K</td>
    <td style="white-space: nowrap; text-align: right">94.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.15%</td>
    <td style="white-space: nowrap; text-align: right">93.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">118.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.85 K</td>
    <td style="white-space: nowrap; text-align: right">101.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.92%</td>
    <td style="white-space: nowrap; text-align: right">100.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">124.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.41 K</td>
    <td style="white-space: nowrap; text-align: right">118.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.93%</td>
    <td style="white-space: nowrap; text-align: right">116.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">142.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.19 K</td>
    <td style="white-space: nowrap; text-align: right">192.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.87%</td>
    <td style="white-space: nowrap; text-align: right">189.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">278.68 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">3.95 K</td>
    <td style="white-space: nowrap; text-align: right">253.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.42%</td>
    <td style="white-space: nowrap; text-align: right">249.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">308.34 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3926.03 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3656.62 K</td>
    <td style="white-space: nowrap; text-align: right">1.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1336.84 K</td>
    <td style="white-space: nowrap; text-align: right">2.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">277.82 K</td>
    <td style="white-space: nowrap; text-align: right">14.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">223.70 K</td>
    <td style="white-space: nowrap; text-align: right">17.55x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">101.14 K</td>
    <td style="white-space: nowrap; text-align: right">38.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">100.08 K</td>
    <td style="white-space: nowrap; text-align: right">39.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">98.07 K</td>
    <td style="white-space: nowrap; text-align: right">40.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.04 K</td>
    <td style="white-space: nowrap; text-align: right">41.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">84.89 K</td>
    <td style="white-space: nowrap; text-align: right">46.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">84.52 K</td>
    <td style="white-space: nowrap; text-align: right">46.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">84.30 K</td>
    <td style="white-space: nowrap; text-align: right">46.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">78.70 K</td>
    <td style="white-space: nowrap; text-align: right">49.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.10 K</td>
    <td style="white-space: nowrap; text-align: right">51.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">56.76 K</td>
    <td style="white-space: nowrap; text-align: right">69.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">55.02 K</td>
    <td style="white-space: nowrap; text-align: right">71.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">54.41 K</td>
    <td style="white-space: nowrap; text-align: right">72.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">51.98 K</td>
    <td style="white-space: nowrap; text-align: right">75.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">39.70 K</td>
    <td style="white-space: nowrap; text-align: right">98.9x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">38.81 K</td>
    <td style="white-space: nowrap; text-align: right">101.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">36.91 K</td>
    <td style="white-space: nowrap; text-align: right">106.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">29.86 K</td>
    <td style="white-space: nowrap; text-align: right">131.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">27.77 K</td>
    <td style="white-space: nowrap; text-align: right">141.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.25 K</td>
    <td style="white-space: nowrap; text-align: right">144.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">25.44 K</td>
    <td style="white-space: nowrap; text-align: right">154.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">24.19 K</td>
    <td style="white-space: nowrap; text-align: right">162.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.84 K</td>
    <td style="white-space: nowrap; text-align: right">171.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.88 K</td>
    <td style="white-space: nowrap; text-align: right">207.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.44 K</td>
    <td style="white-space: nowrap; text-align: right">238.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.24 K</td>
    <td style="white-space: nowrap; text-align: right">257.55x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.46 K</td>
    <td style="white-space: nowrap; text-align: right">291.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">10.63 K</td>
    <td style="white-space: nowrap; text-align: right">369.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.85 K</td>
    <td style="white-space: nowrap; text-align: right">398.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.41 K</td>
    <td style="white-space: nowrap; text-align: right">466.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.19 K</td>
    <td style="white-space: nowrap; text-align: right">757.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">3.95 K</td>
    <td style="white-space: nowrap; text-align: right">994.0x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.77 KB</td>
    <td>41.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.25 KB</td>
    <td>124.0x</td>
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
    <td style="white-space: nowrap">10.98 KB</td>
    <td>58.58x</td>
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
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">14.27 KB</td>
    <td>76.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>384.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">19.23 KB</td>
    <td>102.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap">10.88 KB</td>
    <td>58.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">30.63 KB</td>
    <td>163.38x</td>
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
    <td style="white-space: nowrap">54.14 KB</td>
    <td>288.75x</td>
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