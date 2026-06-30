Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 18:57:17.529020Z
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
    <td style="white-space: nowrap; text-align: right">4010.63 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2136.12%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3765.60 K</td>
    <td style="white-space: nowrap; text-align: right">0.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1220.96%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1383.06 K</td>
    <td style="white-space: nowrap; text-align: right">0.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;625.50%</td>
    <td style="white-space: nowrap; text-align: right">0.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">283.46 K</td>
    <td style="white-space: nowrap; text-align: right">3.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;156.19%</td>
    <td style="white-space: nowrap; text-align: right">3.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">230.43 K</td>
    <td style="white-space: nowrap; text-align: right">4.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;118.95%</td>
    <td style="white-space: nowrap; text-align: right">4.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">106.13 K</td>
    <td style="white-space: nowrap; text-align: right">9.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;65.41%</td>
    <td style="white-space: nowrap; text-align: right">8.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">102.19 K</td>
    <td style="white-space: nowrap; text-align: right">9.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;77.47%</td>
    <td style="white-space: nowrap; text-align: right">9.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">101.77 K</td>
    <td style="white-space: nowrap; text-align: right">9.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.58%</td>
    <td style="white-space: nowrap; text-align: right">9.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.95 K</td>
    <td style="white-space: nowrap; text-align: right">10.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.45%</td>
    <td style="white-space: nowrap; text-align: right">10.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">89.15 K</td>
    <td style="white-space: nowrap; text-align: right">11.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;47.80%</td>
    <td style="white-space: nowrap; text-align: right">10.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">87.41 K</td>
    <td style="white-space: nowrap; text-align: right">11.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;37.27%</td>
    <td style="white-space: nowrap; text-align: right">10.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">85.83 K</td>
    <td style="white-space: nowrap; text-align: right">11.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.00%</td>
    <td style="white-space: nowrap; text-align: right">10.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">31.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">85.04 K</td>
    <td style="white-space: nowrap; text-align: right">11.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.52%</td>
    <td style="white-space: nowrap; text-align: right">11.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">78.19 K</td>
    <td style="white-space: nowrap; text-align: right">12.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.26%</td>
    <td style="white-space: nowrap; text-align: right">12.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">58.49 K</td>
    <td style="white-space: nowrap; text-align: right">17.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.96%</td>
    <td style="white-space: nowrap; text-align: right">15.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">54.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">57.62 K</td>
    <td style="white-space: nowrap; text-align: right">17.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.17%</td>
    <td style="white-space: nowrap; text-align: right">16.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">54.37 K</td>
    <td style="white-space: nowrap; text-align: right">18.39 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.52%</td>
    <td style="white-space: nowrap; text-align: right">17.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">52.56 K</td>
    <td style="white-space: nowrap; text-align: right">19.03 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.24%</td>
    <td style="white-space: nowrap; text-align: right">17.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.67 K</td>
    <td style="white-space: nowrap; text-align: right">22.39 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.31%</td>
    <td style="white-space: nowrap; text-align: right">20.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">51.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.84 K</td>
    <td style="white-space: nowrap; text-align: right">24.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.02%</td>
    <td style="white-space: nowrap; text-align: right">23.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.12 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">37.73 K</td>
    <td style="white-space: nowrap; text-align: right">26.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.29%</td>
    <td style="white-space: nowrap; text-align: right">26.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">37.31 K</td>
    <td style="white-space: nowrap; text-align: right">26.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.21%</td>
    <td style="white-space: nowrap; text-align: right">26.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.29 K</td>
    <td style="white-space: nowrap; text-align: right">26.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.93%</td>
    <td style="white-space: nowrap; text-align: right">26.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">32.03 K</td>
    <td style="white-space: nowrap; text-align: right">31.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.18%</td>
    <td style="white-space: nowrap; text-align: right">30.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">60.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.52 K</td>
    <td style="white-space: nowrap; text-align: right">37.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.04%</td>
    <td style="white-space: nowrap; text-align: right">33.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.12 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.63 K</td>
    <td style="white-space: nowrap; text-align: right">39.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.77%</td>
    <td style="white-space: nowrap; text-align: right">35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">23.17 K</td>
    <td style="white-space: nowrap; text-align: right">43.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.12%</td>
    <td style="white-space: nowrap; text-align: right">42.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.99 K</td>
    <td style="white-space: nowrap; text-align: right">52.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.11%</td>
    <td style="white-space: nowrap; text-align: right">51.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.57 K</td>
    <td style="white-space: nowrap; text-align: right">60.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.94%</td>
    <td style="white-space: nowrap; text-align: right">59.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.87 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.45 K</td>
    <td style="white-space: nowrap; text-align: right">64.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.85%</td>
    <td style="white-space: nowrap; text-align: right">64.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.49 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.62 K</td>
    <td style="white-space: nowrap; text-align: right">73.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.39%</td>
    <td style="white-space: nowrap; text-align: right">72.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">86.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">11.27 K</td>
    <td style="white-space: nowrap; text-align: right">88.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.63%</td>
    <td style="white-space: nowrap; text-align: right">87.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">110.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.20 K</td>
    <td style="white-space: nowrap; text-align: right">98.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.57%</td>
    <td style="white-space: nowrap; text-align: right">97.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">117.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.54 K</td>
    <td style="white-space: nowrap; text-align: right">117.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.46%</td>
    <td style="white-space: nowrap; text-align: right">115.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">137.64 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.14 K</td>
    <td style="white-space: nowrap; text-align: right">194.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.94%</td>
    <td style="white-space: nowrap; text-align: right">190.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">275.37 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.12 K</td>
    <td style="white-space: nowrap; text-align: right">242.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.15%</td>
    <td style="white-space: nowrap; text-align: right">241.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">287.17 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4010.63 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3765.60 K</td>
    <td style="white-space: nowrap; text-align: right">1.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1383.06 K</td>
    <td style="white-space: nowrap; text-align: right">2.9x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">283.46 K</td>
    <td style="white-space: nowrap; text-align: right">14.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">230.43 K</td>
    <td style="white-space: nowrap; text-align: right">17.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">106.13 K</td>
    <td style="white-space: nowrap; text-align: right">37.79x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">102.19 K</td>
    <td style="white-space: nowrap; text-align: right">39.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">101.77 K</td>
    <td style="white-space: nowrap; text-align: right">39.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.95 K</td>
    <td style="white-space: nowrap; text-align: right">42.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">89.15 K</td>
    <td style="white-space: nowrap; text-align: right">44.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">87.41 K</td>
    <td style="white-space: nowrap; text-align: right">45.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">85.83 K</td>
    <td style="white-space: nowrap; text-align: right">46.73x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">85.04 K</td>
    <td style="white-space: nowrap; text-align: right">47.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">78.19 K</td>
    <td style="white-space: nowrap; text-align: right">51.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">58.49 K</td>
    <td style="white-space: nowrap; text-align: right">68.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">57.62 K</td>
    <td style="white-space: nowrap; text-align: right">69.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">54.37 K</td>
    <td style="white-space: nowrap; text-align: right">73.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">52.56 K</td>
    <td style="white-space: nowrap; text-align: right">76.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.67 K</td>
    <td style="white-space: nowrap; text-align: right">89.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.84 K</td>
    <td style="white-space: nowrap; text-align: right">98.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">37.73 K</td>
    <td style="white-space: nowrap; text-align: right">106.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">37.31 K</td>
    <td style="white-space: nowrap; text-align: right">107.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.29 K</td>
    <td style="white-space: nowrap; text-align: right">107.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">32.03 K</td>
    <td style="white-space: nowrap; text-align: right">125.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.52 K</td>
    <td style="white-space: nowrap; text-align: right">151.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.63 K</td>
    <td style="white-space: nowrap; text-align: right">156.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">23.17 K</td>
    <td style="white-space: nowrap; text-align: right">173.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.99 K</td>
    <td style="white-space: nowrap; text-align: right">211.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.57 K</td>
    <td style="white-space: nowrap; text-align: right">242.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.45 K</td>
    <td style="white-space: nowrap; text-align: right">259.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.62 K</td>
    <td style="white-space: nowrap; text-align: right">294.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">11.27 K</td>
    <td style="white-space: nowrap; text-align: right">356.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.20 K</td>
    <td style="white-space: nowrap; text-align: right">393.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.54 K</td>
    <td style="white-space: nowrap; text-align: right">469.42x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.14 K</td>
    <td style="white-space: nowrap; text-align: right">780.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.12 K</td>
    <td style="white-space: nowrap; text-align: right">972.71x</td>
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
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.25 KB</td>
    <td>124.0x</td>
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
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">15.34 KB</td>
    <td>81.83x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>384.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">38.46 KB</td>
    <td>205.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">41.30 KB</td>
    <td>220.29x</td>
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