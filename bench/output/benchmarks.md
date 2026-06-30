Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 20:21:16.219517Z
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
    <td style="white-space: nowrap; text-align: right">3877.19 K</td>
    <td style="white-space: nowrap; text-align: right">0.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1640.94%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3689.09 K</td>
    <td style="white-space: nowrap; text-align: right">0.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1235.16%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1239.62 K</td>
    <td style="white-space: nowrap; text-align: right">0.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;687.49%</td>
    <td style="white-space: nowrap; text-align: right">0.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">269.46 K</td>
    <td style="white-space: nowrap; text-align: right">3.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;102.81%</td>
    <td style="white-space: nowrap; text-align: right">3.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">5.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">226.79 K</td>
    <td style="white-space: nowrap; text-align: right">4.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;128.80%</td>
    <td style="white-space: nowrap; text-align: right">4.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">106.82 K</td>
    <td style="white-space: nowrap; text-align: right">9.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;92.43%</td>
    <td style="white-space: nowrap; text-align: right">8.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">100.18 K</td>
    <td style="white-space: nowrap; text-align: right">9.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;80.36%</td>
    <td style="white-space: nowrap; text-align: right">9 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">98.49 K</td>
    <td style="white-space: nowrap; text-align: right">10.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.03%</td>
    <td style="white-space: nowrap; text-align: right">9.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.41 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">91.90 K</td>
    <td style="white-space: nowrap; text-align: right">10.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.42%</td>
    <td style="white-space: nowrap; text-align: right">10.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.47 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">88.30 K</td>
    <td style="white-space: nowrap; text-align: right">11.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.44%</td>
    <td style="white-space: nowrap; text-align: right">10.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">85.90 K</td>
    <td style="white-space: nowrap; text-align: right">11.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;57.55%</td>
    <td style="white-space: nowrap; text-align: right">10.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">31.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">81.66 K</td>
    <td style="white-space: nowrap; text-align: right">12.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.16%</td>
    <td style="white-space: nowrap; text-align: right">11.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">81.27 K</td>
    <td style="white-space: nowrap; text-align: right">12.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;65.63%</td>
    <td style="white-space: nowrap; text-align: right">11.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">75.52 K</td>
    <td style="white-space: nowrap; text-align: right">13.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;61.86%</td>
    <td style="white-space: nowrap; text-align: right">12.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">65.31 K</td>
    <td style="white-space: nowrap; text-align: right">15.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.79%</td>
    <td style="white-space: nowrap; text-align: right">14.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">59.71 K</td>
    <td style="white-space: nowrap; text-align: right">16.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.72%</td>
    <td style="white-space: nowrap; text-align: right">15.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">40.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">56.65 K</td>
    <td style="white-space: nowrap; text-align: right">17.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.46%</td>
    <td style="white-space: nowrap; text-align: right">16.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">42.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">51.10 K</td>
    <td style="white-space: nowrap; text-align: right">19.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.27%</td>
    <td style="white-space: nowrap; text-align: right">18.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">37.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">42.08 K</td>
    <td style="white-space: nowrap; text-align: right">23.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.22%</td>
    <td style="white-space: nowrap; text-align: right">21.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">46.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.45 K</td>
    <td style="white-space: nowrap; text-align: right">24.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.70%</td>
    <td style="white-space: nowrap; text-align: right">23.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">59.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.36 K</td>
    <td style="white-space: nowrap; text-align: right">26.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.85%</td>
    <td style="white-space: nowrap; text-align: right">26.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.42 K</td>
    <td style="white-space: nowrap; text-align: right">36.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.65%</td>
    <td style="white-space: nowrap; text-align: right">35.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">26.96 K</td>
    <td style="white-space: nowrap; text-align: right">37.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.02%</td>
    <td style="white-space: nowrap; text-align: right">36.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">50.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">23.68 K</td>
    <td style="white-space: nowrap; text-align: right">42.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.04%</td>
    <td style="white-space: nowrap; text-align: right">39.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">79.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">23.00 K</td>
    <td style="white-space: nowrap; text-align: right">43.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.26%</td>
    <td style="white-space: nowrap; text-align: right">40.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.68 K</td>
    <td style="white-space: nowrap; text-align: right">44.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.52%</td>
    <td style="white-space: nowrap; text-align: right">43.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.93 K</td>
    <td style="white-space: nowrap; text-align: right">50.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.58%</td>
    <td style="white-space: nowrap; text-align: right">48.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.44 K</td>
    <td style="white-space: nowrap; text-align: right">51.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.27%</td>
    <td style="white-space: nowrap; text-align: right">51.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">65.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.06 K</td>
    <td style="white-space: nowrap; text-align: right">58.61 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.08%</td>
    <td style="white-space: nowrap; text-align: right">58.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">71.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.37 K</td>
    <td style="white-space: nowrap; text-align: right">65.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.75%</td>
    <td style="white-space: nowrap; text-align: right">64.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">82.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.50 K</td>
    <td style="white-space: nowrap; text-align: right">74.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.11%</td>
    <td style="white-space: nowrap; text-align: right">73.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">93.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">9.77 K</td>
    <td style="white-space: nowrap; text-align: right">102.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.94%</td>
    <td style="white-space: nowrap; text-align: right">99.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">136.03 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.37 K</td>
    <td style="white-space: nowrap; text-align: right">106.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.94%</td>
    <td style="white-space: nowrap; text-align: right">105.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">134.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.68 K</td>
    <td style="white-space: nowrap; text-align: right">115.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.26%</td>
    <td style="white-space: nowrap; text-align: right">114.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">146.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.99 K</td>
    <td style="white-space: nowrap; text-align: right">200.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.57%</td>
    <td style="white-space: nowrap; text-align: right">200.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">275.34 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">3.86 K</td>
    <td style="white-space: nowrap; text-align: right">259.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.29%</td>
    <td style="white-space: nowrap; text-align: right">258.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">322.19 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3877.19 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3689.09 K</td>
    <td style="white-space: nowrap; text-align: right">1.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1239.62 K</td>
    <td style="white-space: nowrap; text-align: right">3.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">269.46 K</td>
    <td style="white-space: nowrap; text-align: right">14.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">226.79 K</td>
    <td style="white-space: nowrap; text-align: right">17.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">106.82 K</td>
    <td style="white-space: nowrap; text-align: right">36.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">100.18 K</td>
    <td style="white-space: nowrap; text-align: right">38.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">98.49 K</td>
    <td style="white-space: nowrap; text-align: right">39.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">91.90 K</td>
    <td style="white-space: nowrap; text-align: right">42.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">88.30 K</td>
    <td style="white-space: nowrap; text-align: right">43.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">85.90 K</td>
    <td style="white-space: nowrap; text-align: right">45.14x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">81.66 K</td>
    <td style="white-space: nowrap; text-align: right">47.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">81.27 K</td>
    <td style="white-space: nowrap; text-align: right">47.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">75.52 K</td>
    <td style="white-space: nowrap; text-align: right">51.34x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">65.31 K</td>
    <td style="white-space: nowrap; text-align: right">59.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">59.71 K</td>
    <td style="white-space: nowrap; text-align: right">64.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">56.65 K</td>
    <td style="white-space: nowrap; text-align: right">68.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">51.10 K</td>
    <td style="white-space: nowrap; text-align: right">75.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">42.08 K</td>
    <td style="white-space: nowrap; text-align: right">92.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.45 K</td>
    <td style="white-space: nowrap; text-align: right">95.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.36 K</td>
    <td style="white-space: nowrap; text-align: right">103.79x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.42 K</td>
    <td style="white-space: nowrap; text-align: right">141.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">26.96 K</td>
    <td style="white-space: nowrap; text-align: right">143.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">23.68 K</td>
    <td style="white-space: nowrap; text-align: right">163.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">23.00 K</td>
    <td style="white-space: nowrap; text-align: right">168.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.68 K</td>
    <td style="white-space: nowrap; text-align: right">170.96x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.93 K</td>
    <td style="white-space: nowrap; text-align: right">194.53x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.44 K</td>
    <td style="white-space: nowrap; text-align: right">199.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.06 K</td>
    <td style="white-space: nowrap; text-align: right">227.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.37 K</td>
    <td style="white-space: nowrap; text-align: right">252.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.50 K</td>
    <td style="white-space: nowrap; text-align: right">287.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">9.77 K</td>
    <td style="white-space: nowrap; text-align: right">396.86x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.37 K</td>
    <td style="white-space: nowrap; text-align: right">413.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.68 K</td>
    <td style="white-space: nowrap; text-align: right">446.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.99 K</td>
    <td style="white-space: nowrap; text-align: right">777.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">3.86 K</td>
    <td style="white-space: nowrap; text-align: right">1004.34x</td>
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
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap">29.76 KB</td>
    <td>158.71x</td>
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
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">8.55 KB</td>
    <td>45.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">11.91 KB</td>
    <td>63.5x</td>
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
    <td style="white-space: nowrap">16.79 KB</td>
    <td>89.54x</td>
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
    <td style="white-space: nowrap">35.64 KB</td>
    <td>190.08x</td>
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
    <td style="white-space: nowrap">46.91 KB</td>
    <td>250.17x</td>
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