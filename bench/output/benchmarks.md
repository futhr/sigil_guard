Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 18:30:44.759122Z
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
    <td style="white-space: nowrap; text-align: right">4222.96 K</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2226.30%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3540.70 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1036.82%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1269.39 K</td>
    <td style="white-space: nowrap; text-align: right">0.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;695.83%</td>
    <td style="white-space: nowrap; text-align: right">0.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">216.60 K</td>
    <td style="white-space: nowrap; text-align: right">4.62 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;108.40%</td>
    <td style="white-space: nowrap; text-align: right">4.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">99.61 K</td>
    <td style="white-space: nowrap; text-align: right">10.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;83.03%</td>
    <td style="white-space: nowrap; text-align: right">9.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">96.66 K</td>
    <td style="white-space: nowrap; text-align: right">10.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.08%</td>
    <td style="white-space: nowrap; text-align: right">9.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">90.12 K</td>
    <td style="white-space: nowrap; text-align: right">11.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.82%</td>
    <td style="white-space: nowrap; text-align: right">10.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.76 K</td>
    <td style="white-space: nowrap; text-align: right">11.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.42%</td>
    <td style="white-space: nowrap; text-align: right">11.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">85.08 K</td>
    <td style="white-space: nowrap; text-align: right">11.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;50.64%</td>
    <td style="white-space: nowrap; text-align: right">11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">81.72 K</td>
    <td style="white-space: nowrap; text-align: right">12.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;32.58%</td>
    <td style="white-space: nowrap; text-align: right">11.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">74.80 K</td>
    <td style="white-space: nowrap; text-align: right">13.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.45%</td>
    <td style="white-space: nowrap; text-align: right">12.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">64.13 K</td>
    <td style="white-space: nowrap; text-align: right">15.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;50.04%</td>
    <td style="white-space: nowrap; text-align: right">14.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">50.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">57.19 K</td>
    <td style="white-space: nowrap; text-align: right">17.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;42.56%</td>
    <td style="white-space: nowrap; text-align: right">15.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">51.89 K</td>
    <td style="white-space: nowrap; text-align: right">19.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.72%</td>
    <td style="white-space: nowrap; text-align: right">18.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.94 K</td>
    <td style="white-space: nowrap; text-align: right">22.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;42.76%</td>
    <td style="white-space: nowrap; text-align: right">20.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.55 K</td>
    <td style="white-space: nowrap; text-align: right">24.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.78%</td>
    <td style="white-space: nowrap; text-align: right">24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">59.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">36.18 K</td>
    <td style="white-space: nowrap; text-align: right">27.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.76%</td>
    <td style="white-space: nowrap; text-align: right">26.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">35.52 K</td>
    <td style="white-space: nowrap; text-align: right">28.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.12%</td>
    <td style="white-space: nowrap; text-align: right">27.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">33.24 K</td>
    <td style="white-space: nowrap; text-align: right">30.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.78%</td>
    <td style="white-space: nowrap; text-align: right">28.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.87 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">23.04 K</td>
    <td style="white-space: nowrap; text-align: right">43.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.45%</td>
    <td style="white-space: nowrap; text-align: right">42.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">55.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.27 K</td>
    <td style="white-space: nowrap; text-align: right">51.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.44%</td>
    <td style="white-space: nowrap; text-align: right">51.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">68.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.58 K</td>
    <td style="white-space: nowrap; text-align: right">64.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.23%</td>
    <td style="white-space: nowrap; text-align: right">63.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">81.91 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.06 K</td>
    <td style="white-space: nowrap; text-align: right">76.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.21%</td>
    <td style="white-space: nowrap; text-align: right">74.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">97.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">10.95 K</td>
    <td style="white-space: nowrap; text-align: right">91.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.39%</td>
    <td style="white-space: nowrap; text-align: right">88.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">125.99 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.51 K</td>
    <td style="white-space: nowrap; text-align: right">117.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.96%</td>
    <td style="white-space: nowrap; text-align: right">116.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">143.66 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.19 K</td>
    <td style="white-space: nowrap; text-align: right">192.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.20%</td>
    <td style="white-space: nowrap; text-align: right">189.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">292.70 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.01 K</td>
    <td style="white-space: nowrap; text-align: right">249.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.59%</td>
    <td style="white-space: nowrap; text-align: right">250.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">320.22 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4222.96 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3540.70 K</td>
    <td style="white-space: nowrap; text-align: right">1.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1269.39 K</td>
    <td style="white-space: nowrap; text-align: right">3.33x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">216.60 K</td>
    <td style="white-space: nowrap; text-align: right">19.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">99.61 K</td>
    <td style="white-space: nowrap; text-align: right">42.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">96.66 K</td>
    <td style="white-space: nowrap; text-align: right">43.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">90.12 K</td>
    <td style="white-space: nowrap; text-align: right">46.86x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.76 K</td>
    <td style="white-space: nowrap; text-align: right">49.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">85.08 K</td>
    <td style="white-space: nowrap; text-align: right">49.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">81.72 K</td>
    <td style="white-space: nowrap; text-align: right">51.68x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">74.80 K</td>
    <td style="white-space: nowrap; text-align: right">56.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">64.13 K</td>
    <td style="white-space: nowrap; text-align: right">65.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">57.19 K</td>
    <td style="white-space: nowrap; text-align: right">73.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">51.89 K</td>
    <td style="white-space: nowrap; text-align: right">81.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.94 K</td>
    <td style="white-space: nowrap; text-align: right">93.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.55 K</td>
    <td style="white-space: nowrap; text-align: right">104.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">36.18 K</td>
    <td style="white-space: nowrap; text-align: right">116.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">35.52 K</td>
    <td style="white-space: nowrap; text-align: right">118.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">33.24 K</td>
    <td style="white-space: nowrap; text-align: right">127.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">23.04 K</td>
    <td style="white-space: nowrap; text-align: right">183.32x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.27 K</td>
    <td style="white-space: nowrap; text-align: right">219.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.58 K</td>
    <td style="white-space: nowrap; text-align: right">271.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.06 K</td>
    <td style="white-space: nowrap; text-align: right">323.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">10.95 K</td>
    <td style="white-space: nowrap; text-align: right">385.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.51 K</td>
    <td style="white-space: nowrap; text-align: right">496.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.19 K</td>
    <td style="white-space: nowrap; text-align: right">813.96x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.01 K</td>
    <td style="white-space: nowrap; text-align: right">1053.26x</td>
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
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">14.19 KB</td>
    <td>75.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.23 KB</td>
    <td>91.92x</td>
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
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>10.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.75 KB</td>
    <td>14.65x</td>
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