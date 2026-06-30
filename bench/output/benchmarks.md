Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 18:18:47.611541Z
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
    <td style="white-space: nowrap; text-align: right">3817.94 K</td>
    <td style="white-space: nowrap; text-align: right">0.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1722.60%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3658.10 K</td>
    <td style="white-space: nowrap; text-align: right">0.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1063.54%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1294.51 K</td>
    <td style="white-space: nowrap; text-align: right">0.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;696.80%</td>
    <td style="white-space: nowrap; text-align: right">0.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">219.09 K</td>
    <td style="white-space: nowrap; text-align: right">4.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;109.02%</td>
    <td style="white-space: nowrap; text-align: right">4.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">100.62 K</td>
    <td style="white-space: nowrap; text-align: right">9.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;98.88%</td>
    <td style="white-space: nowrap; text-align: right">9.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">100.16 K</td>
    <td style="white-space: nowrap; text-align: right">9.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.08%</td>
    <td style="white-space: nowrap; text-align: right">9.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.08 K</td>
    <td style="white-space: nowrap; text-align: right">10.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.29%</td>
    <td style="white-space: nowrap; text-align: right">10.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.07 K</td>
    <td style="white-space: nowrap; text-align: right">11.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;71.75%</td>
    <td style="white-space: nowrap; text-align: right">10.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">30.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">86.48 K</td>
    <td style="white-space: nowrap; text-align: right">11.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;61.35%</td>
    <td style="white-space: nowrap; text-align: right">11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">80.15 K</td>
    <td style="white-space: nowrap; text-align: right">12.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;42.76%</td>
    <td style="white-space: nowrap; text-align: right">11.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">73.82 K</td>
    <td style="white-space: nowrap; text-align: right">13.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.89%</td>
    <td style="white-space: nowrap; text-align: right">12.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">57.85 K</td>
    <td style="white-space: nowrap; text-align: right">17.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;79.51%</td>
    <td style="white-space: nowrap; text-align: right">15.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">81.78 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">54.67 K</td>
    <td style="white-space: nowrap; text-align: right">18.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;47.68%</td>
    <td style="white-space: nowrap; text-align: right">16.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">53.32 K</td>
    <td style="white-space: nowrap; text-align: right">18.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.36%</td>
    <td style="white-space: nowrap; text-align: right">17.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">45.02 K</td>
    <td style="white-space: nowrap; text-align: right">22.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;42.68%</td>
    <td style="white-space: nowrap; text-align: right">20.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.24 K</td>
    <td style="white-space: nowrap; text-align: right">24.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.13%</td>
    <td style="white-space: nowrap; text-align: right">23.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">36.26 K</td>
    <td style="white-space: nowrap; text-align: right">27.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.51%</td>
    <td style="white-space: nowrap; text-align: right">27.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">40.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">35.94 K</td>
    <td style="white-space: nowrap; text-align: right">27.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.24%</td>
    <td style="white-space: nowrap; text-align: right">27.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">40.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">30.51 K</td>
    <td style="white-space: nowrap; text-align: right">32.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.87%</td>
    <td style="white-space: nowrap; text-align: right">30.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">94.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.39 K</td>
    <td style="white-space: nowrap; text-align: right">44.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.26%</td>
    <td style="white-space: nowrap; text-align: right">43.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">59.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.17 K</td>
    <td style="white-space: nowrap; text-align: right">55.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.73%</td>
    <td style="white-space: nowrap; text-align: right">53.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.25 K</td>
    <td style="white-space: nowrap; text-align: right">65.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.51%</td>
    <td style="white-space: nowrap; text-align: right">65.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">85.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.56 K</td>
    <td style="white-space: nowrap; text-align: right">73.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.87%</td>
    <td style="white-space: nowrap; text-align: right">73.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">92.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">10.96 K</td>
    <td style="white-space: nowrap; text-align: right">91.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.48%</td>
    <td style="white-space: nowrap; text-align: right">87.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">129.48 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.77 K</td>
    <td style="white-space: nowrap; text-align: right">114.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.68%</td>
    <td style="white-space: nowrap; text-align: right">113.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">140.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.14 K</td>
    <td style="white-space: nowrap; text-align: right">194.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.88%</td>
    <td style="white-space: nowrap; text-align: right">191.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">277.52 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.00 K</td>
    <td style="white-space: nowrap; text-align: right">250.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.38%</td>
    <td style="white-space: nowrap; text-align: right">248.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">316.55 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3817.94 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3658.10 K</td>
    <td style="white-space: nowrap; text-align: right">1.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1294.51 K</td>
    <td style="white-space: nowrap; text-align: right">2.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">219.09 K</td>
    <td style="white-space: nowrap; text-align: right">17.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">100.62 K</td>
    <td style="white-space: nowrap; text-align: right">37.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">100.16 K</td>
    <td style="white-space: nowrap; text-align: right">38.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.08 K</td>
    <td style="white-space: nowrap; text-align: right">40.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.07 K</td>
    <td style="white-space: nowrap; text-align: right">43.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">86.48 K</td>
    <td style="white-space: nowrap; text-align: right">44.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">80.15 K</td>
    <td style="white-space: nowrap; text-align: right">47.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">73.82 K</td>
    <td style="white-space: nowrap; text-align: right">51.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">57.85 K</td>
    <td style="white-space: nowrap; text-align: right">65.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">54.67 K</td>
    <td style="white-space: nowrap; text-align: right">69.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">53.32 K</td>
    <td style="white-space: nowrap; text-align: right">71.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">45.02 K</td>
    <td style="white-space: nowrap; text-align: right">84.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.24 K</td>
    <td style="white-space: nowrap; text-align: right">94.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">36.26 K</td>
    <td style="white-space: nowrap; text-align: right">105.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">35.94 K</td>
    <td style="white-space: nowrap; text-align: right">106.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">30.51 K</td>
    <td style="white-space: nowrap; text-align: right">125.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.39 K</td>
    <td style="white-space: nowrap; text-align: right">170.55x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.17 K</td>
    <td style="white-space: nowrap; text-align: right">210.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.25 K</td>
    <td style="white-space: nowrap; text-align: right">250.32x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.56 K</td>
    <td style="white-space: nowrap; text-align: right">281.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">10.96 K</td>
    <td style="white-space: nowrap; text-align: right">348.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.77 K</td>
    <td style="white-space: nowrap; text-align: right">435.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.14 K</td>
    <td style="white-space: nowrap; text-align: right">743.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.00 K</td>
    <td style="white-space: nowrap; text-align: right">954.65x</td>
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
    <td style="white-space: nowrap">4.56 KB</td>
    <td>24.33x</td>
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
    <td style="white-space: nowrap">8.05 KB</td>
    <td>42.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.70 KB</td>
    <td>30.38x</td>
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
    <td style="white-space: nowrap">10.41 KB</td>
    <td>55.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">13.77 KB</td>
    <td>73.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.08 KB</td>
    <td>91.08x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">16.23 KB</td>
    <td>86.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>384.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">42.83 KB</td>
    <td>228.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">40.81 KB</td>
    <td>217.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">29.98 KB</td>
    <td>159.92x</td>
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
    <td style="white-space: nowrap">54.03 KB</td>
    <td>288.17x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.47 KB</td>
    <td>23.83x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap">170.36 KB</td>
    <td>908.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap">720.41 KB</td>
    <td>3842.17x</td>
  </tr>
</table>