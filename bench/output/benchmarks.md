Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 17:36:40.866591Z
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
    <td style="white-space: nowrap; text-align: right">4343.07 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1591.33%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3891.19 K</td>
    <td style="white-space: nowrap; text-align: right">0.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1130.91%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1420.22 K</td>
    <td style="white-space: nowrap; text-align: right">0.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;646.68%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">166.99 K</td>
    <td style="white-space: nowrap; text-align: right">5.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;686.14%</td>
    <td style="white-space: nowrap; text-align: right">4.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">13.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">111.14 K</td>
    <td style="white-space: nowrap; text-align: right">9.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;77.41%</td>
    <td style="white-space: nowrap; text-align: right">8.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">107.49 K</td>
    <td style="white-space: nowrap; text-align: right">9.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;105.05%</td>
    <td style="white-space: nowrap; text-align: right">8.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">92.77 K</td>
    <td style="white-space: nowrap; text-align: right">10.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;70.53%</td>
    <td style="white-space: nowrap; text-align: right">10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">88.93 K</td>
    <td style="white-space: nowrap; text-align: right">11.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;69.89%</td>
    <td style="white-space: nowrap; text-align: right">10.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">83.40 K</td>
    <td style="white-space: nowrap; text-align: right">11.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;51.07%</td>
    <td style="white-space: nowrap; text-align: right">11.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.50 K</td>
    <td style="white-space: nowrap; text-align: right">13.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.36%</td>
    <td style="white-space: nowrap; text-align: right">12.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">64.27 K</td>
    <td style="white-space: nowrap; text-align: right">15.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;50.28%</td>
    <td style="white-space: nowrap; text-align: right">14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">50.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">63.25 K</td>
    <td style="white-space: nowrap; text-align: right">15.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;65.14%</td>
    <td style="white-space: nowrap; text-align: right">14.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">62.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">61.58 K</td>
    <td style="white-space: nowrap; text-align: right">16.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;52.45%</td>
    <td style="white-space: nowrap; text-align: right">14.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">58.29 K</td>
    <td style="white-space: nowrap; text-align: right">17.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.82%</td>
    <td style="white-space: nowrap; text-align: right">15.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">28.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.32 K</td>
    <td style="white-space: nowrap; text-align: right">23.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.74%</td>
    <td style="white-space: nowrap; text-align: right">21.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">42.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">33.17 K</td>
    <td style="white-space: nowrap; text-align: right">30.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.12%</td>
    <td style="white-space: nowrap; text-align: right">27.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">59.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.46 K</td>
    <td style="white-space: nowrap; text-align: right">40.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.91%</td>
    <td style="white-space: nowrap; text-align: right">39.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.05 K</td>
    <td style="white-space: nowrap; text-align: right">49.89 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.26%</td>
    <td style="white-space: nowrap; text-align: right">49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">64.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">12.43 K</td>
    <td style="white-space: nowrap; text-align: right">80.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.16%</td>
    <td style="white-space: nowrap; text-align: right">79.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">111.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.10 K</td>
    <td style="white-space: nowrap; text-align: right">109.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.94%</td>
    <td style="white-space: nowrap; text-align: right">108.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">132.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.22 K</td>
    <td style="white-space: nowrap; text-align: right">191.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.02%</td>
    <td style="white-space: nowrap; text-align: right">188.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">250.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.36 K</td>
    <td style="white-space: nowrap; text-align: right">229.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.66%</td>
    <td style="white-space: nowrap; text-align: right">224.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">286.65 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4343.07 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3891.19 K</td>
    <td style="white-space: nowrap; text-align: right">1.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1420.22 K</td>
    <td style="white-space: nowrap; text-align: right">3.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">166.99 K</td>
    <td style="white-space: nowrap; text-align: right">26.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">111.14 K</td>
    <td style="white-space: nowrap; text-align: right">39.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">107.49 K</td>
    <td style="white-space: nowrap; text-align: right">40.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">92.77 K</td>
    <td style="white-space: nowrap; text-align: right">46.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">88.93 K</td>
    <td style="white-space: nowrap; text-align: right">48.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">83.40 K</td>
    <td style="white-space: nowrap; text-align: right">52.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.50 K</td>
    <td style="white-space: nowrap; text-align: right">56.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">64.27 K</td>
    <td style="white-space: nowrap; text-align: right">67.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">63.25 K</td>
    <td style="white-space: nowrap; text-align: right">68.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">61.58 K</td>
    <td style="white-space: nowrap; text-align: right">70.53x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">58.29 K</td>
    <td style="white-space: nowrap; text-align: right">74.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.32 K</td>
    <td style="white-space: nowrap; text-align: right">100.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">33.17 K</td>
    <td style="white-space: nowrap; text-align: right">130.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.46 K</td>
    <td style="white-space: nowrap; text-align: right">177.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.05 K</td>
    <td style="white-space: nowrap; text-align: right">216.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">12.43 K</td>
    <td style="white-space: nowrap; text-align: right">349.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.10 K</td>
    <td style="white-space: nowrap; text-align: right">477.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.22 K</td>
    <td style="white-space: nowrap; text-align: right">832.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.36 K</td>
    <td style="white-space: nowrap; text-align: right">997.1x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">4.83 KB</td>
    <td>25.75x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.48 KB</td>
    <td>23.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">5.52 KB</td>
    <td>29.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">5.97 KB</td>
    <td>31.83x</td>
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
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">10.98 KB</td>
    <td>58.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">10.46 KB</td>
    <td>55.79x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">10.95 KB</td>
    <td>58.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.08 KB</td>
    <td>91.08x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>384.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">29.97 KB</td>
    <td>159.83x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>10.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.74 KB</td>
    <td>14.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">38.41 KB</td>
    <td>204.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.39 KB</td>
    <td>23.42x</td>
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