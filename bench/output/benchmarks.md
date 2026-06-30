Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 18:02:20.150694Z
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
    <td style="white-space: nowrap; text-align: right">4084.54 K</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1635.38%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3549.79 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1128.73%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1234.88 K</td>
    <td style="white-space: nowrap; text-align: right">0.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;596.90%</td>
    <td style="white-space: nowrap; text-align: right">0.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">215.26 K</td>
    <td style="white-space: nowrap; text-align: right">4.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;120.72%</td>
    <td style="white-space: nowrap; text-align: right">4.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">9.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">106.88 K</td>
    <td style="white-space: nowrap; text-align: right">9.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;100.80%</td>
    <td style="white-space: nowrap; text-align: right">8.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">104.32 K</td>
    <td style="white-space: nowrap; text-align: right">9.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;127.30%</td>
    <td style="white-space: nowrap; text-align: right">8.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">94.70 K</td>
    <td style="white-space: nowrap; text-align: right">10.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;175.25%</td>
    <td style="white-space: nowrap; text-align: right">10.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">90.65 K</td>
    <td style="white-space: nowrap; text-align: right">11.03 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;110.52%</td>
    <td style="white-space: nowrap; text-align: right">10.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">89.46 K</td>
    <td style="white-space: nowrap; text-align: right">11.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;90.15%</td>
    <td style="white-space: nowrap; text-align: right">10.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">87.00 K</td>
    <td style="white-space: nowrap; text-align: right">11.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;68.63%</td>
    <td style="white-space: nowrap; text-align: right">10.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">75.99 K</td>
    <td style="white-space: nowrap; text-align: right">13.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;427.59%</td>
    <td style="white-space: nowrap; text-align: right">11.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">75.39 K</td>
    <td style="white-space: nowrap; text-align: right">13.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.77%</td>
    <td style="white-space: nowrap; text-align: right">12.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">58.11 K</td>
    <td style="white-space: nowrap; text-align: right">17.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;63.55%</td>
    <td style="white-space: nowrap; text-align: right">15.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">59.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">57.58 K</td>
    <td style="white-space: nowrap; text-align: right">17.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.95%</td>
    <td style="white-space: nowrap; text-align: right">16.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">56.39 K</td>
    <td style="white-space: nowrap; text-align: right">17.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;60.20%</td>
    <td style="white-space: nowrap; text-align: right">16.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">60.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">56.05 K</td>
    <td style="white-space: nowrap; text-align: right">17.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;106.47%</td>
    <td style="white-space: nowrap; text-align: right">16.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">42.24 K</td>
    <td style="white-space: nowrap; text-align: right">23.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.56%</td>
    <td style="white-space: nowrap; text-align: right">22.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">31.12 K</td>
    <td style="white-space: nowrap; text-align: right">32.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.14%</td>
    <td style="white-space: nowrap; text-align: right">30.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">23.00 K</td>
    <td style="white-space: nowrap; text-align: right">43.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.99%</td>
    <td style="white-space: nowrap; text-align: right">43.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.92 K</td>
    <td style="white-space: nowrap; text-align: right">52.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.22%</td>
    <td style="white-space: nowrap; text-align: right">52.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">14.70 K</td>
    <td style="white-space: nowrap; text-align: right">68.03 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.16%</td>
    <td style="white-space: nowrap; text-align: right">66.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">92.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.80 K</td>
    <td style="white-space: nowrap; text-align: right">72.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.98%</td>
    <td style="white-space: nowrap; text-align: right">73.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">87 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">11.53 K</td>
    <td style="white-space: nowrap; text-align: right">86.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.21%</td>
    <td style="white-space: nowrap; text-align: right">83.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">128.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.01 K</td>
    <td style="white-space: nowrap; text-align: right">111.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.74%</td>
    <td style="white-space: nowrap; text-align: right">111.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">135.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.03 K</td>
    <td style="white-space: nowrap; text-align: right">198.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.30%</td>
    <td style="white-space: nowrap; text-align: right">197.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">262.91 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.12 K</td>
    <td style="white-space: nowrap; text-align: right">242.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.43%</td>
    <td style="white-space: nowrap; text-align: right">242.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">292.47 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4084.54 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3549.79 K</td>
    <td style="white-space: nowrap; text-align: right">1.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1234.88 K</td>
    <td style="white-space: nowrap; text-align: right">3.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">215.26 K</td>
    <td style="white-space: nowrap; text-align: right">18.98x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">106.88 K</td>
    <td style="white-space: nowrap; text-align: right">38.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">104.32 K</td>
    <td style="white-space: nowrap; text-align: right">39.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">94.70 K</td>
    <td style="white-space: nowrap; text-align: right">43.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">90.65 K</td>
    <td style="white-space: nowrap; text-align: right">45.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">89.46 K</td>
    <td style="white-space: nowrap; text-align: right">45.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">87.00 K</td>
    <td style="white-space: nowrap; text-align: right">46.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">75.99 K</td>
    <td style="white-space: nowrap; text-align: right">53.75x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">75.39 K</td>
    <td style="white-space: nowrap; text-align: right">54.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">58.11 K</td>
    <td style="white-space: nowrap; text-align: right">70.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">57.58 K</td>
    <td style="white-space: nowrap; text-align: right">70.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">56.39 K</td>
    <td style="white-space: nowrap; text-align: right">72.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">56.05 K</td>
    <td style="white-space: nowrap; text-align: right">72.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">42.24 K</td>
    <td style="white-space: nowrap; text-align: right">96.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">31.12 K</td>
    <td style="white-space: nowrap; text-align: right">131.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">23.00 K</td>
    <td style="white-space: nowrap; text-align: right">177.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.92 K</td>
    <td style="white-space: nowrap; text-align: right">215.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">14.70 K</td>
    <td style="white-space: nowrap; text-align: right">277.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.80 K</td>
    <td style="white-space: nowrap; text-align: right">295.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">11.53 K</td>
    <td style="white-space: nowrap; text-align: right">354.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.01 K</td>
    <td style="white-space: nowrap; text-align: right">453.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.03 K</td>
    <td style="white-space: nowrap; text-align: right">811.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.12 K</td>
    <td style="white-space: nowrap; text-align: right">991.37x</td>
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