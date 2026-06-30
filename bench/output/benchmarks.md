Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 17:26:04.637615Z
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
    <td style="white-space: nowrap; text-align: right">4293.70 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1595.71%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3998.02 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1119.98%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1451.73 K</td>
    <td style="white-space: nowrap; text-align: right">0.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;589.35%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">114.92 K</td>
    <td style="white-space: nowrap; text-align: right">8.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;80.60%</td>
    <td style="white-space: nowrap; text-align: right">8.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">111.80 K</td>
    <td style="white-space: nowrap; text-align: right">8.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;73.06%</td>
    <td style="white-space: nowrap; text-align: right">8.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">94.84 K</td>
    <td style="white-space: nowrap; text-align: right">10.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;71.28%</td>
    <td style="white-space: nowrap; text-align: right">9.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">91.51 K</td>
    <td style="white-space: nowrap; text-align: right">10.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;76.86%</td>
    <td style="white-space: nowrap; text-align: right">10.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.89 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">65.59 K</td>
    <td style="white-space: nowrap; text-align: right">15.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;47.84%</td>
    <td style="white-space: nowrap; text-align: right">13.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">64.57 K</td>
    <td style="white-space: nowrap; text-align: right">15.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;61.96%</td>
    <td style="white-space: nowrap; text-align: right">13.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">61.80 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">64.42 K</td>
    <td style="white-space: nowrap; text-align: right">15.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;70.97%</td>
    <td style="white-space: nowrap; text-align: right">13.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">56.62 K</td>
    <td style="white-space: nowrap; text-align: right">17.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.18%</td>
    <td style="white-space: nowrap; text-align: right">16.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">28.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.62 K</td>
    <td style="white-space: nowrap; text-align: right">22.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.95%</td>
    <td style="white-space: nowrap; text-align: right">21.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.07 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">40.19 K</td>
    <td style="white-space: nowrap; text-align: right">24.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.97%</td>
    <td style="white-space: nowrap; text-align: right">22.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">61.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.84 K</td>
    <td style="white-space: nowrap; text-align: right">40.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.69%</td>
    <td style="white-space: nowrap; text-align: right">38.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.44 K</td>
    <td style="white-space: nowrap; text-align: right">48.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.45%</td>
    <td style="white-space: nowrap; text-align: right">47.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">63.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">12.91 K</td>
    <td style="white-space: nowrap; text-align: right">77.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.30%</td>
    <td style="white-space: nowrap; text-align: right">75.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">111.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.23 K</td>
    <td style="white-space: nowrap; text-align: right">108.39 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.27%</td>
    <td style="white-space: nowrap; text-align: right">106.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">131.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.73 K</td>
    <td style="white-space: nowrap; text-align: right">174.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.72%</td>
    <td style="white-space: nowrap; text-align: right">168.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">241.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.46 K</td>
    <td style="white-space: nowrap; text-align: right">224.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.58%</td>
    <td style="white-space: nowrap; text-align: right">219.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">273.68 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4293.70 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3998.02 K</td>
    <td style="white-space: nowrap; text-align: right">1.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1451.73 K</td>
    <td style="white-space: nowrap; text-align: right">2.96x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">114.92 K</td>
    <td style="white-space: nowrap; text-align: right">37.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">111.80 K</td>
    <td style="white-space: nowrap; text-align: right">38.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">94.84 K</td>
    <td style="white-space: nowrap; text-align: right">45.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">91.51 K</td>
    <td style="white-space: nowrap; text-align: right">46.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">65.59 K</td>
    <td style="white-space: nowrap; text-align: right">65.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">64.57 K</td>
    <td style="white-space: nowrap; text-align: right">66.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">64.42 K</td>
    <td style="white-space: nowrap; text-align: right">66.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">56.62 K</td>
    <td style="white-space: nowrap; text-align: right">75.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.62 K</td>
    <td style="white-space: nowrap; text-align: right">98.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">40.19 K</td>
    <td style="white-space: nowrap; text-align: right">106.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.84 K</td>
    <td style="white-space: nowrap; text-align: right">172.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.44 K</td>
    <td style="white-space: nowrap; text-align: right">210.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">12.91 K</td>
    <td style="white-space: nowrap; text-align: right">332.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.23 K</td>
    <td style="white-space: nowrap; text-align: right">465.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.73 K</td>
    <td style="white-space: nowrap; text-align: right">748.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.46 K</td>
    <td style="white-space: nowrap; text-align: right">962.21x</td>
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
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">10.97 KB</td>
    <td>58.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">10.45 KB</td>
    <td>55.75x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">10.94 KB</td>
    <td>58.33x</td>
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
    <td style="white-space: nowrap">20.13 KB</td>
    <td>107.38x</td>
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
    <td style="white-space: nowrap">38.39 KB</td>
    <td>204.75x</td>
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