Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 16:14:23.658034Z
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
    <td style="white-space: nowrap; text-align: right">4396.23 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1633.90%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4346.04 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;335.14%</td>
    <td style="white-space: nowrap; text-align: right">0.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.31 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1556.26 K</td>
    <td style="white-space: nowrap; text-align: right">0.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;626.80%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">113.88 K</td>
    <td style="white-space: nowrap; text-align: right">8.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;61.24%</td>
    <td style="white-space: nowrap; text-align: right">8.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">111.01 K</td>
    <td style="white-space: nowrap; text-align: right">9.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;68.98%</td>
    <td style="white-space: nowrap; text-align: right">8.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">96.42 K</td>
    <td style="white-space: nowrap; text-align: right">10.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;50.05%</td>
    <td style="white-space: nowrap; text-align: right">9.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">91.29 K</td>
    <td style="white-space: nowrap; text-align: right">10.95 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;49.48%</td>
    <td style="white-space: nowrap; text-align: right">10.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">47.72 K</td>
    <td style="white-space: nowrap; text-align: right">20.95 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.03%</td>
    <td style="white-space: nowrap; text-align: right">17.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.53 K</td>
    <td style="white-space: nowrap; text-align: right">22.97 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.10%</td>
    <td style="white-space: nowrap; text-align: right">21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">56.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">25.18 K</td>
    <td style="white-space: nowrap; text-align: right">39.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.47%</td>
    <td style="white-space: nowrap; text-align: right">38.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.68 K</td>
    <td style="white-space: nowrap; text-align: right">48.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.74%</td>
    <td style="white-space: nowrap; text-align: right">46.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">62.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.63 K</td>
    <td style="white-space: nowrap; text-align: right">103.89 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.01%</td>
    <td style="white-space: nowrap; text-align: right">101.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">123.22 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.80 K</td>
    <td style="white-space: nowrap; text-align: right">208.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.73%</td>
    <td style="white-space: nowrap; text-align: right">203.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">297.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.20 K</td>
    <td style="white-space: nowrap; text-align: right">238.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.86%</td>
    <td style="white-space: nowrap; text-align: right">237.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">292.49 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4396.23 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4346.04 K</td>
    <td style="white-space: nowrap; text-align: right">1.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1556.26 K</td>
    <td style="white-space: nowrap; text-align: right">2.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">113.88 K</td>
    <td style="white-space: nowrap; text-align: right">38.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">111.01 K</td>
    <td style="white-space: nowrap; text-align: right">39.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">96.42 K</td>
    <td style="white-space: nowrap; text-align: right">45.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">91.29 K</td>
    <td style="white-space: nowrap; text-align: right">48.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">47.72 K</td>
    <td style="white-space: nowrap; text-align: right">92.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.53 K</td>
    <td style="white-space: nowrap; text-align: right">101.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">25.18 K</td>
    <td style="white-space: nowrap; text-align: right">174.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.68 K</td>
    <td style="white-space: nowrap; text-align: right">212.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.63 K</td>
    <td style="white-space: nowrap; text-align: right">456.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.80 K</td>
    <td style="white-space: nowrap; text-align: right">915.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.20 K</td>
    <td style="white-space: nowrap; text-align: right">1047.48x</td>
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
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">22.08 KB</td>
    <td>117.75x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.11 KB</td>
    <td>384.58x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.39 KB</td>
    <td>23.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap">220.36 KB</td>
    <td>1175.25x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap">741.75 KB</td>
    <td>3956.0x</td>
  </tr>
</table>