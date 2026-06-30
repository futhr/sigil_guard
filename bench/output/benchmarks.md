Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 16:25:32.237449Z
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
    <td style="white-space: nowrap; text-align: right">4378.86 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2057.04%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4019.45 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1163.29%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1444.55 K</td>
    <td style="white-space: nowrap; text-align: right">0.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1462.38%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">113.15 K</td>
    <td style="white-space: nowrap; text-align: right">8.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;69.77%</td>
    <td style="white-space: nowrap; text-align: right">8.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">111.38 K</td>
    <td style="white-space: nowrap; text-align: right">8.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;88.07%</td>
    <td style="white-space: nowrap; text-align: right">8.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">93.85 K</td>
    <td style="white-space: nowrap; text-align: right">10.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;68.71%</td>
    <td style="white-space: nowrap; text-align: right">9.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">90.50 K</td>
    <td style="white-space: nowrap; text-align: right">11.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;61.27%</td>
    <td style="white-space: nowrap; text-align: right">10.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">52.37 K</td>
    <td style="white-space: nowrap; text-align: right">19.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.06%</td>
    <td style="white-space: nowrap; text-align: right">18.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">30.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.50 K</td>
    <td style="white-space: nowrap; text-align: right">22.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.42%</td>
    <td style="white-space: nowrap; text-align: right">21.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">25.00 K</td>
    <td style="white-space: nowrap; text-align: right">40.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.46%</td>
    <td style="white-space: nowrap; text-align: right">38.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.66 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.44 K</td>
    <td style="white-space: nowrap; text-align: right">48.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.41%</td>
    <td style="white-space: nowrap; text-align: right">47.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">62.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.41 K</td>
    <td style="white-space: nowrap; text-align: right">106.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.12%</td>
    <td style="white-space: nowrap; text-align: right">103.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">129.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.12 K</td>
    <td style="white-space: nowrap; text-align: right">195.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.40%</td>
    <td style="white-space: nowrap; text-align: right">192.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">249.28 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.55 K</td>
    <td style="white-space: nowrap; text-align: right">219.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.72%</td>
    <td style="white-space: nowrap; text-align: right">215.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">267.94 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4378.86 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4019.45 K</td>
    <td style="white-space: nowrap; text-align: right">1.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1444.55 K</td>
    <td style="white-space: nowrap; text-align: right">3.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">113.15 K</td>
    <td style="white-space: nowrap; text-align: right">38.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">111.38 K</td>
    <td style="white-space: nowrap; text-align: right">39.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">93.85 K</td>
    <td style="white-space: nowrap; text-align: right">46.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">90.50 K</td>
    <td style="white-space: nowrap; text-align: right">48.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">52.37 K</td>
    <td style="white-space: nowrap; text-align: right">83.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.50 K</td>
    <td style="white-space: nowrap; text-align: right">100.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">25.00 K</td>
    <td style="white-space: nowrap; text-align: right">175.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.44 K</td>
    <td style="white-space: nowrap; text-align: right">214.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.41 K</td>
    <td style="white-space: nowrap; text-align: right">465.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.12 K</td>
    <td style="white-space: nowrap; text-align: right">854.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.55 K</td>
    <td style="white-space: nowrap; text-align: right">962.59x</td>
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
    <td style="white-space: nowrap">17.08 KB</td>
    <td>91.08x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>384.67x</td>
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
    <td style="white-space: nowrap">170.36 KB</td>
    <td>908.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap">720.41 KB</td>
    <td>3842.17x</td>
  </tr>
</table>