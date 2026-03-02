Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-03-01 23:49:11.392246Z
Backend: Elixir only


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
    <td style="white-space: nowrap">1.19.5</td>
  </tr><tr>
    <th style="white-space: nowrap">Erlang Version</th>
    <td style="white-space: nowrap">28.3.1</td>
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
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">4670.92 K</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;390.53%</td>
    <td style="white-space: nowrap; text-align: right">0.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap; text-align: right">2849.92 K</td>
    <td style="white-space: nowrap; text-align: right">0.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1562.49%</td>
    <td style="white-space: nowrap; text-align: right">0.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1453.18 K</td>
    <td style="white-space: nowrap; text-align: right">0.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;630.42%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.18 K</td>
    <td style="white-space: nowrap; text-align: right">9.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;60.97%</td>
    <td style="white-space: nowrap; text-align: right">8.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">108.97 K</td>
    <td style="white-space: nowrap; text-align: right">9.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;73.42%</td>
    <td style="white-space: nowrap; text-align: right">8.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">93.05 K</td>
    <td style="white-space: nowrap; text-align: right">10.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.88%</td>
    <td style="white-space: nowrap; text-align: right">10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">89.92 K</td>
    <td style="white-space: nowrap; text-align: right">11.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;49.23%</td>
    <td style="white-space: nowrap; text-align: right">10.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">50.04 K</td>
    <td style="white-space: nowrap; text-align: right">19.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.98%</td>
    <td style="white-space: nowrap; text-align: right">18.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">54.90 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">49.55 K</td>
    <td style="white-space: nowrap; text-align: right">20.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.53%</td>
    <td style="white-space: nowrap; text-align: right">18.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.69 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.20 K</td>
    <td style="white-space: nowrap; text-align: right">41.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.14%</td>
    <td style="white-space: nowrap; text-align: right">41.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.62 K</td>
    <td style="white-space: nowrap; text-align: right">50.97 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.87%</td>
    <td style="white-space: nowrap; text-align: right">51.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">64.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.31 K</td>
    <td style="white-space: nowrap; text-align: right">107.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.66%</td>
    <td style="white-space: nowrap; text-align: right">107.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">127.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.07 K</td>
    <td style="white-space: nowrap; text-align: right">197.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.14%</td>
    <td style="white-space: nowrap; text-align: right">195.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">231.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.36 K</td>
    <td style="white-space: nowrap; text-align: right">229.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.10%</td>
    <td style="white-space: nowrap; text-align: right">224.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">315.20 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap;text-align: right">4670.92 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap; text-align: right">2849.92 K</td>
    <td style="white-space: nowrap; text-align: right">1.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1453.18 K</td>
    <td style="white-space: nowrap; text-align: right">3.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.18 K</td>
    <td style="white-space: nowrap; text-align: right">42.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">108.97 K</td>
    <td style="white-space: nowrap; text-align: right">42.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">93.05 K</td>
    <td style="white-space: nowrap; text-align: right">50.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">89.92 K</td>
    <td style="white-space: nowrap; text-align: right">51.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">50.04 K</td>
    <td style="white-space: nowrap; text-align: right">93.34x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">49.55 K</td>
    <td style="white-space: nowrap; text-align: right">94.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.20 K</td>
    <td style="white-space: nowrap; text-align: right">193.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.62 K</td>
    <td style="white-space: nowrap; text-align: right">238.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.31 K</td>
    <td style="white-space: nowrap; text-align: right">501.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.07 K</td>
    <td style="white-space: nowrap; text-align: right">920.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.36 K</td>
    <td style="white-space: nowrap; text-align: right">1071.04x</td>
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
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap">0.0234 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap">0.33 KB</td>
    <td>14.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap">1.44 KB</td>
    <td>61.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.41 KB</td>
    <td>188.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">4.75 KB</td>
    <td>202.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">5.45 KB</td>
    <td>232.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">5.89 KB</td>
    <td>251.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">19.37 KB</td>
    <td>826.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">21.84 KB</td>
    <td>932.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">1.95 KB</td>
    <td>83.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">3.06 KB</td>
    <td>130.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.50 KB</td>
    <td>192.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap">193.04 KB</td>
    <td>8236.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap">218.02 KB</td>
    <td>9302.0x</td>
  </tr>
</table>