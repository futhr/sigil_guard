Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 17:12:27.976225Z
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
    <td style="white-space: nowrap; text-align: right">4279.17 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1637.57%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3922.60 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1161.40%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1439.33 K</td>
    <td style="white-space: nowrap; text-align: right">0.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;587.19%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">112.89 K</td>
    <td style="white-space: nowrap; text-align: right">8.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;76.14%</td>
    <td style="white-space: nowrap; text-align: right">8.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.77 K</td>
    <td style="white-space: nowrap; text-align: right">9.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;98.28%</td>
    <td style="white-space: nowrap; text-align: right">8.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">93.49 K</td>
    <td style="white-space: nowrap; text-align: right">10.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;108.76%</td>
    <td style="white-space: nowrap; text-align: right">9.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">89.96 K</td>
    <td style="white-space: nowrap; text-align: right">11.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;68.34%</td>
    <td style="white-space: nowrap; text-align: right">10.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">66.32 K</td>
    <td style="white-space: nowrap; text-align: right">15.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.54%</td>
    <td style="white-space: nowrap; text-align: right">13.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">38.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">63.40 K</td>
    <td style="white-space: nowrap; text-align: right">15.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;65.55%</td>
    <td style="white-space: nowrap; text-align: right">14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">59.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">62.99 K</td>
    <td style="white-space: nowrap; text-align: right">15.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;55.43%</td>
    <td style="white-space: nowrap; text-align: right">14.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">56.77 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">57.08 K</td>
    <td style="white-space: nowrap; text-align: right">17.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.37%</td>
    <td style="white-space: nowrap; text-align: right">16.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.60 K</td>
    <td style="white-space: nowrap; text-align: right">22.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;62.17%</td>
    <td style="white-space: nowrap; text-align: right">21.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">40.01 K</td>
    <td style="white-space: nowrap; text-align: right">24.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.66%</td>
    <td style="white-space: nowrap; text-align: right">22.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">63.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.81 K</td>
    <td style="white-space: nowrap; text-align: right">40.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.03%</td>
    <td style="white-space: nowrap; text-align: right">38.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.36 K</td>
    <td style="white-space: nowrap; text-align: right">49.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.97%</td>
    <td style="white-space: nowrap; text-align: right">47.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">65 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.42 K</td>
    <td style="white-space: nowrap; text-align: right">106.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.20%</td>
    <td style="white-space: nowrap; text-align: right">104.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">129.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.79 K</td>
    <td style="white-space: nowrap; text-align: right">172.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.88%</td>
    <td style="white-space: nowrap; text-align: right">168.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">231.62 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.46 K</td>
    <td style="white-space: nowrap; text-align: right">224.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.50%</td>
    <td style="white-space: nowrap; text-align: right">219.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">273.97 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4279.17 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3922.60 K</td>
    <td style="white-space: nowrap; text-align: right">1.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1439.33 K</td>
    <td style="white-space: nowrap; text-align: right">2.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">112.89 K</td>
    <td style="white-space: nowrap; text-align: right">37.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.77 K</td>
    <td style="white-space: nowrap; text-align: right">38.98x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">93.49 K</td>
    <td style="white-space: nowrap; text-align: right">45.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">89.96 K</td>
    <td style="white-space: nowrap; text-align: right">47.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">66.32 K</td>
    <td style="white-space: nowrap; text-align: right">64.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">63.40 K</td>
    <td style="white-space: nowrap; text-align: right">67.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">62.99 K</td>
    <td style="white-space: nowrap; text-align: right">67.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">57.08 K</td>
    <td style="white-space: nowrap; text-align: right">74.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.60 K</td>
    <td style="white-space: nowrap; text-align: right">98.14x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">40.01 K</td>
    <td style="white-space: nowrap; text-align: right">106.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.81 K</td>
    <td style="white-space: nowrap; text-align: right">172.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.36 K</td>
    <td style="white-space: nowrap; text-align: right">210.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.42 K</td>
    <td style="white-space: nowrap; text-align: right">454.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.79 K</td>
    <td style="white-space: nowrap; text-align: right">738.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.46 K</td>
    <td style="white-space: nowrap; text-align: right">959.37x</td>
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