Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 21:03:30.093079Z
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
    <td style="white-space: nowrap; text-align: right">3961.21 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1545.49%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3230.04 K</td>
    <td style="white-space: nowrap; text-align: right">0.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1343.29%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1569.04 K</td>
    <td style="white-space: nowrap; text-align: right">0.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;615.62%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">280.12 K</td>
    <td style="white-space: nowrap; text-align: right">3.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;97.49%</td>
    <td style="white-space: nowrap; text-align: right">3.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">232.56 K</td>
    <td style="white-space: nowrap; text-align: right">4.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;116.97%</td>
    <td style="white-space: nowrap; text-align: right">4.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">111.67 K</td>
    <td style="white-space: nowrap; text-align: right">8.95 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;66.59%</td>
    <td style="white-space: nowrap; text-align: right">8.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">15.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">107.88 K</td>
    <td style="white-space: nowrap; text-align: right">9.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;83.31%</td>
    <td style="white-space: nowrap; text-align: right">8.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">103.50 K</td>
    <td style="white-space: nowrap; text-align: right">9.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;37.78%</td>
    <td style="white-space: nowrap; text-align: right">9.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">98.62 K</td>
    <td style="white-space: nowrap; text-align: right">10.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.69%</td>
    <td style="white-space: nowrap; text-align: right">9.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">91.23 K</td>
    <td style="white-space: nowrap; text-align: right">10.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;46.39%</td>
    <td style="white-space: nowrap; text-align: right">10.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">88.21 K</td>
    <td style="white-space: nowrap; text-align: right">11.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.53%</td>
    <td style="white-space: nowrap; text-align: right">10.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">86.42 K</td>
    <td style="white-space: nowrap; text-align: right">11.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;63.65%</td>
    <td style="white-space: nowrap; text-align: right">10.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">83.40 K</td>
    <td style="white-space: nowrap; text-align: right">11.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.44%</td>
    <td style="white-space: nowrap; text-align: right">11.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">78.68 K</td>
    <td style="white-space: nowrap; text-align: right">12.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.18%</td>
    <td style="white-space: nowrap; text-align: right">12.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.34 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">71.62 K</td>
    <td style="white-space: nowrap; text-align: right">13.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.36%</td>
    <td style="white-space: nowrap; text-align: right">13.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">61.01 K</td>
    <td style="white-space: nowrap; text-align: right">16.39 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;61.62%</td>
    <td style="white-space: nowrap; text-align: right">15.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">37.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">55.75 K</td>
    <td style="white-space: nowrap; text-align: right">17.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.20%</td>
    <td style="white-space: nowrap; text-align: right">17.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.94 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">55.13 K</td>
    <td style="white-space: nowrap; text-align: right">18.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;97.56%</td>
    <td style="white-space: nowrap; text-align: right">15.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.59 K</td>
    <td style="white-space: nowrap; text-align: right">22.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.85%</td>
    <td style="white-space: nowrap; text-align: right">21.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">39.07 K</td>
    <td style="white-space: nowrap; text-align: right">25.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.19%</td>
    <td style="white-space: nowrap; text-align: right">24.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">61.52 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">38.65 K</td>
    <td style="white-space: nowrap; text-align: right">25.87 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.00%</td>
    <td style="white-space: nowrap; text-align: right">24.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">28.89 K</td>
    <td style="white-space: nowrap; text-align: right">34.62 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.94%</td>
    <td style="white-space: nowrap; text-align: right">33.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">46.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">28.26 K</td>
    <td style="white-space: nowrap; text-align: right">35.39 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.98%</td>
    <td style="white-space: nowrap; text-align: right">34.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.29 K</td>
    <td style="white-space: nowrap; text-align: right">38.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.42%</td>
    <td style="white-space: nowrap; text-align: right">34.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">76.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.14 K</td>
    <td style="white-space: nowrap; text-align: right">39.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.25%</td>
    <td style="white-space: nowrap; text-align: right">36.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">79.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.89 K</td>
    <td style="white-space: nowrap; text-align: right">43.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.79%</td>
    <td style="white-space: nowrap; text-align: right">43.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.86 K</td>
    <td style="white-space: nowrap; text-align: right">50.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.38%</td>
    <td style="white-space: nowrap; text-align: right">48.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">78.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.22 K</td>
    <td style="white-space: nowrap; text-align: right">52.03 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.74%</td>
    <td style="white-space: nowrap; text-align: right">51.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">64.80 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.88 K</td>
    <td style="white-space: nowrap; text-align: right">59.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.65%</td>
    <td style="white-space: nowrap; text-align: right">58.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.00 K</td>
    <td style="white-space: nowrap; text-align: right">66.68 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.63%</td>
    <td style="white-space: nowrap; text-align: right">65.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">83.64 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.29 K</td>
    <td style="white-space: nowrap; text-align: right">69.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.22%</td>
    <td style="white-space: nowrap; text-align: right">70.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">82.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">14.03 K</td>
    <td style="white-space: nowrap; text-align: right">71.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.17%</td>
    <td style="white-space: nowrap; text-align: right">70.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">93.73 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.30 K</td>
    <td style="white-space: nowrap; text-align: right">75.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.35%</td>
    <td style="white-space: nowrap; text-align: right">73.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">99.66 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.14 K</td>
    <td style="white-space: nowrap; text-align: right">98.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.45%</td>
    <td style="white-space: nowrap; text-align: right">98.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">128.09 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.32 K</td>
    <td style="white-space: nowrap; text-align: right">120.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.95%</td>
    <td style="white-space: nowrap; text-align: right">118.84 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">150.32 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.48 K</td>
    <td style="white-space: nowrap; text-align: right">182.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.71%</td>
    <td style="white-space: nowrap; text-align: right">178.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">257.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.11 K</td>
    <td style="white-space: nowrap; text-align: right">243.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.99%</td>
    <td style="white-space: nowrap; text-align: right">241.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">303.58 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3961.21 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3230.04 K</td>
    <td style="white-space: nowrap; text-align: right">1.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1569.04 K</td>
    <td style="white-space: nowrap; text-align: right">2.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">280.12 K</td>
    <td style="white-space: nowrap; text-align: right">14.14x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">232.56 K</td>
    <td style="white-space: nowrap; text-align: right">17.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">111.67 K</td>
    <td style="white-space: nowrap; text-align: right">35.47x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">107.88 K</td>
    <td style="white-space: nowrap; text-align: right">36.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">103.50 K</td>
    <td style="white-space: nowrap; text-align: right">38.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">98.62 K</td>
    <td style="white-space: nowrap; text-align: right">40.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">91.23 K</td>
    <td style="white-space: nowrap; text-align: right">43.42x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">88.21 K</td>
    <td style="white-space: nowrap; text-align: right">44.9x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">86.42 K</td>
    <td style="white-space: nowrap; text-align: right">45.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">83.40 K</td>
    <td style="white-space: nowrap; text-align: right">47.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">78.68 K</td>
    <td style="white-space: nowrap; text-align: right">50.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">71.62 K</td>
    <td style="white-space: nowrap; text-align: right">55.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">61.01 K</td>
    <td style="white-space: nowrap; text-align: right">64.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">55.75 K</td>
    <td style="white-space: nowrap; text-align: right">71.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">55.13 K</td>
    <td style="white-space: nowrap; text-align: right">71.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">44.59 K</td>
    <td style="white-space: nowrap; text-align: right">88.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">39.07 K</td>
    <td style="white-space: nowrap; text-align: right">101.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">38.65 K</td>
    <td style="white-space: nowrap; text-align: right">102.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">28.89 K</td>
    <td style="white-space: nowrap; text-align: right">137.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">28.26 K</td>
    <td style="white-space: nowrap; text-align: right">140.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">26.29 K</td>
    <td style="white-space: nowrap; text-align: right">150.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.14 K</td>
    <td style="white-space: nowrap; text-align: right">157.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.89 K</td>
    <td style="white-space: nowrap; text-align: right">173.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.86 K</td>
    <td style="white-space: nowrap; text-align: right">199.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.22 K</td>
    <td style="white-space: nowrap; text-align: right">206.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.88 K</td>
    <td style="white-space: nowrap; text-align: right">234.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.00 K</td>
    <td style="white-space: nowrap; text-align: right">264.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.29 K</td>
    <td style="white-space: nowrap; text-align: right">277.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">14.03 K</td>
    <td style="white-space: nowrap; text-align: right">282.37x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.30 K</td>
    <td style="white-space: nowrap; text-align: right">297.79x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.14 K</td>
    <td style="white-space: nowrap; text-align: right">390.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.32 K</td>
    <td style="white-space: nowrap; text-align: right">475.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.48 K</td>
    <td style="white-space: nowrap; text-align: right">722.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.11 K</td>
    <td style="white-space: nowrap; text-align: right">964.92x</td>
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
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>147.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap">27.41 KB</td>
    <td>146.21x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.77 KB</td>
    <td>41.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.32 KB</td>
    <td>124.38x</td>
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
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap">29.76 KB</td>
    <td>158.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">8.34 KB</td>
    <td>44.5x</td>
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
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">12.02 KB</td>
    <td>64.08x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">16.90 KB</td>
    <td>90.13x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">51.73 KB</td>
    <td>275.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">68.59 KB</td>
    <td>365.79x</td>
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
    <td style="white-space: nowrap">35.75 KB</td>
    <td>190.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.76 KB</td>
    <td>14.72x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>96.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap">62.88 KB</td>
    <td>335.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap">15.74 KB</td>
    <td>83.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.29 KB</td>
    <td>177.54x</td>
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