Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-07-01 10:26:00.360688Z
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
    <td style="white-space: nowrap; text-align: right">4340.05 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1643.98%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3981.11 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1118.88%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1483.06 K</td>
    <td style="white-space: nowrap; text-align: right">0.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;585.97%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / canonical bytes</td>
    <td style="white-space: nowrap; text-align: right">400.59 K</td>
    <td style="white-space: nowrap; text-align: right">2.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;162.50%</td>
    <td style="white-space: nowrap; text-align: right">2.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / digest</td>
    <td style="white-space: nowrap; text-align: right">366.25 K</td>
    <td style="white-space: nowrap; text-align: right">2.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;202.13%</td>
    <td style="white-space: nowrap; text-align: right">2.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">305.81 K</td>
    <td style="white-space: nowrap; text-align: right">3.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;103.40%</td>
    <td style="white-space: nowrap; text-align: right">3.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">249.49 K</td>
    <td style="white-space: nowrap; text-align: right">4.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;148.16%</td>
    <td style="white-space: nowrap; text-align: right">3.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">9.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">247.05 K</td>
    <td style="white-space: nowrap; text-align: right">4.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;110.46%</td>
    <td style="white-space: nowrap; text-align: right">3.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">235.36 K</td>
    <td style="white-space: nowrap; text-align: right">4.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;136.23%</td>
    <td style="white-space: nowrap; text-align: right">3.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">115.51 K</td>
    <td style="white-space: nowrap; text-align: right">8.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;44.32%</td>
    <td style="white-space: nowrap; text-align: right">7.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">108.95 K</td>
    <td style="white-space: nowrap; text-align: right">9.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.21%</td>
    <td style="white-space: nowrap; text-align: right">8.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">108.24 K</td>
    <td style="white-space: nowrap; text-align: right">9.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.99%</td>
    <td style="white-space: nowrap; text-align: right">8.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">107.45 K</td>
    <td style="white-space: nowrap; text-align: right">9.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;69.78%</td>
    <td style="white-space: nowrap; text-align: right">8.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">102.07 K</td>
    <td style="white-space: nowrap; text-align: right">9.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.78%</td>
    <td style="white-space: nowrap; text-align: right">9.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">92.19 K</td>
    <td style="white-space: nowrap; text-align: right">10.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.63%</td>
    <td style="white-space: nowrap; text-align: right">10.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">91.56 K</td>
    <td style="white-space: nowrap; text-align: right">10.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.60%</td>
    <td style="white-space: nowrap; text-align: right">10.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">90.59 K</td>
    <td style="white-space: nowrap; text-align: right">11.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;43.66%</td>
    <td style="white-space: nowrap; text-align: right">10.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">28.49 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">85.39 K</td>
    <td style="white-space: nowrap; text-align: right">11.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.52%</td>
    <td style="white-space: nowrap; text-align: right">10.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.80 K</td>
    <td style="white-space: nowrap; text-align: right">13.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.04%</td>
    <td style="white-space: nowrap; text-align: right">12.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">71.91 K</td>
    <td style="white-space: nowrap; text-align: right">13.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.52%</td>
    <td style="white-space: nowrap; text-align: right">13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">63.63 K</td>
    <td style="white-space: nowrap; text-align: right">15.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;32.40%</td>
    <td style="white-space: nowrap; text-align: right">14.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">60.12 K</td>
    <td style="white-space: nowrap; text-align: right">16.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.13%</td>
    <td style="white-space: nowrap; text-align: right">15.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">37.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.19 K</td>
    <td style="white-space: nowrap; text-align: right">16.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.21%</td>
    <td style="white-space: nowrap; text-align: right">15.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">38.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">45.09 K</td>
    <td style="white-space: nowrap; text-align: right">22.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.58%</td>
    <td style="white-space: nowrap; text-align: right">20.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">40.56 K</td>
    <td style="white-space: nowrap; text-align: right">24.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.07%</td>
    <td style="white-space: nowrap; text-align: right">23.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.50 K</td>
    <td style="white-space: nowrap; text-align: right">24.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.79%</td>
    <td style="white-space: nowrap; text-align: right">23.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.20 K</td>
    <td style="white-space: nowrap; text-align: right">33.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.83%</td>
    <td style="white-space: nowrap; text-align: right">32.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.83 K</td>
    <td style="white-space: nowrap; text-align: right">35.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.39%</td>
    <td style="white-space: nowrap; text-align: right">31.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.76 K</td>
    <td style="white-space: nowrap; text-align: right">37.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.54%</td>
    <td style="white-space: nowrap; text-align: right">35.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">51.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.62 K</td>
    <td style="white-space: nowrap; text-align: right">37.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.70%</td>
    <td style="white-space: nowrap; text-align: right">32.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">24.72 K</td>
    <td style="white-space: nowrap; text-align: right">40.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;61.59%</td>
    <td style="white-space: nowrap; text-align: right">37.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">93.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.72 K</td>
    <td style="white-space: nowrap; text-align: right">40.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.19%</td>
    <td style="white-space: nowrap; text-align: right">38.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.78 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap; text-align: right">21.13 K</td>
    <td style="white-space: nowrap; text-align: right">47.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.58%</td>
    <td style="white-space: nowrap; text-align: right">46.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">67.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.64 K</td>
    <td style="white-space: nowrap; text-align: right">48.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.60%</td>
    <td style="white-space: nowrap; text-align: right">45.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / verify signed</td>
    <td style="white-space: nowrap; text-align: right">18.75 K</td>
    <td style="white-space: nowrap; text-align: right">53.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;51.30%</td>
    <td style="white-space: nowrap; text-align: right">49.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">162.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / sign</td>
    <td style="white-space: nowrap; text-align: right">18.17 K</td>
    <td style="white-space: nowrap; text-align: right">55.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.39%</td>
    <td style="white-space: nowrap; text-align: right">54.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">68.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">17.74 K</td>
    <td style="white-space: nowrap; text-align: right">56.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.59%</td>
    <td style="white-space: nowrap; text-align: right">54.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">158.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">16.86 K</td>
    <td style="white-space: nowrap; text-align: right">59.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.20%</td>
    <td style="white-space: nowrap; text-align: right">59.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.37 K</td>
    <td style="white-space: nowrap; text-align: right">61.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.97%</td>
    <td style="white-space: nowrap; text-align: right">59.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">76.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap; text-align: right">15.02 K</td>
    <td style="white-space: nowrap; text-align: right">66.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.43%</td>
    <td style="white-space: nowrap; text-align: right">65.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">90.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">14.78 K</td>
    <td style="white-space: nowrap; text-align: right">67.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.18%</td>
    <td style="white-space: nowrap; text-align: right">61.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">192.69 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.50 K</td>
    <td style="white-space: nowrap; text-align: right">68.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.15%</td>
    <td style="white-space: nowrap; text-align: right">67.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">85.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">14.26 K</td>
    <td style="white-space: nowrap; text-align: right">70.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;19.35%</td>
    <td style="white-space: nowrap; text-align: right">67.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">113.06 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.12 K</td>
    <td style="white-space: nowrap; text-align: right">70.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.45%</td>
    <td style="white-space: nowrap; text-align: right">68.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">92.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.03 K</td>
    <td style="white-space: nowrap; text-align: right">71.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.85%</td>
    <td style="white-space: nowrap; text-align: right">69.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">92.82 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.15 K</td>
    <td style="white-space: nowrap; text-align: right">82.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.70%</td>
    <td style="white-space: nowrap; text-align: right">79.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">111.43 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.06 K</td>
    <td style="white-space: nowrap; text-align: right">99.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.32%</td>
    <td style="white-space: nowrap; text-align: right">97.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">131.34 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.60 K</td>
    <td style="white-space: nowrap; text-align: right">104.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.43%</td>
    <td style="white-space: nowrap; text-align: right">103.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">136.09 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.91 K</td>
    <td style="white-space: nowrap; text-align: right">112.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.78%</td>
    <td style="white-space: nowrap; text-align: right">109.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">138.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.07 K</td>
    <td style="white-space: nowrap; text-align: right">123.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.30%</td>
    <td style="white-space: nowrap; text-align: right">119.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">303.69 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.61 K</td>
    <td style="white-space: nowrap; text-align: right">178.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.66%</td>
    <td style="white-space: nowrap; text-align: right">175.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">254.09 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.41 K</td>
    <td style="white-space: nowrap; text-align: right">226.97 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.86%</td>
    <td style="white-space: nowrap; text-align: right">222.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">270.98 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4340.05 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3981.11 K</td>
    <td style="white-space: nowrap; text-align: right">1.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1483.06 K</td>
    <td style="white-space: nowrap; text-align: right">2.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / canonical bytes</td>
    <td style="white-space: nowrap; text-align: right">400.59 K</td>
    <td style="white-space: nowrap; text-align: right">10.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / digest</td>
    <td style="white-space: nowrap; text-align: right">366.25 K</td>
    <td style="white-space: nowrap; text-align: right">11.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">305.81 K</td>
    <td style="white-space: nowrap; text-align: right">14.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">249.49 K</td>
    <td style="white-space: nowrap; text-align: right">17.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">247.05 K</td>
    <td style="white-space: nowrap; text-align: right">17.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">235.36 K</td>
    <td style="white-space: nowrap; text-align: right">18.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">115.51 K</td>
    <td style="white-space: nowrap; text-align: right">37.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">108.95 K</td>
    <td style="white-space: nowrap; text-align: right">39.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">108.24 K</td>
    <td style="white-space: nowrap; text-align: right">40.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">107.45 K</td>
    <td style="white-space: nowrap; text-align: right">40.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">102.07 K</td>
    <td style="white-space: nowrap; text-align: right">42.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">92.19 K</td>
    <td style="white-space: nowrap; text-align: right">47.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">91.56 K</td>
    <td style="white-space: nowrap; text-align: right">47.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">90.59 K</td>
    <td style="white-space: nowrap; text-align: right">47.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">85.39 K</td>
    <td style="white-space: nowrap; text-align: right">50.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.80 K</td>
    <td style="white-space: nowrap; text-align: right">56.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">71.91 K</td>
    <td style="white-space: nowrap; text-align: right">60.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">63.63 K</td>
    <td style="white-space: nowrap; text-align: right">68.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">60.12 K</td>
    <td style="white-space: nowrap; text-align: right">72.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.19 K</td>
    <td style="white-space: nowrap; text-align: right">73.33x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">45.09 K</td>
    <td style="white-space: nowrap; text-align: right">96.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">40.56 K</td>
    <td style="white-space: nowrap; text-align: right">107.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.50 K</td>
    <td style="white-space: nowrap; text-align: right">107.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.20 K</td>
    <td style="white-space: nowrap; text-align: right">143.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.83 K</td>
    <td style="white-space: nowrap; text-align: right">155.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.76 K</td>
    <td style="white-space: nowrap; text-align: right">162.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.62 K</td>
    <td style="white-space: nowrap; text-align: right">163.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">24.72 K</td>
    <td style="white-space: nowrap; text-align: right">175.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.72 K</td>
    <td style="white-space: nowrap; text-align: right">175.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap; text-align: right">21.13 K</td>
    <td style="white-space: nowrap; text-align: right">205.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.64 K</td>
    <td style="white-space: nowrap; text-align: right">210.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / verify signed</td>
    <td style="white-space: nowrap; text-align: right">18.75 K</td>
    <td style="white-space: nowrap; text-align: right">231.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / sign</td>
    <td style="white-space: nowrap; text-align: right">18.17 K</td>
    <td style="white-space: nowrap; text-align: right">238.79x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">17.74 K</td>
    <td style="white-space: nowrap; text-align: right">244.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">16.86 K</td>
    <td style="white-space: nowrap; text-align: right">257.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.37 K</td>
    <td style="white-space: nowrap; text-align: right">265.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap; text-align: right">15.02 K</td>
    <td style="white-space: nowrap; text-align: right">288.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">14.78 K</td>
    <td style="white-space: nowrap; text-align: right">293.6x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.50 K</td>
    <td style="white-space: nowrap; text-align: right">299.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">14.26 K</td>
    <td style="white-space: nowrap; text-align: right">304.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.12 K</td>
    <td style="white-space: nowrap; text-align: right">307.38x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.03 K</td>
    <td style="white-space: nowrap; text-align: right">309.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.15 K</td>
    <td style="white-space: nowrap; text-align: right">357.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.06 K</td>
    <td style="white-space: nowrap; text-align: right">431.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.60 K</td>
    <td style="white-space: nowrap; text-align: right">452.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.91 K</td>
    <td style="white-space: nowrap; text-align: right">487.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.07 K</td>
    <td style="white-space: nowrap; text-align: right">537.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.61 K</td>
    <td style="white-space: nowrap; text-align: right">773.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.41 K</td>
    <td style="white-space: nowrap; text-align: right">985.04x</td>
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
    <td style="white-space: nowrap">audit anchor receipt / canonical bytes</td>
    <td style="white-space: nowrap">6.16 KB</td>
    <td>32.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor receipt / digest</td>
    <td style="white-space: nowrap">6.31 KB</td>
    <td>33.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap">4.38 KB</td>
    <td>23.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap">8.79 KB</td>
    <td>46.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap">11.18 KB</td>
    <td>59.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap">8.46 KB</td>
    <td>45.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap">17.24 KB</td>
    <td>91.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap">9.55 KB</td>
    <td>50.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap">27.41 KB</td>
    <td>146.21x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.71 KB</td>
    <td>25.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>147.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.91 KB</td>
    <td>31.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.32 KB</td>
    <td>124.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.95 KB</td>
    <td>42.38x</td>
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
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">12.32 KB</td>
    <td>65.71x</td>
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
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">16.97 KB</td>
    <td>90.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap">10.88 KB</td>
    <td>58.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>384.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">51.87 KB</td>
    <td>276.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap">40.66 KB</td>
    <td>216.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap">55.74 KB</td>
    <td>297.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap">40.95 KB</td>
    <td>218.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">69.45 KB</td>
    <td>370.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>10.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap">26.58 KB</td>
    <td>141.75x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.70 KB</td>
    <td>190.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor receipt / verify signed</td>
    <td style="white-space: nowrap">19.52 KB</td>
    <td>104.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor receipt / sign</td>
    <td style="white-space: nowrap">13.19 KB</td>
    <td>70.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.76 KB</td>
    <td>14.72x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap">15.27 KB</td>
    <td>81.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap">62.88 KB</td>
    <td>335.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap">48.02 KB</td>
    <td>256.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>96.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap">75.55 KB</td>
    <td>402.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.76 KB</td>
    <td>180.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap">35.06 KB</td>
    <td>187.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap">63.34 KB</td>
    <td>337.83x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap">74.30 KB</td>
    <td>396.25x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap">68.34 KB</td>
    <td>364.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap">115.90 KB</td>
    <td>618.13x</td>
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