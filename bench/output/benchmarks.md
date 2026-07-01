Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-07-01 08:34:16.115911Z
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
    <td style="white-space: nowrap; text-align: right">4309.86 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1580.15%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3932.25 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1127.08%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1485.94 K</td>
    <td style="white-space: nowrap; text-align: right">0.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;586.97%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">311.34 K</td>
    <td style="white-space: nowrap; text-align: right">3.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;101.01%</td>
    <td style="white-space: nowrap; text-align: right">3.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">251.55 K</td>
    <td style="white-space: nowrap; text-align: right">3.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;149.78%</td>
    <td style="white-space: nowrap; text-align: right">3.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">245.42 K</td>
    <td style="white-space: nowrap; text-align: right">4.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;104.87%</td>
    <td style="white-space: nowrap; text-align: right">3.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">234.73 K</td>
    <td style="white-space: nowrap; text-align: right">4.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;136.57%</td>
    <td style="white-space: nowrap; text-align: right">3.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">116.47 K</td>
    <td style="white-space: nowrap; text-align: right">8.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;44.23%</td>
    <td style="white-space: nowrap; text-align: right">7.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">111.00 K</td>
    <td style="white-space: nowrap; text-align: right">9.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;57.48%</td>
    <td style="white-space: nowrap; text-align: right">8.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.08 K</td>
    <td style="white-space: nowrap; text-align: right">9.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;69.35%</td>
    <td style="white-space: nowrap; text-align: right">8.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">107.74 K</td>
    <td style="white-space: nowrap; text-align: right">9.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;43.64%</td>
    <td style="white-space: nowrap; text-align: right">8.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">102.75 K</td>
    <td style="white-space: nowrap; text-align: right">9.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.00%</td>
    <td style="white-space: nowrap; text-align: right">9.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">93.59 K</td>
    <td style="white-space: nowrap; text-align: right">10.68 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;47.89%</td>
    <td style="white-space: nowrap; text-align: right">10.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">93.49 K</td>
    <td style="white-space: nowrap; text-align: right">10.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.08%</td>
    <td style="white-space: nowrap; text-align: right">10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">92.65 K</td>
    <td style="white-space: nowrap; text-align: right">10.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;43.58%</td>
    <td style="white-space: nowrap; text-align: right">10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">87.06 K</td>
    <td style="white-space: nowrap; text-align: right">11.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.62%</td>
    <td style="white-space: nowrap; text-align: right">10.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">84.09 K</td>
    <td style="white-space: nowrap; text-align: right">11.89 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.80%</td>
    <td style="white-space: nowrap; text-align: right">11.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">72.65 K</td>
    <td style="white-space: nowrap; text-align: right">13.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;32.30%</td>
    <td style="white-space: nowrap; text-align: right">12.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">25.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">64.39 K</td>
    <td style="white-space: nowrap; text-align: right">15.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.82%</td>
    <td style="white-space: nowrap; text-align: right">14.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">60.58 K</td>
    <td style="white-space: nowrap; text-align: right">16.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.70%</td>
    <td style="white-space: nowrap; text-align: right">15.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">37.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">58.87 K</td>
    <td style="white-space: nowrap; text-align: right">16.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.74%</td>
    <td style="white-space: nowrap; text-align: right">15.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">47.90 K</td>
    <td style="white-space: nowrap; text-align: right">20.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.56%</td>
    <td style="white-space: nowrap; text-align: right">19.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.70 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.24 K</td>
    <td style="white-space: nowrap; text-align: right">23.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.30%</td>
    <td style="white-space: nowrap; text-align: right">21.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">40.34 K</td>
    <td style="white-space: nowrap; text-align: right">24.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.93%</td>
    <td style="white-space: nowrap; text-align: right">24.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.33 K</td>
    <td style="white-space: nowrap; text-align: right">32.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.90%</td>
    <td style="white-space: nowrap; text-align: right">32.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">46.61 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">30.17 K</td>
    <td style="white-space: nowrap; text-align: right">33.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.03%</td>
    <td style="white-space: nowrap; text-align: right">32.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.69 K</td>
    <td style="white-space: nowrap; text-align: right">36.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.87%</td>
    <td style="white-space: nowrap; text-align: right">31.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.88 K</td>
    <td style="white-space: nowrap; text-align: right">37.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.98%</td>
    <td style="white-space: nowrap; text-align: right">35.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">50.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.60 K</td>
    <td style="white-space: nowrap; text-align: right">37.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.53%</td>
    <td style="white-space: nowrap; text-align: right">32.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.83 K</td>
    <td style="white-space: nowrap; text-align: right">40.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.25%</td>
    <td style="white-space: nowrap; text-align: right">38.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.91 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap; text-align: right">20.89 K</td>
    <td style="white-space: nowrap; text-align: right">47.87 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.97%</td>
    <td style="white-space: nowrap; text-align: right">47.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.78 K</td>
    <td style="white-space: nowrap; text-align: right">48.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.39%</td>
    <td style="white-space: nowrap; text-align: right">44.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.27 K</td>
    <td style="white-space: nowrap; text-align: right">49.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.22%</td>
    <td style="white-space: nowrap; text-align: right">47.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">63.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.79 K</td>
    <td style="white-space: nowrap; text-align: right">56.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.06%</td>
    <td style="white-space: nowrap; text-align: right">54.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">71.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.24 K</td>
    <td style="white-space: nowrap; text-align: right">58.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.29%</td>
    <td style="white-space: nowrap; text-align: right">56.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.44 K</td>
    <td style="white-space: nowrap; text-align: right">60.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.21%</td>
    <td style="white-space: nowrap; text-align: right">58.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">76.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">15.60 K</td>
    <td style="white-space: nowrap; text-align: right">64.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.96%</td>
    <td style="white-space: nowrap; text-align: right">63.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">84.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap; text-align: right">15.54 K</td>
    <td style="white-space: nowrap; text-align: right">64.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.18%</td>
    <td style="white-space: nowrap; text-align: right">62.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">83.07 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.56 K</td>
    <td style="white-space: nowrap; text-align: right">68.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.02%</td>
    <td style="white-space: nowrap; text-align: right">66.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">85.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.46 K</td>
    <td style="white-space: nowrap; text-align: right">69.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.91%</td>
    <td style="white-space: nowrap; text-align: right">66.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">90.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.26 K</td>
    <td style="white-space: nowrap; text-align: right">70.12 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.20%</td>
    <td style="white-space: nowrap; text-align: right">68.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">90.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.44 K</td>
    <td style="white-space: nowrap; text-align: right">80.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.23%</td>
    <td style="white-space: nowrap; text-align: right">77.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">100 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.09 K</td>
    <td style="white-space: nowrap; text-align: right">99.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.77%</td>
    <td style="white-space: nowrap; text-align: right">97.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">128.73 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.90 K</td>
    <td style="white-space: nowrap; text-align: right">101.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.05%</td>
    <td style="white-space: nowrap; text-align: right">98.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">127.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.22 K</td>
    <td style="white-space: nowrap; text-align: right">108.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.50%</td>
    <td style="white-space: nowrap; text-align: right">106.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">132.49 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.92 K</td>
    <td style="white-space: nowrap; text-align: right">112.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.15%</td>
    <td style="white-space: nowrap; text-align: right">109.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">137.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.65 K</td>
    <td style="white-space: nowrap; text-align: right">176.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.43%</td>
    <td style="white-space: nowrap; text-align: right">172.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">248.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.32 K</td>
    <td style="white-space: nowrap; text-align: right">231.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.83%</td>
    <td style="white-space: nowrap; text-align: right">226.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">277.36 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4309.86 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3932.25 K</td>
    <td style="white-space: nowrap; text-align: right">1.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1485.94 K</td>
    <td style="white-space: nowrap; text-align: right">2.9x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">311.34 K</td>
    <td style="white-space: nowrap; text-align: right">13.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">251.55 K</td>
    <td style="white-space: nowrap; text-align: right">17.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">245.42 K</td>
    <td style="white-space: nowrap; text-align: right">17.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">234.73 K</td>
    <td style="white-space: nowrap; text-align: right">18.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">116.47 K</td>
    <td style="white-space: nowrap; text-align: right">37.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">111.00 K</td>
    <td style="white-space: nowrap; text-align: right">38.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.08 K</td>
    <td style="white-space: nowrap; text-align: right">39.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">107.74 K</td>
    <td style="white-space: nowrap; text-align: right">40.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">102.75 K</td>
    <td style="white-space: nowrap; text-align: right">41.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">93.59 K</td>
    <td style="white-space: nowrap; text-align: right">46.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">93.49 K</td>
    <td style="white-space: nowrap; text-align: right">46.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">92.65 K</td>
    <td style="white-space: nowrap; text-align: right">46.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">87.06 K</td>
    <td style="white-space: nowrap; text-align: right">49.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">84.09 K</td>
    <td style="white-space: nowrap; text-align: right">51.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">72.65 K</td>
    <td style="white-space: nowrap; text-align: right">59.32x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">64.39 K</td>
    <td style="white-space: nowrap; text-align: right">66.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">60.58 K</td>
    <td style="white-space: nowrap; text-align: right">71.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">58.87 K</td>
    <td style="white-space: nowrap; text-align: right">73.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">47.90 K</td>
    <td style="white-space: nowrap; text-align: right">89.98x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">43.24 K</td>
    <td style="white-space: nowrap; text-align: right">99.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">40.34 K</td>
    <td style="white-space: nowrap; text-align: right">106.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.33 K</td>
    <td style="white-space: nowrap; text-align: right">142.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">30.17 K</td>
    <td style="white-space: nowrap; text-align: right">142.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.69 K</td>
    <td style="white-space: nowrap; text-align: right">155.63x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">26.88 K</td>
    <td style="white-space: nowrap; text-align: right">160.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.60 K</td>
    <td style="white-space: nowrap; text-align: right">162.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.83 K</td>
    <td style="white-space: nowrap; text-align: right">173.55x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap; text-align: right">20.89 K</td>
    <td style="white-space: nowrap; text-align: right">206.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.78 K</td>
    <td style="white-space: nowrap; text-align: right">207.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">20.27 K</td>
    <td style="white-space: nowrap; text-align: right">212.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.79 K</td>
    <td style="white-space: nowrap; text-align: right">242.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">17.24 K</td>
    <td style="white-space: nowrap; text-align: right">250.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.44 K</td>
    <td style="white-space: nowrap; text-align: right">262.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">15.60 K</td>
    <td style="white-space: nowrap; text-align: right">276.36x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap; text-align: right">15.54 K</td>
    <td style="white-space: nowrap; text-align: right">277.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.56 K</td>
    <td style="white-space: nowrap; text-align: right">296.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">14.46 K</td>
    <td style="white-space: nowrap; text-align: right">298.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">14.26 K</td>
    <td style="white-space: nowrap; text-align: right">302.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">12.44 K</td>
    <td style="white-space: nowrap; text-align: right">346.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.09 K</td>
    <td style="white-space: nowrap; text-align: right">427.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.90 K</td>
    <td style="white-space: nowrap; text-align: right">435.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.22 K</td>
    <td style="white-space: nowrap; text-align: right">467.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.92 K</td>
    <td style="white-space: nowrap; text-align: right">482.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.65 K</td>
    <td style="white-space: nowrap; text-align: right">762.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.32 K</td>
    <td style="white-space: nowrap; text-align: right">997.99x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.71 KB</td>
    <td>25.13x</td>
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
    <td style="white-space: nowrap">51.87 KB</td>
    <td>276.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">69.45 KB</td>
    <td>370.42x</td>
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
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>10.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap">26.51 KB</td>
    <td>141.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.70 KB</td>
    <td>190.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.77 KB</td>
    <td>14.77x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>96.04x</td>
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
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap">75.55 KB</td>
    <td>402.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap">47.91 KB</td>
    <td>255.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.62 KB</td>
    <td>24.63x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap">115.90 KB</td>
    <td>618.13x</td>
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