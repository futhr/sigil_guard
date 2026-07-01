Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-07-01 13:03:06.013467Z
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
    <td style="white-space: nowrap; text-align: right">4285.36 K</td>
    <td style="white-space: nowrap; text-align: right">0.23 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1588.46%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3955.22 K</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1104.85%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1550.82 K</td>
    <td style="white-space: nowrap; text-align: right">0.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;609.41%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / canonical bytes</td>
    <td style="white-space: nowrap; text-align: right">417.21 K</td>
    <td style="white-space: nowrap; text-align: right">2.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;181.87%</td>
    <td style="white-space: nowrap; text-align: right">2.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / digest</td>
    <td style="white-space: nowrap; text-align: right">376.15 K</td>
    <td style="white-space: nowrap; text-align: right">2.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;201.15%</td>
    <td style="white-space: nowrap; text-align: right">2.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">295.93 K</td>
    <td style="white-space: nowrap; text-align: right">3.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;120.63%</td>
    <td style="white-space: nowrap; text-align: right">3.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">258.80 K</td>
    <td style="white-space: nowrap; text-align: right">3.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;153.45%</td>
    <td style="white-space: nowrap; text-align: right">3.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">250.48 K</td>
    <td style="white-space: nowrap; text-align: right">3.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;108.74%</td>
    <td style="white-space: nowrap; text-align: right">3.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">240.05 K</td>
    <td style="white-space: nowrap; text-align: right">4.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;123.64%</td>
    <td style="white-space: nowrap; text-align: right">3.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">219.53 K</td>
    <td style="white-space: nowrap; text-align: right">4.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;233.44%</td>
    <td style="white-space: nowrap; text-align: right">3.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">9.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">164.26 K</td>
    <td style="white-space: nowrap; text-align: right">6.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;133.75%</td>
    <td style="white-space: nowrap; text-align: right">5.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">13.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">164.05 K</td>
    <td style="white-space: nowrap; text-align: right">6.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;128.03%</td>
    <td style="white-space: nowrap; text-align: right">5.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">118.15 K</td>
    <td style="white-space: nowrap; text-align: right">8.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;39.18%</td>
    <td style="white-space: nowrap; text-align: right">7.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">16.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">112.18 K</td>
    <td style="white-space: nowrap; text-align: right">8.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;56.83%</td>
    <td style="white-space: nowrap; text-align: right">8.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">109.28 K</td>
    <td style="white-space: nowrap; text-align: right">9.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.31%</td>
    <td style="white-space: nowrap; text-align: right">8.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">108.97 K</td>
    <td style="white-space: nowrap; text-align: right">9.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;73.31%</td>
    <td style="white-space: nowrap; text-align: right">8.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">29.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">103.09 K</td>
    <td style="white-space: nowrap; text-align: right">9.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.19%</td>
    <td style="white-space: nowrap; text-align: right">9.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">95.24 K</td>
    <td style="white-space: nowrap; text-align: right">10.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.35%</td>
    <td style="white-space: nowrap; text-align: right">9.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">92.07 K</td>
    <td style="white-space: nowrap; text-align: right">10.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;72.55%</td>
    <td style="white-space: nowrap; text-align: right">9.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">88.41 K</td>
    <td style="white-space: nowrap; text-align: right">11.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.15%</td>
    <td style="white-space: nowrap; text-align: right">10.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">85.55 K</td>
    <td style="white-space: nowrap; text-align: right">11.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;31.45%</td>
    <td style="white-space: nowrap; text-align: right">11.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">63.55 K</td>
    <td style="white-space: nowrap; text-align: right">15.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;33.22%</td>
    <td style="white-space: nowrap; text-align: right">14.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">51.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">61.24 K</td>
    <td style="white-space: nowrap; text-align: right">16.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.18%</td>
    <td style="white-space: nowrap; text-align: right">15.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.66 K</td>
    <td style="white-space: nowrap; text-align: right">16.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.66%</td>
    <td style="white-space: nowrap; text-align: right">15.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">30.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">44.26 K</td>
    <td style="white-space: nowrap; text-align: right">22.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.10%</td>
    <td style="white-space: nowrap; text-align: right">21.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">40.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">40.54 K</td>
    <td style="white-space: nowrap; text-align: right">24.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.93%</td>
    <td style="white-space: nowrap; text-align: right">24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">35.47 K</td>
    <td style="white-space: nowrap; text-align: right">28.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.54%</td>
    <td style="white-space: nowrap; text-align: right">26.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">40.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">35.45 K</td>
    <td style="white-space: nowrap; text-align: right">28.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.55%</td>
    <td style="white-space: nowrap; text-align: right">27.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">31.21 K</td>
    <td style="white-space: nowrap; text-align: right">32.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.71%</td>
    <td style="white-space: nowrap; text-align: right">31.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.99 K</td>
    <td style="white-space: nowrap; text-align: right">35.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.51%</td>
    <td style="white-space: nowrap; text-align: right">32.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.75 K</td>
    <td style="white-space: nowrap; text-align: right">37.39 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.73%</td>
    <td style="white-space: nowrap; text-align: right">33.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">73.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.60 K</td>
    <td style="white-space: nowrap; text-align: right">40.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.29%</td>
    <td style="white-space: nowrap; text-align: right">39.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">23.26 K</td>
    <td style="white-space: nowrap; text-align: right">42.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.93%</td>
    <td style="white-space: nowrap; text-align: right">41.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / verify signed</td>
    <td style="white-space: nowrap; text-align: right">21.66 K</td>
    <td style="white-space: nowrap; text-align: right">46.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.94%</td>
    <td style="white-space: nowrap; text-align: right">45.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">58.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap; text-align: right">20.98 K</td>
    <td style="white-space: nowrap; text-align: right">47.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.43%</td>
    <td style="white-space: nowrap; text-align: right">46.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.97 K</td>
    <td style="white-space: nowrap; text-align: right">50.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.39%</td>
    <td style="white-space: nowrap; text-align: right">49.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.44 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">18.90 K</td>
    <td style="white-space: nowrap; text-align: right">52.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.01%</td>
    <td style="white-space: nowrap; text-align: right">52.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / sign</td>
    <td style="white-space: nowrap; text-align: right">18.72 K</td>
    <td style="white-space: nowrap; text-align: right">53.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.59%</td>
    <td style="white-space: nowrap; text-align: right">52.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">17.92 K</td>
    <td style="white-space: nowrap; text-align: right">55.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.03%</td>
    <td style="white-space: nowrap; text-align: right">54.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">83.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.78 K</td>
    <td style="white-space: nowrap; text-align: right">56.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.77%</td>
    <td style="white-space: nowrap; text-align: right">56.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">69.90 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">17.69 K</td>
    <td style="white-space: nowrap; text-align: right">56.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.78%</td>
    <td style="white-space: nowrap; text-align: right">55.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">17.29 K</td>
    <td style="white-space: nowrap; text-align: right">57.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.51%</td>
    <td style="white-space: nowrap; text-align: right">56.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.35 K</td>
    <td style="white-space: nowrap; text-align: right">61.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.04%</td>
    <td style="white-space: nowrap; text-align: right">59.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap; text-align: right">15.59 K</td>
    <td style="white-space: nowrap; text-align: right">64.15 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.11%</td>
    <td style="white-space: nowrap; text-align: right">62.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">92.18 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.51 K</td>
    <td style="white-space: nowrap; text-align: right">68.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.72%</td>
    <td style="white-space: nowrap; text-align: right">67.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">84.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">13.15 K</td>
    <td style="white-space: nowrap; text-align: right">76.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.78%</td>
    <td style="white-space: nowrap; text-align: right">74.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">93.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.93 K</td>
    <td style="white-space: nowrap; text-align: right">91.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.79%</td>
    <td style="white-space: nowrap; text-align: right">89.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">114.31 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">10.03 K</td>
    <td style="white-space: nowrap; text-align: right">99.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.93%</td>
    <td style="white-space: nowrap; text-align: right">97.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">124.65 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.68 K</td>
    <td style="white-space: nowrap; text-align: right">103.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.20%</td>
    <td style="white-space: nowrap; text-align: right">102.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">125.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.97 K</td>
    <td style="white-space: nowrap; text-align: right">111.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.43%</td>
    <td style="white-space: nowrap; text-align: right">108.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">134.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.79 K</td>
    <td style="white-space: nowrap; text-align: right">172.70 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.54%</td>
    <td style="white-space: nowrap; text-align: right">168.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">242.01 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.41 K</td>
    <td style="white-space: nowrap; text-align: right">226.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.80%</td>
    <td style="white-space: nowrap; text-align: right">223.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">274.38 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4285.36 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3955.22 K</td>
    <td style="white-space: nowrap; text-align: right">1.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1550.82 K</td>
    <td style="white-space: nowrap; text-align: right">2.76x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / canonical bytes</td>
    <td style="white-space: nowrap; text-align: right">417.21 K</td>
    <td style="white-space: nowrap; text-align: right">10.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / digest</td>
    <td style="white-space: nowrap; text-align: right">376.15 K</td>
    <td style="white-space: nowrap; text-align: right">11.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">295.93 K</td>
    <td style="white-space: nowrap; text-align: right">14.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / digest 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">258.80 K</td>
    <td style="white-space: nowrap; text-align: right">16.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">250.48 K</td>
    <td style="white-space: nowrap; text-align: right">17.11x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / create 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">240.05 K</td>
    <td style="white-space: nowrap; text-align: right">17.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">219.53 K</td>
    <td style="white-space: nowrap; text-align: right">19.52x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">164.26 K</td>
    <td style="white-space: nowrap; text-align: right">26.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">164.05 K</td>
    <td style="white-space: nowrap; text-align: right">26.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap; text-align: right">118.15 K</td>
    <td style="white-space: nowrap; text-align: right">36.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">112.18 K</td>
    <td style="white-space: nowrap; text-align: right">38.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">109.28 K</td>
    <td style="white-space: nowrap; text-align: right">39.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">108.97 K</td>
    <td style="white-space: nowrap; text-align: right">39.33x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">103.09 K</td>
    <td style="white-space: nowrap; text-align: right">41.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">95.24 K</td>
    <td style="white-space: nowrap; text-align: right">44.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">92.07 K</td>
    <td style="white-space: nowrap; text-align: right">46.55x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">88.41 K</td>
    <td style="white-space: nowrap; text-align: right">48.47x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">85.55 K</td>
    <td style="white-space: nowrap; text-align: right">50.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">63.55 K</td>
    <td style="white-space: nowrap; text-align: right">67.43x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">61.24 K</td>
    <td style="white-space: nowrap; text-align: right">69.98x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">59.66 K</td>
    <td style="white-space: nowrap; text-align: right">71.83x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">44.26 K</td>
    <td style="white-space: nowrap; text-align: right">96.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">40.54 K</td>
    <td style="white-space: nowrap; text-align: right">105.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">35.47 K</td>
    <td style="white-space: nowrap; text-align: right">120.81x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">35.45 K</td>
    <td style="white-space: nowrap; text-align: right">120.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap; text-align: right">31.21 K</td>
    <td style="white-space: nowrap; text-align: right">137.33x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.99 K</td>
    <td style="white-space: nowrap; text-align: right">153.12x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.75 K</td>
    <td style="white-space: nowrap; text-align: right">160.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.60 K</td>
    <td style="white-space: nowrap; text-align: right">174.2x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">23.26 K</td>
    <td style="white-space: nowrap; text-align: right">184.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / verify signed</td>
    <td style="white-space: nowrap; text-align: right">21.66 K</td>
    <td style="white-space: nowrap; text-align: right">197.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap; text-align: right">20.98 K</td>
    <td style="white-space: nowrap; text-align: right">204.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.97 K</td>
    <td style="white-space: nowrap; text-align: right">214.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">18.90 K</td>
    <td style="white-space: nowrap; text-align: right">226.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor receipt / sign</td>
    <td style="white-space: nowrap; text-align: right">18.72 K</td>
    <td style="white-space: nowrap; text-align: right">228.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">17.92 K</td>
    <td style="white-space: nowrap; text-align: right">239.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">17.78 K</td>
    <td style="white-space: nowrap; text-align: right">241.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap; text-align: right">17.69 K</td>
    <td style="white-space: nowrap; text-align: right">242.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap; text-align: right">17.29 K</td>
    <td style="white-space: nowrap; text-align: right">247.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">16.35 K</td>
    <td style="white-space: nowrap; text-align: right">262.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap; text-align: right">15.59 K</td>
    <td style="white-space: nowrap; text-align: right">274.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.51 K</td>
    <td style="white-space: nowrap; text-align: right">295.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap; text-align: right">13.15 K</td>
    <td style="white-space: nowrap; text-align: right">325.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.93 K</td>
    <td style="white-space: nowrap; text-align: right">392.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">10.03 K</td>
    <td style="white-space: nowrap; text-align: right">427.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">9.68 K</td>
    <td style="white-space: nowrap; text-align: right">442.53x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.97 K</td>
    <td style="white-space: nowrap; text-align: right">477.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.79 K</td>
    <td style="white-space: nowrap; text-align: right">740.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.41 K</td>
    <td style="white-space: nowrap; text-align: right">971.93x</td>
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
    <td style="white-space: nowrap">5.60 KB</td>
    <td>29.88x</td>
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
    <td style="white-space: nowrap">8.60 KB</td>
    <td>45.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.20 KB</td>
    <td>22.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.49 KB</td>
    <td>29.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.83 KB</td>
    <td>41.75x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor / verify 100 checkpoint</td>
    <td style="white-space: nowrap">18.28 KB</td>
    <td>97.5x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap">9.80 KB</td>
    <td>52.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap">27.41 KB</td>
    <td>146.21x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">8.38 KB</td>
    <td>44.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>147.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.32 KB</td>
    <td>124.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">11.82 KB</td>
    <td>63.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap">11.45 KB</td>
    <td>61.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap">29.76 KB</td>
    <td>158.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">19.07 KB</td>
    <td>101.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap">13.82 KB</td>
    <td>73.71x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.45 KB</td>
    <td>93.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.34 KB</td>
    <td>385.79x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap">12.02 KB</td>
    <td>64.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">64.90 KB</td>
    <td>346.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">60 KB</td>
    <td>320.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed request</td>
    <td style="white-space: nowrap">57.48 KB</td>
    <td>306.58x</td>
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
    <td style="white-space: nowrap">35.25 KB</td>
    <td>188.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor receipt / verify signed</td>
    <td style="white-space: nowrap">19.67 KB</td>
    <td>104.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor store / local fetch</td>
    <td style="white-space: nowrap">26.82 KB</td>
    <td>143.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.77 KB</td>
    <td>14.77x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap">16.12 KB</td>
    <td>85.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor receipt / sign</td>
    <td style="white-space: nowrap">13.19 KB</td>
    <td>70.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.50 KB</td>
    <td>178.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>96.04x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / guarded stream result</td>
    <td style="white-space: nowrap">32.62 KB</td>
    <td>173.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / confirmed result release</td>
    <td style="white-space: nowrap">76.20 KB</td>
    <td>406.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap">63.23 KB</td>
    <td>337.25x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit anchor store / local verify</td>
    <td style="white-space: nowrap">48.65 KB</td>
    <td>259.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed confirmed request</td>
    <td style="white-space: nowrap">64.75 KB</td>
    <td>345.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap">74.89 KB</td>
    <td>399.42x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap">68.48 KB</td>
    <td>365.25x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.20 KB</td>
    <td>22.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap">117.21 KB</td>
    <td>625.13x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap">174.24 KB</td>
    <td>929.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap">722.73 KB</td>
    <td>3854.54x</td>
  </tr>
</table>