Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 21:23:36.515616Z
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
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3746.85 K</td>
    <td style="white-space: nowrap; text-align: right">0.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1191.94%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap; text-align: right">3674.95 K</td>
    <td style="white-space: nowrap; text-align: right">0.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1773.36%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1455.51 K</td>
    <td style="white-space: nowrap; text-align: right">0.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;614.41%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">313.91 K</td>
    <td style="white-space: nowrap; text-align: right">3.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;98.20%</td>
    <td style="white-space: nowrap; text-align: right">3.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">234.11 K</td>
    <td style="white-space: nowrap; text-align: right">4.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;114.85%</td>
    <td style="white-space: nowrap; text-align: right">4 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">103.55 K</td>
    <td style="white-space: nowrap; text-align: right">9.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;62.22%</td>
    <td style="white-space: nowrap; text-align: right">9.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">99.80 K</td>
    <td style="white-space: nowrap; text-align: right">10.02 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;42.88%</td>
    <td style="white-space: nowrap; text-align: right">9.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">99.54 K</td>
    <td style="white-space: nowrap; text-align: right">10.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.41%</td>
    <td style="white-space: nowrap; text-align: right">9.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">92.34 K</td>
    <td style="white-space: nowrap; text-align: right">10.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;147.73%</td>
    <td style="white-space: nowrap; text-align: right">9.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">89.21 K</td>
    <td style="white-space: nowrap; text-align: right">11.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.65%</td>
    <td style="white-space: nowrap; text-align: right">10.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.33 K</td>
    <td style="white-space: nowrap; text-align: right">11.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.36%</td>
    <td style="white-space: nowrap; text-align: right">10.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">30.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.21 K</td>
    <td style="white-space: nowrap; text-align: right">11.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;72.87%</td>
    <td style="white-space: nowrap; text-align: right">11.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">81.52 K</td>
    <td style="white-space: nowrap; text-align: right">12.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;17.04%</td>
    <td style="white-space: nowrap; text-align: right">12.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">80.90 K</td>
    <td style="white-space: nowrap; text-align: right">12.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;62.61%</td>
    <td style="white-space: nowrap; text-align: right">11.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">66.72 K</td>
    <td style="white-space: nowrap; text-align: right">14.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.02%</td>
    <td style="white-space: nowrap; text-align: right">14.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">61.73 K</td>
    <td style="white-space: nowrap; text-align: right">16.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.86%</td>
    <td style="white-space: nowrap; text-align: right">15.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">57.58 K</td>
    <td style="white-space: nowrap; text-align: right">17.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;32.69%</td>
    <td style="white-space: nowrap; text-align: right">16.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">42.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">54.03 K</td>
    <td style="white-space: nowrap; text-align: right">18.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.23%</td>
    <td style="white-space: nowrap; text-align: right">17.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">45.58 K</td>
    <td style="white-space: nowrap; text-align: right">21.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.91%</td>
    <td style="white-space: nowrap; text-align: right">21.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.34 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">41.67 K</td>
    <td style="white-space: nowrap; text-align: right">24.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.21%</td>
    <td style="white-space: nowrap; text-align: right">23.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">38.00 K</td>
    <td style="white-space: nowrap; text-align: right">26.32 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.53%</td>
    <td style="white-space: nowrap; text-align: right">26.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">28.49 K</td>
    <td style="white-space: nowrap; text-align: right">35.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.43%</td>
    <td style="white-space: nowrap; text-align: right">34.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">26.81 K</td>
    <td style="white-space: nowrap; text-align: right">37.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.42%</td>
    <td style="white-space: nowrap; text-align: right">36.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">25.28 K</td>
    <td style="white-space: nowrap; text-align: right">39.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.03%</td>
    <td style="white-space: nowrap; text-align: right">35.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">81.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">24.22 K</td>
    <td style="white-space: nowrap; text-align: right">41.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;29.65%</td>
    <td style="white-space: nowrap; text-align: right">37.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">84.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.94 K</td>
    <td style="white-space: nowrap; text-align: right">43.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.86%</td>
    <td style="white-space: nowrap; text-align: right">43.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">59.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.07 K</td>
    <td style="white-space: nowrap; text-align: right">52.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.97%</td>
    <td style="white-space: nowrap; text-align: right">52.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">18.74 K</td>
    <td style="white-space: nowrap; text-align: right">53.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.39%</td>
    <td style="white-space: nowrap; text-align: right">51.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">85.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.53 K</td>
    <td style="white-space: nowrap; text-align: right">60.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.19%</td>
    <td style="white-space: nowrap; text-align: right">59.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">74.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.25 K</td>
    <td style="white-space: nowrap; text-align: right">65.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.39%</td>
    <td style="white-space: nowrap; text-align: right">65.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">84.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">13.79 K</td>
    <td style="white-space: nowrap; text-align: right">72.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.00%</td>
    <td style="white-space: nowrap; text-align: right">71.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">91.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.76 K</td>
    <td style="white-space: nowrap; text-align: right">72.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.27%</td>
    <td style="white-space: nowrap; text-align: right">72.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">88.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">12.83 K</td>
    <td style="white-space: nowrap; text-align: right">77.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.94%</td>
    <td style="white-space: nowrap; text-align: right">77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">102.93 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.02 K</td>
    <td style="white-space: nowrap; text-align: right">99.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.99%</td>
    <td style="white-space: nowrap; text-align: right">99.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">128.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.12 K</td>
    <td style="white-space: nowrap; text-align: right">109.61 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.61%</td>
    <td style="white-space: nowrap; text-align: right">109.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">133.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.76 K</td>
    <td style="white-space: nowrap; text-align: right">114.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.10%</td>
    <td style="white-space: nowrap; text-align: right">112.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">136.37 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.16 K</td>
    <td style="white-space: nowrap; text-align: right">122.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.58%</td>
    <td style="white-space: nowrap; text-align: right">121.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">156.32 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.16 K</td>
    <td style="white-space: nowrap; text-align: right">193.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.19%</td>
    <td style="white-space: nowrap; text-align: right">190.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">277.70 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">3.97 K</td>
    <td style="white-space: nowrap; text-align: right">252.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.08%</td>
    <td style="white-space: nowrap; text-align: right">253.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">327.74 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3746.85 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir evaluate</td>
    <td style="white-space: nowrap; text-align: right">3674.95 K</td>
    <td style="white-space: nowrap; text-align: right">1.02x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1455.51 K</td>
    <td style="white-space: nowrap; text-align: right">2.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">313.91 K</td>
    <td style="white-space: nowrap; text-align: right">11.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">234.11 K</td>
    <td style="white-space: nowrap; text-align: right">16.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">103.55 K</td>
    <td style="white-space: nowrap; text-align: right">36.19x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">99.80 K</td>
    <td style="white-space: nowrap; text-align: right">37.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">99.54 K</td>
    <td style="white-space: nowrap; text-align: right">37.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">92.34 K</td>
    <td style="white-space: nowrap; text-align: right">40.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">89.21 K</td>
    <td style="white-space: nowrap; text-align: right">42.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.33 K</td>
    <td style="white-space: nowrap; text-align: right">42.9x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.21 K</td>
    <td style="white-space: nowrap; text-align: right">43.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">81.52 K</td>
    <td style="white-space: nowrap; text-align: right">45.96x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">80.90 K</td>
    <td style="white-space: nowrap; text-align: right">46.32x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">66.72 K</td>
    <td style="white-space: nowrap; text-align: right">56.16x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">61.73 K</td>
    <td style="white-space: nowrap; text-align: right">60.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">57.58 K</td>
    <td style="white-space: nowrap; text-align: right">65.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">54.03 K</td>
    <td style="white-space: nowrap; text-align: right">69.34x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">45.58 K</td>
    <td style="white-space: nowrap; text-align: right">82.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">41.67 K</td>
    <td style="white-space: nowrap; text-align: right">89.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">38.00 K</td>
    <td style="white-space: nowrap; text-align: right">98.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">28.49 K</td>
    <td style="white-space: nowrap; text-align: right">131.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">26.81 K</td>
    <td style="white-space: nowrap; text-align: right">139.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">25.28 K</td>
    <td style="white-space: nowrap; text-align: right">148.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">24.22 K</td>
    <td style="white-space: nowrap; text-align: right">154.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">22.94 K</td>
    <td style="white-space: nowrap; text-align: right">163.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.07 K</td>
    <td style="white-space: nowrap; text-align: right">196.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">18.74 K</td>
    <td style="white-space: nowrap; text-align: right">199.93x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.53 K</td>
    <td style="white-space: nowrap; text-align: right">226.62x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.25 K</td>
    <td style="white-space: nowrap; text-align: right">245.66x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">13.79 K</td>
    <td style="white-space: nowrap; text-align: right">271.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.76 K</td>
    <td style="white-space: nowrap; text-align: right">272.28x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">12.83 K</td>
    <td style="white-space: nowrap; text-align: right">292.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.02 K</td>
    <td style="white-space: nowrap; text-align: right">373.96x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">9.12 K</td>
    <td style="white-space: nowrap; text-align: right">410.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.76 K</td>
    <td style="white-space: nowrap; text-align: right">427.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap; text-align: right">8.16 K</td>
    <td style="white-space: nowrap; text-align: right">459.09x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.16 K</td>
    <td style="white-space: nowrap; text-align: right">726.8x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">3.97 K</td>
    <td style="white-space: nowrap; text-align: right">944.57x</td>
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
    <td style="white-space: nowrap">0.188 KB</td>
    <td>8.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap">1.34 KB</td>
    <td>57.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap">4.38 KB</td>
    <td>187.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap">11.18 KB</td>
    <td>477.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap">9.55 KB</td>
    <td>407.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap">27.41 KB</td>
    <td>1169.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>1176.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap">4.71 KB</td>
    <td>201.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.32 KB</td>
    <td>995.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.77 KB</td>
    <td>331.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.79 KB</td>
    <td>247.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap">29.76 KB</td>
    <td>1269.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap">10.98 KB</td>
    <td>468.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap">8.34 KB</td>
    <td>356.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">12.02 KB</td>
    <td>512.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap">13.48 KB</td>
    <td>575.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.23 KB</td>
    <td>735.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">16.90 KB</td>
    <td>721.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap">72.13 KB</td>
    <td>3077.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap">10.88 KB</td>
    <td>464.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap">51.73 KB</td>
    <td>2207.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap">68.59 KB</td>
    <td>2926.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap">40.66 KB</td>
    <td>1735.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap">40.95 KB</td>
    <td>1747.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>87.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap">2.74 KB</td>
    <td>117.07x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.75 KB</td>
    <td>1525.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap">18.01 KB</td>
    <td>768.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap">62.88 KB</td>
    <td>2683.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap">15.74 KB</td>
    <td>671.67x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>2364.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.29 KB</td>
    <td>1420.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap">74.30 KB</td>
    <td>3170.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / create signed anchored 100</td>
    <td style="white-space: nowrap">68.34 KB</td>
    <td>2916.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap">4.62 KB</td>
    <td>197.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit export / verify signed anchored 100</td>
    <td style="white-space: nowrap">115.90 KB</td>
    <td>4945.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap">171.92 KB</td>
    <td>7335.33x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap">720.41 KB</td>
    <td>30737.33x</td>
  </tr>
</table>