Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 20:53:10.506120Z
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
    <td style="white-space: nowrap; text-align: right">4125.99 K</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1558.42%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3659.15 K</td>
    <td style="white-space: nowrap; text-align: right">0.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1136.09%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1454.80 K</td>
    <td style="white-space: nowrap; text-align: right">0.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;586.47%</td>
    <td style="white-space: nowrap; text-align: right">0.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">280.74 K</td>
    <td style="white-space: nowrap; text-align: right">3.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;127.21%</td>
    <td style="white-space: nowrap; text-align: right">3.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">5.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">219.90 K</td>
    <td style="white-space: nowrap; text-align: right">4.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;106.50%</td>
    <td style="white-space: nowrap; text-align: right">4.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">8.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">107.75 K</td>
    <td style="white-space: nowrap; text-align: right">9.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.68%</td>
    <td style="white-space: nowrap; text-align: right">8.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">101.52 K</td>
    <td style="white-space: nowrap; text-align: right">9.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;74.26%</td>
    <td style="white-space: nowrap; text-align: right">8.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">97.83 K</td>
    <td style="white-space: nowrap; text-align: right">10.22 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;101.11%</td>
    <td style="white-space: nowrap; text-align: right">9.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">91.66 K</td>
    <td style="white-space: nowrap; text-align: right">10.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.61%</td>
    <td style="white-space: nowrap; text-align: right">10.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.03 K</td>
    <td style="white-space: nowrap; text-align: right">11.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.92%</td>
    <td style="white-space: nowrap; text-align: right">10.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">86.52 K</td>
    <td style="white-space: nowrap; text-align: right">11.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;38.40%</td>
    <td style="white-space: nowrap; text-align: right">10.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.95 K</td>
    <td style="white-space: nowrap; text-align: right">11.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;74.13%</td>
    <td style="white-space: nowrap; text-align: right">10.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">85.88 K</td>
    <td style="white-space: nowrap; text-align: right">11.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;51.35%</td>
    <td style="white-space: nowrap; text-align: right">10.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.49 K</td>
    <td style="white-space: nowrap; text-align: right">13.07 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.00%</td>
    <td style="white-space: nowrap; text-align: right">12.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">65.94 K</td>
    <td style="white-space: nowrap; text-align: right">15.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.11%</td>
    <td style="white-space: nowrap; text-align: right">14.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">60.32 K</td>
    <td style="white-space: nowrap; text-align: right">16.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;33.33%</td>
    <td style="white-space: nowrap; text-align: right">15.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">57.70 K</td>
    <td style="white-space: nowrap; text-align: right">17.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;33.52%</td>
    <td style="white-space: nowrap; text-align: right">16.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">56.11 K</td>
    <td style="white-space: nowrap; text-align: right">17.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.28%</td>
    <td style="white-space: nowrap; text-align: right">17.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">43.58 K</td>
    <td style="white-space: nowrap; text-align: right">22.95 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.77%</td>
    <td style="white-space: nowrap; text-align: right">21.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">40.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">41.36 K</td>
    <td style="white-space: nowrap; text-align: right">24.18 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.61%</td>
    <td style="white-space: nowrap; text-align: right">23.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">46.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.27 K</td>
    <td style="white-space: nowrap; text-align: right">26.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.03%</td>
    <td style="white-space: nowrap; text-align: right">26.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">29.77 K</td>
    <td style="white-space: nowrap; text-align: right">33.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.69%</td>
    <td style="white-space: nowrap; text-align: right">32.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">28.88 K</td>
    <td style="white-space: nowrap; text-align: right">34.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.38%</td>
    <td style="white-space: nowrap; text-align: right">33.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.29 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">23.11 K</td>
    <td style="white-space: nowrap; text-align: right">43.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.91%</td>
    <td style="white-space: nowrap; text-align: right">37.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">96.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">22.36 K</td>
    <td style="white-space: nowrap; text-align: right">44.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;33.80%</td>
    <td style="white-space: nowrap; text-align: right">40.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">97.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.91 K</td>
    <td style="white-space: nowrap; text-align: right">47.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.31%</td>
    <td style="white-space: nowrap; text-align: right">47.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">65.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">20.34 K</td>
    <td style="white-space: nowrap; text-align: right">49.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;65.79%</td>
    <td style="white-space: nowrap; text-align: right">44.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">148.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.29 K</td>
    <td style="white-space: nowrap; text-align: right">51.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.74%</td>
    <td style="white-space: nowrap; text-align: right">51.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">67.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.73 K</td>
    <td style="white-space: nowrap; text-align: right">59.76 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.35%</td>
    <td style="white-space: nowrap; text-align: right">58.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.72 K</td>
    <td style="white-space: nowrap; text-align: right">63.62 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.30%</td>
    <td style="white-space: nowrap; text-align: right">63.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">77.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">14.17 K</td>
    <td style="white-space: nowrap; text-align: right">70.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.78%</td>
    <td style="white-space: nowrap; text-align: right">69.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">89.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.56 K</td>
    <td style="white-space: nowrap; text-align: right">73.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.20%</td>
    <td style="white-space: nowrap; text-align: right">71.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">97.61 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.48 K</td>
    <td style="white-space: nowrap; text-align: right">74.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.25%</td>
    <td style="white-space: nowrap; text-align: right">73.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">91.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.66 K</td>
    <td style="white-space: nowrap; text-align: right">103.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.69%</td>
    <td style="white-space: nowrap; text-align: right">102.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">156.09 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.48 K</td>
    <td style="white-space: nowrap; text-align: right">117.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.22%</td>
    <td style="white-space: nowrap; text-align: right">117.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">145.34 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.83 K</td>
    <td style="white-space: nowrap; text-align: right">207.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.90%</td>
    <td style="white-space: nowrap; text-align: right">206.09 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">290.98 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.01 K</td>
    <td style="white-space: nowrap; text-align: right">249.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.38%</td>
    <td style="white-space: nowrap; text-align: right">244.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">325.65 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4125.99 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3659.15 K</td>
    <td style="white-space: nowrap; text-align: right">1.13x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1454.80 K</td>
    <td style="white-space: nowrap; text-align: right">2.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">280.74 K</td>
    <td style="white-space: nowrap; text-align: right">14.7x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">219.90 K</td>
    <td style="white-space: nowrap; text-align: right">18.76x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">107.75 K</td>
    <td style="white-space: nowrap; text-align: right">38.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">101.52 K</td>
    <td style="white-space: nowrap; text-align: right">40.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">97.83 K</td>
    <td style="white-space: nowrap; text-align: right">42.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">91.66 K</td>
    <td style="white-space: nowrap; text-align: right">45.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.03 K</td>
    <td style="white-space: nowrap; text-align: right">47.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">86.52 K</td>
    <td style="white-space: nowrap; text-align: right">47.69x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">85.95 K</td>
    <td style="white-space: nowrap; text-align: right">48.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">85.88 K</td>
    <td style="white-space: nowrap; text-align: right">48.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.49 K</td>
    <td style="white-space: nowrap; text-align: right">53.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">65.94 K</td>
    <td style="white-space: nowrap; text-align: right">62.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">60.32 K</td>
    <td style="white-space: nowrap; text-align: right">68.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">57.70 K</td>
    <td style="white-space: nowrap; text-align: right">71.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">56.11 K</td>
    <td style="white-space: nowrap; text-align: right">73.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">43.58 K</td>
    <td style="white-space: nowrap; text-align: right">94.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">41.36 K</td>
    <td style="white-space: nowrap; text-align: right">99.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.27 K</td>
    <td style="white-space: nowrap; text-align: right">110.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">29.77 K</td>
    <td style="white-space: nowrap; text-align: right">138.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">28.88 K</td>
    <td style="white-space: nowrap; text-align: right">142.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">23.11 K</td>
    <td style="white-space: nowrap; text-align: right">178.57x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">22.36 K</td>
    <td style="white-space: nowrap; text-align: right">184.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">20.91 K</td>
    <td style="white-space: nowrap; text-align: right">197.34x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">20.34 K</td>
    <td style="white-space: nowrap; text-align: right">202.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">19.29 K</td>
    <td style="white-space: nowrap; text-align: right">213.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.73 K</td>
    <td style="white-space: nowrap; text-align: right">246.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.72 K</td>
    <td style="white-space: nowrap; text-align: right">262.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap; text-align: right">14.17 K</td>
    <td style="white-space: nowrap; text-align: right">291.14x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.56 K</td>
    <td style="white-space: nowrap; text-align: right">304.22x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.48 K</td>
    <td style="white-space: nowrap; text-align: right">306.0x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.66 K</td>
    <td style="white-space: nowrap; text-align: right">427.31x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.48 K</td>
    <td style="white-space: nowrap; text-align: right">486.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.83 K</td>
    <td style="white-space: nowrap; text-align: right">854.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.01 K</td>
    <td style="white-space: nowrap; text-align: right">1028.55x</td>
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
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap">27.41 KB</td>
    <td>146.21x</td>
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
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>147.0x</td>
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
    <td style="white-space: nowrap">8.55 KB</td>
    <td>45.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap">11.91 KB</td>
    <td>63.5x</td>
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
    <td style="white-space: nowrap">16.79 KB</td>
    <td>89.54x</td>
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
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.64 KB</td>
    <td>190.08x</td>
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
    <td style="white-space: nowrap">mcp gateway / signed request</td>
    <td style="white-space: nowrap">13.83 KB</td>
    <td>73.75x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.27 KB</td>
    <td>177.46x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
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