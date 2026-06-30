Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 20:29:28.000458Z
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
    <td style="white-space: nowrap; text-align: right">3845.85 K</td>
    <td style="white-space: nowrap; text-align: right">0.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1607.46%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3629.38 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1204.19%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1333.38 K</td>
    <td style="white-space: nowrap; text-align: right">0.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;641.38%</td>
    <td style="white-space: nowrap; text-align: right">0.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">273.86 K</td>
    <td style="white-space: nowrap; text-align: right">3.65 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;114.13%</td>
    <td style="white-space: nowrap; text-align: right">3.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">5.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">220.38 K</td>
    <td style="white-space: nowrap; text-align: right">4.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;123.46%</td>
    <td style="white-space: nowrap; text-align: right">4.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">109.05 K</td>
    <td style="white-space: nowrap; text-align: right">9.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;41.07%</td>
    <td style="white-space: nowrap; text-align: right">8.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">101.06 K</td>
    <td style="white-space: nowrap; text-align: right">9.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;90.99%</td>
    <td style="white-space: nowrap; text-align: right">9.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">19 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">100.94 K</td>
    <td style="white-space: nowrap; text-align: right">9.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;62.79%</td>
    <td style="white-space: nowrap; text-align: right">9.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">93.28 K</td>
    <td style="white-space: nowrap; text-align: right">10.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;46.97%</td>
    <td style="white-space: nowrap; text-align: right">9.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">92.64 K</td>
    <td style="white-space: nowrap; text-align: right">10.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;30.50%</td>
    <td style="white-space: nowrap; text-align: right">10.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">88.29 K</td>
    <td style="white-space: nowrap; text-align: right">11.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;42.43%</td>
    <td style="white-space: nowrap; text-align: right">10.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">27.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">85.52 K</td>
    <td style="white-space: nowrap; text-align: right">11.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.57%</td>
    <td style="white-space: nowrap; text-align: right">11.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">26.16 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">84.69 K</td>
    <td style="white-space: nowrap; text-align: right">11.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;50.61%</td>
    <td style="white-space: nowrap; text-align: right">11.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">30.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.19 K</td>
    <td style="white-space: nowrap; text-align: right">13.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;24.59%</td>
    <td style="white-space: nowrap; text-align: right">12.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">67.97 K</td>
    <td style="white-space: nowrap; text-align: right">14.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;45.14%</td>
    <td style="white-space: nowrap; text-align: right">14.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">31.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">59.62 K</td>
    <td style="white-space: nowrap; text-align: right">16.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.98%</td>
    <td style="white-space: nowrap; text-align: right">15.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">57.38 K</td>
    <td style="white-space: nowrap; text-align: right">17.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;37.15%</td>
    <td style="white-space: nowrap; text-align: right">16.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">56.57 K</td>
    <td style="white-space: nowrap; text-align: right">17.68 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.06%</td>
    <td style="white-space: nowrap; text-align: right">17.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">37.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">43.43 K</td>
    <td style="white-space: nowrap; text-align: right">23.03 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.44%</td>
    <td style="white-space: nowrap; text-align: right">21.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">42.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.52 K</td>
    <td style="white-space: nowrap; text-align: right">24.68 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;23.64%</td>
    <td style="white-space: nowrap; text-align: right">23.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">36.96 K</td>
    <td style="white-space: nowrap; text-align: right">27.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.38%</td>
    <td style="white-space: nowrap; text-align: right">26.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">35.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.41 K</td>
    <td style="white-space: nowrap; text-align: right">32.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.97%</td>
    <td style="white-space: nowrap; text-align: right">32.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">43.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.95 K</td>
    <td style="white-space: nowrap; text-align: right">35.78 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.44%</td>
    <td style="white-space: nowrap; text-align: right">34.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">49.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.50 K</td>
    <td style="white-space: nowrap; text-align: right">36.37 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.00%</td>
    <td style="white-space: nowrap; text-align: right">32.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.57 K</td>
    <td style="white-space: nowrap; text-align: right">37.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.34%</td>
    <td style="white-space: nowrap; text-align: right">34.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">71.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.08 K</td>
    <td style="white-space: nowrap; text-align: right">41.53 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.39%</td>
    <td style="white-space: nowrap; text-align: right">42.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">52.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.55 K</td>
    <td style="white-space: nowrap; text-align: right">51.14 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.47%</td>
    <td style="white-space: nowrap; text-align: right">49.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">71.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.45 K</td>
    <td style="white-space: nowrap; text-align: right">54.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.34%</td>
    <td style="white-space: nowrap; text-align: right">53.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">71.28 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.17 K</td>
    <td style="white-space: nowrap; text-align: right">61.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.33%</td>
    <td style="white-space: nowrap; text-align: right">60.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">79.00 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.17 K</td>
    <td style="white-space: nowrap; text-align: right">65.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.93%</td>
    <td style="white-space: nowrap; text-align: right">64.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">84.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.21 K</td>
    <td style="white-space: nowrap; text-align: right">75.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;10.26%</td>
    <td style="white-space: nowrap; text-align: right">74.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">94.73 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.00 K</td>
    <td style="white-space: nowrap; text-align: right">76.93 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.69%</td>
    <td style="white-space: nowrap; text-align: right">74.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">112.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.63 K</td>
    <td style="white-space: nowrap; text-align: right">103.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.67%</td>
    <td style="white-space: nowrap; text-align: right">101.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">161.45 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.59 K</td>
    <td style="white-space: nowrap; text-align: right">116.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.28%</td>
    <td style="white-space: nowrap; text-align: right">114.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">142.97 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.15 K</td>
    <td style="white-space: nowrap; text-align: right">194.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.42%</td>
    <td style="white-space: nowrap; text-align: right">191.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">284.77 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.32 K</td>
    <td style="white-space: nowrap; text-align: right">231.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.23%</td>
    <td style="white-space: nowrap; text-align: right">230 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">282.39 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">3845.85 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3629.38 K</td>
    <td style="white-space: nowrap; text-align: right">1.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1333.38 K</td>
    <td style="white-space: nowrap; text-align: right">2.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">273.86 K</td>
    <td style="white-space: nowrap; text-align: right">14.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">220.38 K</td>
    <td style="white-space: nowrap; text-align: right">17.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">109.05 K</td>
    <td style="white-space: nowrap; text-align: right">35.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">101.06 K</td>
    <td style="white-space: nowrap; text-align: right">38.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">100.94 K</td>
    <td style="white-space: nowrap; text-align: right">38.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">93.28 K</td>
    <td style="white-space: nowrap; text-align: right">41.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">92.64 K</td>
    <td style="white-space: nowrap; text-align: right">41.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">88.29 K</td>
    <td style="white-space: nowrap; text-align: right">43.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">85.52 K</td>
    <td style="white-space: nowrap; text-align: right">44.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">84.69 K</td>
    <td style="white-space: nowrap; text-align: right">45.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">76.19 K</td>
    <td style="white-space: nowrap; text-align: right">50.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">67.97 K</td>
    <td style="white-space: nowrap; text-align: right">56.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">59.62 K</td>
    <td style="white-space: nowrap; text-align: right">64.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">57.38 K</td>
    <td style="white-space: nowrap; text-align: right">67.02x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">56.57 K</td>
    <td style="white-space: nowrap; text-align: right">67.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">43.43 K</td>
    <td style="white-space: nowrap; text-align: right">88.55x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">40.52 K</td>
    <td style="white-space: nowrap; text-align: right">94.9x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">36.96 K</td>
    <td style="white-space: nowrap; text-align: right">104.06x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">30.41 K</td>
    <td style="white-space: nowrap; text-align: right">126.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">27.95 K</td>
    <td style="white-space: nowrap; text-align: right">137.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.50 K</td>
    <td style="white-space: nowrap; text-align: right">139.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">26.57 K</td>
    <td style="white-space: nowrap; text-align: right">144.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.08 K</td>
    <td style="white-space: nowrap; text-align: right">159.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.55 K</td>
    <td style="white-space: nowrap; text-align: right">196.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.45 K</td>
    <td style="white-space: nowrap; text-align: right">208.46x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.17 K</td>
    <td style="white-space: nowrap; text-align: right">237.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.17 K</td>
    <td style="white-space: nowrap; text-align: right">253.45x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">13.21 K</td>
    <td style="white-space: nowrap; text-align: right">291.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.00 K</td>
    <td style="white-space: nowrap; text-align: right">295.86x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">9.63 K</td>
    <td style="white-space: nowrap; text-align: right">399.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.59 K</td>
    <td style="white-space: nowrap; text-align: right">447.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.15 K</td>
    <td style="white-space: nowrap; text-align: right">746.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.32 K</td>
    <td style="white-space: nowrap; text-align: right">890.98x</td>
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
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.79 KB</td>
    <td>30.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>147.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap">10.98 KB</td>
    <td>58.58x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap">23.32 KB</td>
    <td>124.38x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap">7.77 KB</td>
    <td>41.42x</td>
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
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap">2.05 KB</td>
    <td>10.96x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap">35.64 KB</td>
    <td>190.08x</td>
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
    <td style="white-space: nowrap">61.55 KB</td>
    <td>328.29x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap">55.41 KB</td>
    <td>295.54x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap">33.27 KB</td>
    <td>177.46x</td>
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