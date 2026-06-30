Benchmark

# SigilGuard Performance Benchmarks

Run on: 2026-06-30 20:38:33.140728Z
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
    <td style="white-space: nowrap; text-align: right">4238.42 K</td>
    <td style="white-space: nowrap; text-align: right">0.24 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1568.30%</td>
    <td style="white-space: nowrap; text-align: right">0.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3600.77 K</td>
    <td style="white-space: nowrap; text-align: right">0.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1213.23%</td>
    <td style="white-space: nowrap; text-align: right">0.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1233.31 K</td>
    <td style="white-space: nowrap; text-align: right">0.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;656.12%</td>
    <td style="white-space: nowrap; text-align: right">0.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">283.73 K</td>
    <td style="white-space: nowrap; text-align: right">3.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;91.34%</td>
    <td style="white-space: nowrap; text-align: right">3.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">4.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">212.29 K</td>
    <td style="white-space: nowrap; text-align: right">4.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;160.18%</td>
    <td style="white-space: nowrap; text-align: right">4.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">11.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.09 K</td>
    <td style="white-space: nowrap; text-align: right">9.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;133.08%</td>
    <td style="white-space: nowrap; text-align: right">8.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">107.97 K</td>
    <td style="white-space: nowrap; text-align: right">9.26 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;40.02%</td>
    <td style="white-space: nowrap; text-align: right">8.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">18.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">101.51 K</td>
    <td style="white-space: nowrap; text-align: right">9.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;64.47%</td>
    <td style="white-space: nowrap; text-align: right">9.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.20 K</td>
    <td style="white-space: nowrap; text-align: right">10.62 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.78%</td>
    <td style="white-space: nowrap; text-align: right">10.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">92.45 K</td>
    <td style="white-space: nowrap; text-align: right">10.82 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;46.45%</td>
    <td style="white-space: nowrap; text-align: right">10.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">22.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.67 K</td>
    <td style="white-space: nowrap; text-align: right">11.41 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;63.22%</td>
    <td style="white-space: nowrap; text-align: right">10.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">28.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">81.40 K</td>
    <td style="white-space: nowrap; text-align: right">12.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.85%</td>
    <td style="white-space: nowrap; text-align: right">11.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">32.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">80.75 K</td>
    <td style="white-space: nowrap; text-align: right">12.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;58.13%</td>
    <td style="white-space: nowrap; text-align: right">11.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">77.78 K</td>
    <td style="white-space: nowrap; text-align: right">12.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.52%</td>
    <td style="white-space: nowrap; text-align: right">12.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">21.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">67.58 K</td>
    <td style="white-space: nowrap; text-align: right">14.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.82%</td>
    <td style="white-space: nowrap; text-align: right">14.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">37.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">62.10 K</td>
    <td style="white-space: nowrap; text-align: right">16.10 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;38.20%</td>
    <td style="white-space: nowrap; text-align: right">15.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">39.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">52.60 K</td>
    <td style="white-space: nowrap; text-align: right">19.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;26.84%</td>
    <td style="white-space: nowrap; text-align: right">18.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">50.53 K</td>
    <td style="white-space: nowrap; text-align: right">19.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;85.07%</td>
    <td style="white-space: nowrap; text-align: right">17.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">37.81 K</td>
    <td style="white-space: nowrap; text-align: right">26.44 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;109.40%</td>
    <td style="white-space: nowrap; text-align: right">22.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">84.41 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.64 K</td>
    <td style="white-space: nowrap; text-align: right">26.57 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.12%</td>
    <td style="white-space: nowrap; text-align: right">26.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">34.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">36.46 K</td>
    <td style="white-space: nowrap; text-align: right">27.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;48.52%</td>
    <td style="white-space: nowrap; text-align: right">25.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">65.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">29.73 K</td>
    <td style="white-space: nowrap; text-align: right">33.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.75%</td>
    <td style="white-space: nowrap; text-align: right">33.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">28.13 K</td>
    <td style="white-space: nowrap; text-align: right">35.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.25%</td>
    <td style="white-space: nowrap; text-align: right">34.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">48.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.17 K</td>
    <td style="white-space: nowrap; text-align: right">36.80 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.87%</td>
    <td style="white-space: nowrap; text-align: right">33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">72.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.77 K</td>
    <td style="white-space: nowrap; text-align: right">38.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;27.33%</td>
    <td style="white-space: nowrap; text-align: right">35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.04 K</td>
    <td style="white-space: nowrap; text-align: right">41.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.93%</td>
    <td style="white-space: nowrap; text-align: right">42.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">53.08 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.10 K</td>
    <td style="white-space: nowrap; text-align: right">52.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;15.69%</td>
    <td style="white-space: nowrap; text-align: right">50.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">75.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.83 K</td>
    <td style="white-space: nowrap; text-align: right">53.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.95%</td>
    <td style="white-space: nowrap; text-align: right">52.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">70.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.38 K</td>
    <td style="white-space: nowrap; text-align: right">61.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.05%</td>
    <td style="white-space: nowrap; text-align: right">60.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">81.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.93 K</td>
    <td style="white-space: nowrap; text-align: right">62.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.28%</td>
    <td style="white-space: nowrap; text-align: right">63.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">76.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.17 K</td>
    <td style="white-space: nowrap; text-align: right">70.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.68%</td>
    <td style="white-space: nowrap; text-align: right">71.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">84.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.08 K</td>
    <td style="white-space: nowrap; text-align: right">76.45 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.16%</td>
    <td style="white-space: nowrap; text-align: right">74.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">103.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.68 K</td>
    <td style="white-space: nowrap; text-align: right">93.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.95%</td>
    <td style="white-space: nowrap; text-align: right">92.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">115.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.81 K</td>
    <td style="white-space: nowrap; text-align: right">113.56 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6.76%</td>
    <td style="white-space: nowrap; text-align: right">113.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">136.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.05 K</td>
    <td style="white-space: nowrap; text-align: right">197.83 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.20%</td>
    <td style="white-space: nowrap; text-align: right">194.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">290.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.02 K</td>
    <td style="white-space: nowrap; text-align: right">248.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.98%</td>
    <td style="white-space: nowrap; text-align: right">245.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">321.73 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">4238.42 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">policy / elixir classify_risk</td>
    <td style="white-space: nowrap; text-align: right">3600.77 K</td>
    <td style="white-space: nowrap; text-align: right">1.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">1233.31 K</td>
    <td style="white-space: nowrap; text-align: right">3.44x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / compile</td>
    <td style="white-space: nowrap; text-align: right">283.73 K</td>
    <td style="white-space: nowrap; text-align: right">14.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / action_digest</td>
    <td style="white-space: nowrap; text-align: right">212.29 K</td>
    <td style="white-space: nowrap; text-align: right">19.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan clean</td>
    <td style="white-space: nowrap; text-align: right">109.09 K</td>
    <td style="white-space: nowrap; text-align: right">38.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / canonical_bytes</td>
    <td style="white-space: nowrap; text-align: right">107.97 K</td>
    <td style="white-space: nowrap; text-align: right">39.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate approval</td>
    <td style="white-space: nowrap; text-align: right">101.51 K</td>
    <td style="white-space: nowrap; text-align: right">41.76x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap; text-align: right">94.20 K</td>
    <td style="white-space: nowrap; text-align: right">44.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap; text-align: right">92.45 K</td>
    <td style="white-space: nowrap; text-align: right">45.85x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan secret</td>
    <td style="white-space: nowrap; text-align: right">87.67 K</td>
    <td style="white-space: nowrap; text-align: right">48.35x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / issue token</td>
    <td style="white-space: nowrap; text-align: right">81.40 K</td>
    <td style="white-space: nowrap; text-align: right">52.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate block</td>
    <td style="white-space: nowrap; text-align: right">80.75 K</td>
    <td style="white-space: nowrap; text-align: right">52.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">confirmation / verify token</td>
    <td style="white-space: nowrap; text-align: right">77.78 K</td>
    <td style="white-space: nowrap; text-align: right">54.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / clean tool result</td>
    <td style="white-space: nowrap; text-align: right">67.58 K</td>
    <td style="white-space: nowrap; text-align: right">62.71x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive external block</td>
    <td style="white-space: nowrap; text-align: right">62.10 K</td>
    <td style="white-space: nowrap; text-align: right">68.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap; text-align: right">52.60 K</td>
    <td style="white-space: nowrap; text-align: right">80.58x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap; text-align: right">50.53 K</td>
    <td style="white-space: nowrap; text-align: right">83.89x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap; text-align: right">37.81 K</td>
    <td style="white-space: nowrap; text-align: right">112.08x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">repo policy / parse</td>
    <td style="white-space: nowrap; text-align: right">37.64 K</td>
    <td style="white-space: nowrap; text-align: right">112.61x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 10</td>
    <td style="white-space: nowrap; text-align: right">36.46 K</td>
    <td style="white-space: nowrap; text-align: right">116.25x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed</td>
    <td style="white-space: nowrap; text-align: right">29.73 K</td>
    <td style="white-space: nowrap; text-align: right">142.56x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan_and_redact</td>
    <td style="white-space: nowrap; text-align: right">28.13 K</td>
    <td style="white-space: nowrap; text-align: right">150.67x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / merkle_root 100</td>
    <td style="white-space: nowrap; text-align: right">27.17 K</td>
    <td style="white-space: nowrap; text-align: right">155.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / create 100</td>
    <td style="white-space: nowrap; text-align: right">25.77 K</td>
    <td style="white-space: nowrap; text-align: right">164.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir verify</td>
    <td style="white-space: nowrap; text-align: right">24.04 K</td>
    <td style="white-space: nowrap; text-align: right">176.29x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime gate / quarantine tool result</td>
    <td style="white-space: nowrap; text-align: right">19.10 K</td>
    <td style="white-space: nowrap; text-align: right">221.88x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">envelope / elixir sign</td>
    <td style="white-space: nowrap; text-align: right">18.83 K</td>
    <td style="white-space: nowrap; text-align: right">225.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / sign 100</td>
    <td style="white-space: nowrap; text-align: right">16.38 K</td>
    <td style="white-space: nowrap; text-align: right">258.82x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / verify signed</td>
    <td style="white-space: nowrap; text-align: right">15.93 K</td>
    <td style="white-space: nowrap; text-align: right">266.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">registry bundle / sign</td>
    <td style="white-space: nowrap; text-align: right">14.17 K</td>
    <td style="white-space: nowrap; text-align: right">299.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">runtime stream / split secret redact</td>
    <td style="white-space: nowrap; text-align: right">13.08 K</td>
    <td style="white-space: nowrap; text-align: right">324.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit checkpoint / verify signed 100</td>
    <td style="white-space: nowrap; text-align: right">10.68 K</td>
    <td style="white-space: nowrap; text-align: right">396.97x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">scanner / elixir scan large</td>
    <td style="white-space: nowrap; text-align: right">8.81 K</td>
    <td style="white-space: nowrap; text-align: right">481.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir build_chain 100</td>
    <td style="white-space: nowrap; text-align: right">5.05 K</td>
    <td style="white-space: nowrap; text-align: right">838.47x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">audit / elixir verify_chain 100</td>
    <td style="white-space: nowrap; text-align: right">4.02 K</td>
    <td style="white-space: nowrap; text-align: right">1054.21x</td>
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
    <td style="white-space: nowrap">registry bundle / digest</td>
    <td style="white-space: nowrap">27.56 KB</td>
    <td>147.0x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">scanner / elixir scan mixed regex-only</td>
    <td style="white-space: nowrap">5.79 KB</td>
    <td>30.88x</td>
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
    <td style="white-space: nowrap">audit / elixir build_chain 10</td>
    <td style="white-space: nowrap">17.23 KB</td>
    <td>91.92x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">repo policy / evaluate allow</td>
    <td style="white-space: nowrap">13.48 KB</td>
    <td>71.88x</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">runtime gate / sensitive model redact</td>
    <td style="white-space: nowrap">16.79 KB</td>
    <td>89.54x</td>
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
    <td style="white-space: nowrap">62.88 KB</td>
    <td>335.38x</td>
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