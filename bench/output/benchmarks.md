## Environment

- Hardware: Apple M5 Pro, 18 cores
- OS: unix/darwin
- Elixir: 1.18.4 / OTP: 28
- SigilGuard: 1.0.1 (ec939e1)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-09-11
- Background load: Unrelated BEAM work exceeded 50% CPU in 60 of 164 sampled seconds, with a peak observed process CPU of 1303.7% (100% is one logical CPU). This shared-host run is informational, not a controlled timing comparison.


Benchmark

# SigilGuard Performance Benchmarks

Mode: measured. Values are measured for this environment, not ratified SLO bounds.


## System

Benchmark suite executing on the following system:

<table style="width: 1%">
  <tr>
    <th style="width: 1%; white-space: nowrap">Operating System</th>
    <td>macOS</td>
  </tr><tr>
    <th style="white-space: nowrap">CPU Information</th>
    <td style="white-space: nowrap">Apple M5 Pro</td>
  </tr><tr>
    <th style="white-space: nowrap">Number of Available Cores</th>
    <td style="white-space: nowrap">18</td>
  </tr><tr>
    <th style="white-space: nowrap">Available Memory</th>
    <td style="white-space: nowrap">48 GB</td>
  </tr><tr>
    <th style="white-space: nowrap">Elixir Version</th>
    <td style="white-space: nowrap">1.18.4</td>
  </tr><tr>
    <th style="white-space: nowrap">Erlang Version</th>
    <td style="white-space: nowrap">28.5.0.6</td>
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
    <th style="text-align: right">Deviation</th>
    <th style="text-align: right">Median</th>
    <th style="text-align: right">99th&nbsp;%</th>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 no-op baseline</td>
    <td style="white-space: nowrap; text-align: right">499356.08 K</td>
    <td style="white-space: nowrap; text-align: right">0.00200 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;55.49%</td>
    <td style="white-space: nowrap; text-align: right">0.00200 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.00221 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap; text-align: right">1685.72 K</td>
    <td style="white-space: nowrap; text-align: right">0.59 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;707.27%</td>
    <td style="white-space: nowrap; text-align: right">0.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.79 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">569.89 K</td>
    <td style="white-space: nowrap; text-align: right">1.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;479.13%</td>
    <td style="white-space: nowrap; text-align: right">1.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">100.90 K</td>
    <td style="white-space: nowrap; text-align: right">9.91 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;69.79%</td>
    <td style="white-space: nowrap; text-align: right">8.54 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">44.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">88.77 K</td>
    <td style="white-space: nowrap; text-align: right">11.27 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.55%</td>
    <td style="white-space: nowrap; text-align: right">11.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">14.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">85.74 K</td>
    <td style="white-space: nowrap; text-align: right">11.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;22.75%</td>
    <td style="white-space: nowrap; text-align: right">11.71 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">14.71 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">32.04 K</td>
    <td style="white-space: nowrap; text-align: right">31.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.62%</td>
    <td style="white-space: nowrap; text-align: right">30.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">41.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">24.63 K</td>
    <td style="white-space: nowrap; text-align: right">40.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.13%</td>
    <td style="white-space: nowrap; text-align: right">39.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">54.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">20.42 K</td>
    <td style="white-space: nowrap; text-align: right">48.98 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.63%</td>
    <td style="white-space: nowrap; text-align: right">47.96 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">60.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">19.36 K</td>
    <td style="white-space: nowrap; text-align: right">51.66 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.19%</td>
    <td style="white-space: nowrap; text-align: right">50.58 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">65.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">14.15 K</td>
    <td style="white-space: nowrap; text-align: right">70.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;12.87%</td>
    <td style="white-space: nowrap; text-align: right">70.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">94.38 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap; text-align: right">13.12 K</td>
    <td style="white-space: nowrap; text-align: right">76.21 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.88%</td>
    <td style="white-space: nowrap; text-align: right">75.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">89.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.27 K</td>
    <td style="white-space: nowrap; text-align: right">88.74 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.56%</td>
    <td style="white-space: nowrap; text-align: right">88.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">105.04 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">9.53 K</td>
    <td style="white-space: nowrap; text-align: right">104.97 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;34.02%</td>
    <td style="white-space: nowrap; text-align: right">88.13 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">243.97 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">8.39 K</td>
    <td style="white-space: nowrap; text-align: right">119.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.83%</td>
    <td style="white-space: nowrap; text-align: right">118.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">142.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.43 K</td>
    <td style="white-space: nowrap; text-align: right">700.73 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2.86%</td>
    <td style="white-space: nowrap; text-align: right">705.19 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">746.09 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.33 K</td>
    <td style="white-space: nowrap; text-align: right">751.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;3.13%</td>
    <td style="white-space: nowrap; text-align: right">751.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">808.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">0.144 K</td>
    <td style="white-space: nowrap; text-align: right">6933.51 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.75%</td>
    <td style="white-space: nowrap; text-align: right">6906.11 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">10360.07 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0891 K</td>
    <td style="white-space: nowrap; text-align: right">11226.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1.32%</td>
    <td style="white-space: nowrap; text-align: right">11201.94 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">11748.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0812 K</td>
    <td style="white-space: nowrap; text-align: right">12317.72 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1.54%</td>
    <td style="white-space: nowrap; text-align: right">12283.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">13065.22 &micro;s</td>
  </tr>

</table>


Run Time Comparison

<table style="width: 1%">
  <tr>
    <th>Name</th>
    <th style="text-align: right">IPS</th>
    <th style="text-align: right">Slower</th>
  <tr>
    <td style="white-space: nowrap">BM.08 no-op baseline</td>
    <td style="white-space: nowrap;text-align: right">499356.08 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap; text-align: right">1685.72 K</td>
    <td style="white-space: nowrap; text-align: right">296.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">569.89 K</td>
    <td style="white-space: nowrap; text-align: right">876.23x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">100.90 K</td>
    <td style="white-space: nowrap; text-align: right">4948.87x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">88.77 K</td>
    <td style="white-space: nowrap; text-align: right">5625.59x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">85.74 K</td>
    <td style="white-space: nowrap; text-align: right">5823.94x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">32.04 K</td>
    <td style="white-space: nowrap; text-align: right">15587.15x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">24.63 K</td>
    <td style="white-space: nowrap; text-align: right">20273.07x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">20.42 K</td>
    <td style="white-space: nowrap; text-align: right">24459.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">19.36 K</td>
    <td style="white-space: nowrap; text-align: right">25796.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">14.15 K</td>
    <td style="white-space: nowrap; text-align: right">35297.48x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap; text-align: right">13.12 K</td>
    <td style="white-space: nowrap; text-align: right">38054.41x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.27 K</td>
    <td style="white-space: nowrap; text-align: right">44312.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">9.53 K</td>
    <td style="white-space: nowrap; text-align: right">52418.34x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">8.39 K</td>
    <td style="white-space: nowrap; text-align: right">59517.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.43 K</td>
    <td style="white-space: nowrap; text-align: right">349915.91x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.33 K</td>
    <td style="white-space: nowrap; text-align: right">375289.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">0.144 K</td>
    <td style="white-space: nowrap; text-align: right">3462290.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0891 K</td>
    <td style="white-space: nowrap; text-align: right">5606105.74x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0812 K</td>
    <td style="white-space: nowrap; text-align: right">6150929.47x</td>
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
    <td style="white-space: nowrap">BM.08 no-op baseline</td>
    <td style="white-space: nowrap">0 KB</td>
    <td>&nbsp;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap">0.0469 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap">1.67 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap">6.69 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap">3.25 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap">3.25 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap">58.29 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap">60.05 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap">101.51 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap">64.55 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap">73.99 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap">54.30 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap">72.97 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap">78.37 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap">48.43 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap">3.27 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap">129.02 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap">4067.81 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap">3.39 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap">2024.05 KB</td>
    <td>&mdash;</td>
  </tr>
</table>