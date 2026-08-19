## Environment

- Hardware: Apple M5 Pro, 18 cores
- OS: unix/darwin
- Elixir: 1.20.2 / OTP: 29
- SigilGuard: 1.0.0 (6d34e71)
- Benchee: warmup 0 ns, time 10 ms, memory_time 0 ns
- Date: 2026-08-19


Benchmark

# SigilGuard Performance Benchmarks

Mode: smoke. Values are measured for this environment, not ratified SLO bounds.


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
    <td style="white-space: nowrap">1.20.2</td>
  </tr><tr>
    <th style="white-space: nowrap">Erlang Version</th>
    <td style="white-space: nowrap">29.0.4</td>
  </tr>
</table>

## Configuration

Benchmark suite executing with the following configuration:

<table style="width: 1%">
  <tr>
    <th style="width: 1%">:time</th>
    <td style="white-space: nowrap">10 ms</td>
  </tr><tr>
    <th>:parallel</th>
    <td style="white-space: nowrap">1</td>
  </tr><tr>
    <th>:warmup</th>
    <td style="white-space: nowrap">0 ns</td>
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
    <td style="white-space: nowrap; text-align: right">212373.90 K</td>
    <td style="white-space: nowrap; text-align: right">0.00471 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;6480.14%</td>
    <td style="white-space: nowrap; text-align: right">0.00420 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.0125 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap; text-align: right">2048.98 K</td>
    <td style="white-space: nowrap; text-align: right">0.49 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;100.36%</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.25 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">646.20 K</td>
    <td style="white-space: nowrap; text-align: right">1.55 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.69%</td>
    <td style="white-space: nowrap; text-align: right">1.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">3.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">135.57 K</td>
    <td style="white-space: nowrap; text-align: right">7.38 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;36.00%</td>
    <td style="white-space: nowrap; text-align: right">6.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">14.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">82.97 K</td>
    <td style="white-space: nowrap; text-align: right">12.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;11.27%</td>
    <td style="white-space: nowrap; text-align: right">11.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">17.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">60.66 K</td>
    <td style="white-space: nowrap; text-align: right">16.48 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;718.15%</td>
    <td style="white-space: nowrap; text-align: right">11.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">20.90 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">44.59 K</td>
    <td style="white-space: nowrap; text-align: right">22.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;20.33%</td>
    <td style="white-space: nowrap; text-align: right">21.42 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">33.99 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">38.39 K</td>
    <td style="white-space: nowrap; text-align: right">26.05 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.69%</td>
    <td style="white-space: nowrap; text-align: right">25.60 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">36.78 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">22.32 K</td>
    <td style="white-space: nowrap; text-align: right">44.81 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;501.58%</td>
    <td style="white-space: nowrap; text-align: right">27.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">101.68 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">18.87 K</td>
    <td style="white-space: nowrap; text-align: right">52.99 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;345.68%</td>
    <td style="white-space: nowrap; text-align: right">38.67 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">338.13 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap; text-align: right">15.11 K</td>
    <td style="white-space: nowrap; text-align: right">66.20 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;16.08%</td>
    <td style="white-space: nowrap; text-align: right">64.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">141.65 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">14.05 K</td>
    <td style="white-space: nowrap; text-align: right">71.16 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;25.26%</td>
    <td style="white-space: nowrap; text-align: right">66.31 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">177.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">11.19 K</td>
    <td style="white-space: nowrap; text-align: right">89.34 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;150.42%</td>
    <td style="white-space: nowrap; text-align: right">75.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">1318.45 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.11 K</td>
    <td style="white-space: nowrap; text-align: right">90.01 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.95%</td>
    <td style="white-space: nowrap; text-align: right">88.79 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">153.61 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">2.09 K</td>
    <td style="white-space: nowrap; text-align: right">478.87 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;348.42%</td>
    <td style="white-space: nowrap; text-align: right">107.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7760.42 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.34 K</td>
    <td style="white-space: nowrap; text-align: right">744.03 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;3.84%</td>
    <td style="white-space: nowrap; text-align: right">748.35 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">782.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.32 K</td>
    <td style="white-space: nowrap; text-align: right">758.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;4.40%</td>
    <td style="white-space: nowrap; text-align: right">749.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">840.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">0.163 K</td>
    <td style="white-space: nowrap; text-align: right">6150.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;5.10%</td>
    <td style="white-space: nowrap; text-align: right">6150.90 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">6372.54 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0885 K</td>
    <td style="white-space: nowrap; text-align: right">11303.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;0.00%</td>
    <td style="white-space: nowrap; text-align: right">11303.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">11303.33 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0778 K</td>
    <td style="white-space: nowrap; text-align: right">12846.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;0.00%</td>
    <td style="white-space: nowrap; text-align: right">12846.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">12846.88 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">212373.90 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap; text-align: right">2048.98 K</td>
    <td style="white-space: nowrap; text-align: right">103.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">646.20 K</td>
    <td style="white-space: nowrap; text-align: right">328.65x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">135.57 K</td>
    <td style="white-space: nowrap; text-align: right">1566.51x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">82.97 K</td>
    <td style="white-space: nowrap; text-align: right">2559.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">60.66 K</td>
    <td style="white-space: nowrap; text-align: right">3500.78x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">44.59 K</td>
    <td style="white-space: nowrap; text-align: right">4762.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">38.39 K</td>
    <td style="white-space: nowrap; text-align: right">5531.4x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">22.32 K</td>
    <td style="white-space: nowrap; text-align: right">9516.1x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">18.87 K</td>
    <td style="white-space: nowrap; text-align: right">11253.99x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap; text-align: right">15.11 K</td>
    <td style="white-space: nowrap; text-align: right">14059.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">14.05 K</td>
    <td style="white-space: nowrap; text-align: right">15112.17x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">11.19 K</td>
    <td style="white-space: nowrap; text-align: right">18972.86x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.11 K</td>
    <td style="white-space: nowrap; text-align: right">19114.84x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">2.09 K</td>
    <td style="white-space: nowrap; text-align: right">101699.72x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.34 K</td>
    <td style="white-space: nowrap; text-align: right">158012.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.32 K</td>
    <td style="white-space: nowrap; text-align: right">161086.21x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">0.163 K</td>
    <td style="white-space: nowrap; text-align: right">1306289.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0885 K</td>
    <td style="white-space: nowrap; text-align: right">2400532.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0778 K</td>
    <td style="white-space: nowrap; text-align: right">2728340.95x</td>
  </tr>

</table>