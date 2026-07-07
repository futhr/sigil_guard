## Environment

- Hardware: Apple M4 Max, 16 cores
- OS: unix/darwin
- Elixir: 1.20.2 / OTP: 29
- SigilGuard: 1.0.0 (298d787)
- Benchee: warmup 2 s, time 5 s, memory_time 2 s
- Date: 2026-07-07


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
    <td style="white-space: nowrap">BM.08 no-op baseline</td>
    <td style="white-space: nowrap; text-align: right">528792.30 K</td>
    <td style="white-space: nowrap; text-align: right">0.00189 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;171.64%</td>
    <td style="white-space: nowrap; text-align: right">0.00188 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">0.00263 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap; text-align: right">2347.01 K</td>
    <td style="white-space: nowrap; text-align: right">0.43 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1218.02%</td>
    <td style="white-space: nowrap; text-align: right">0.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.67 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">570.10 K</td>
    <td style="white-space: nowrap; text-align: right">1.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;336.43%</td>
    <td style="white-space: nowrap; text-align: right">1.63 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">2.46 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">127.23 K</td>
    <td style="white-space: nowrap; text-align: right">7.86 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;144.30%</td>
    <td style="white-space: nowrap; text-align: right">6.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.50 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">71.43 K</td>
    <td style="white-space: nowrap; text-align: right">14.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;54.04%</td>
    <td style="white-space: nowrap; text-align: right">13.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">23.75 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">69.09 K</td>
    <td style="white-space: nowrap; text-align: right">14.47 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;50.96%</td>
    <td style="white-space: nowrap; text-align: right">13.50 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">24.88 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">38.37 K</td>
    <td style="white-space: nowrap; text-align: right">26.06 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;28.52%</td>
    <td style="white-space: nowrap; text-align: right">23.17 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">57.92 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">37.11 K</td>
    <td style="white-space: nowrap; text-align: right">26.95 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;21.04%</td>
    <td style="white-space: nowrap; text-align: right">24.46 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">45.83 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">32.52 K</td>
    <td style="white-space: nowrap; text-align: right">30.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;18.94%</td>
    <td style="white-space: nowrap; text-align: right">27.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">47.28 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">21.12 K</td>
    <td style="white-space: nowrap; text-align: right">47.36 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;13.04%</td>
    <td style="white-space: nowrap; text-align: right">46.25 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">66.58 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap; text-align: right">15.80 K</td>
    <td style="white-space: nowrap; text-align: right">63.28 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.67%</td>
    <td style="white-space: nowrap; text-align: right">62.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">81.17 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">15.53 K</td>
    <td style="white-space: nowrap; text-align: right">64.40 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;9.22%</td>
    <td style="white-space: nowrap; text-align: right">63.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">80.96 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.40 K</td>
    <td style="white-space: nowrap; text-align: right">87.69 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;8.07%</td>
    <td style="white-space: nowrap; text-align: right">85.75 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">108.91 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">9.97 K</td>
    <td style="white-space: nowrap; text-align: right">100.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;35.21%</td>
    <td style="white-space: nowrap; text-align: right">85.00 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">239.24 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">8.01 K</td>
    <td style="white-space: nowrap; text-align: right">124.77 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;7.01%</td>
    <td style="white-space: nowrap; text-align: right">122.33 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">150.63 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.28 K</td>
    <td style="white-space: nowrap; text-align: right">782.08 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;3.65%</td>
    <td style="white-space: nowrap; text-align: right">777.29 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">889.36 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.24 K</td>
    <td style="white-space: nowrap; text-align: right">805.61 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;3.20%</td>
    <td style="white-space: nowrap; text-align: right">802.04 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">901.21 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">0.171 K</td>
    <td style="white-space: nowrap; text-align: right">5859.85 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;14.73%</td>
    <td style="white-space: nowrap; text-align: right">5960.52 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">7416.34 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0804 K</td>
    <td style="white-space: nowrap; text-align: right">12439.30 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;1.33%</td>
    <td style="white-space: nowrap; text-align: right">12421.88 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">12814.93 &micro;s</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0743 K</td>
    <td style="white-space: nowrap; text-align: right">13459.64 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">&plusmn;2.32%</td>
    <td style="white-space: nowrap; text-align: right">13400.92 &micro;s</td>
    <td style="white-space: nowrap; text-align: right">14751.77 &micro;s</td>
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
    <td style="white-space: nowrap;text-align: right">528792.30 K</td>
    <td>&nbsp;</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle cache warm</td>
    <td style="white-space: nowrap; text-align: right">2347.01 K</td>
    <td style="white-space: nowrap; text-align: right">225.3x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit append onto 10k chain</td>
    <td style="white-space: nowrap; text-align: right">570.10 K</td>
    <td style="white-space: nowrap; text-align: right">927.54x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit inclusion verify 10k</td>
    <td style="white-space: nowrap; text-align: right">127.23 K</td>
    <td style="white-space: nowrap; text-align: right">4156.18x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap; text-align: right">71.43 K</td>
    <td style="white-space: nowrap; text-align: right">7403.26x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap; text-align: right">69.09 K</td>
    <td style="white-space: nowrap; text-align: right">7654.04x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap; text-align: right">38.37 K</td>
    <td style="white-space: nowrap; text-align: right">13781.39x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap; text-align: right">37.11 K</td>
    <td style="white-space: nowrap; text-align: right">14250.5x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap; text-align: right">32.52 K</td>
    <td style="white-space: nowrap; text-align: right">16260.64x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap; text-align: right">21.12 K</td>
    <td style="white-space: nowrap; text-align: right">25043.27x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap; text-align: right">15.80 K</td>
    <td style="white-space: nowrap; text-align: right">33462.05x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap; text-align: right">15.53 K</td>
    <td style="white-space: nowrap; text-align: right">34055.01x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap; text-align: right">11.40 K</td>
    <td style="white-space: nowrap; text-align: right">46369.95x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap; text-align: right">9.97 K</td>
    <td style="white-space: nowrap; text-align: right">53040.03x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap; text-align: right">8.01 K</td>
    <td style="white-space: nowrap; text-align: right">65975.76x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap; text-align: right">1.28 K</td>
    <td style="white-space: nowrap; text-align: right">413559.92x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap; text-align: right">1.24 K</td>
    <td style="white-space: nowrap; text-align: right">425997.77x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap; text-align: right">0.171 K</td>
    <td style="white-space: nowrap; text-align: right">3098642.24x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0804 K</td>
    <td style="white-space: nowrap; text-align: right">6577806.49x</td>
  </tr>

  <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap; text-align: right">0.0743 K</td>
    <td style="white-space: nowrap; text-align: right">7117355.27x</td>
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
    <td style="white-space: nowrap">5.67 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1k</td>
    <td style="white-space: nowrap">4.34 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1k</td>
    <td style="white-space: nowrap">4.34 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate block</td>
    <td style="white-space: nowrap">57.08 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.08 tool gateway guard_request</td>
    <td style="white-space: nowrap">57.48 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate redact</td>
    <td style="white-space: nowrap">61.85 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate quarantine</td>
    <td style="white-space: nowrap">66.41 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.06 trust bundle verify cold</td>
    <td style="white-space: nowrap">27.10 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation verify</td>
    <td style="white-space: nowrap">57.95 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.05 attestation sign</td>
    <td style="white-space: nowrap">70.91 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.04 runtime stream 64k split secret</td>
    <td style="white-space: nowrap">77.14 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.03 runtime gate allow</td>
    <td style="white-space: nowrap">50.13 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 64k</td>
    <td style="white-space: nowrap">4.37 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 64k</td>
    <td style="white-space: nowrap">95.43 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.07 audit checkpoint create 10k</td>
    <td style="white-space: nowrap">4063.78 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.01 scan clean 1m</td>
    <td style="white-space: nowrap">4.48 KB</td>
    <td>&mdash;</td>
  </tr>
    <tr>
    <td style="white-space: nowrap">BM.02 scan hits 1m</td>
    <td style="white-space: nowrap">1472.49 KB</td>
    <td>&mdash;</td>
  </tr>
</table>
