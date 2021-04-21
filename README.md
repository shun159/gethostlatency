gethostlatency
---
eBPF u[ret]probe gethost\* function monitor (for my study)

```
2021-04-22 01:38:28.766684097 +09:00 pid: 1117947 comm: ThreadPoolForeg  host: api.github.com                 10.68 msec
2021-04-22 01:38:28.974783902 +09:00 pid: 1117947 comm: ThreadPoolForeg  host: www.google.com                      10.47 msec
2021-04-22 01:38:29.151899318 +09:00 pid: 1117261 comm: ThreadPoolForeg  host: fonts.gstatic.com                    7.72 msec
2021-04-22 01:38:33.214291130 +09:00 pid: 1117947 comm: ThreadPoolForeg  host: ogs.google.com                      10.74 msec
2021-04-22 01:38:33.528931046 +09:00 pid: 1117947 comm: ThreadPoolForeg  host: www.gstatic.com                      8.00 msec
2021-04-22 01:38:33.529068693 +09:00 pid: 1117261 comm: ThreadPoolForeg  host: ssl.gstatic.com                      7.00 msec
2021-04-22 01:38:33.530263687 +09:00 pid: 1119215 comm: ThreadPoolForeg  host: apis.google.com                      7.99 msec
2021-04-22 01:38:33.982535957 +09:00 pid: 1119240 comm: ThreadPoolForeg  host: play.google.com                      8.54 msec
```
