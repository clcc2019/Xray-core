package metrics

import (
	"context"
	"expvar"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"strings"

	"github.com/xtls/xray-core/app/observatory"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/extension"
	"github.com/xtls/xray-core/features/outbound"
	feature_stats "github.com/xtls/xray-core/features/stats"
)

type MetricsHandler struct {
	ohm          outbound.Manager
	statsManager feature_stats.Manager
	observatory  extension.Observatory
	tag          string
	listen       string
	tcpListener  net.Listener
}

// NewMetricsHandler creates a new MetricsHandler based on the given config.
func NewMetricsHandler(ctx context.Context, config *Config) (*MetricsHandler, error) {
	c := &MetricsHandler{
		tag:    config.Tag,
		listen: config.Listen,
	}
	common.Must(core.RequireFeatures(ctx, func(om outbound.Manager, sm feature_stats.Manager) {
		c.statsManager = sm
		c.ohm = om
	}))
	expvar.Publish("stats", expvar.Func(func() interface{} {
		manager, ok := c.statsManager.(*stats.Manager)
		if !ok {
			return nil
		}
		resp := map[string]map[string]map[string]int64{
			"inbound":  {},
			"outbound": {},
			"user":     {},
		}
		manager.VisitCounters(func(name string, counter feature_stats.Counter) bool {
			nameSplit := strings.Split(name, ">>>")
			typeName, tagOrUser, direction := nameSplit[0], nameSplit[1], nameSplit[3]
			if item, found := resp[typeName][tagOrUser]; found {
				item[direction] = counter.Value()
			} else {
				resp[typeName][tagOrUser] = map[string]int64{
					direction: counter.Value(),
				}
			}
			return true
		})
		return resp
	}))
	expvar.Publish("observatory", expvar.Func(func() interface{} {
		if c.observatory == nil {
			common.Must(core.RequireFeatures(ctx, func(observatory extension.Observatory) error {
				c.observatory = observatory
				return nil
			}))
			if c.observatory == nil {
				return nil
			}
		}
		resp := map[string]*observatory.OutboundStatus{}
		if o, err := c.observatory.GetObservation(context.Background()); err != nil {
			return err
		} else {
			for _, x := range o.(*observatory.ObservationResult).GetStatus() {
				resp[x.OutboundTag] = x
			}
		}
		return resp
	}))
	return c, nil
}

func (p *MetricsHandler) Type() interface{} {
	return (*MetricsHandler)(nil)
}

func (p *MetricsHandler) Start() error {

	// direct listen a port if listen is set
	if p.listen != "" {
		TCPlistener, err := net.Listen("tcp", p.listen)
		if err != nil {
			return err
		}
		p.tcpListener = TCPlistener
		errors.LogInfo(context.Background(), "Metrics server listening on ", p.listen)

		go func() {
			if err := http.Serve(TCPlistener, http.DefaultServeMux); err != nil {
				errors.LogErrorInner(context.Background(), err, "failed to start metrics server")
			}
		}()
	}

	listener := &OutboundListener{
		buffer: make(chan net.Conn, 4),
		done:   done.New(),
	}

	go func() {
		if err := http.Serve(listener, http.DefaultServeMux); err != nil {
			errors.LogErrorInner(context.Background(), err, "failed to start metrics server")
		}
	}()

	if err := p.ohm.RemoveHandler(context.Background(), p.tag); err != nil {
		errors.LogInfo(context.Background(), "failed to remove existing handler")
	}

	return p.ohm.AddHandler(context.Background(), &Outbound{
		tag:      p.tag,
		listener: listener,
	})
}

func (p *MetricsHandler) Close() error {
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		return NewMetricsHandler(ctx, cfg.(*Config))
	}))

	// Lightweight dashboard: /debug/charts
	charts := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Simple HTML + Chart.js that polls /debug/vars and renders xtls-related metrics
		// Uses deltas to plot per-second rates
		fmt.Fprint(w, `<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Xray expvar charts</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 16px; background:#0b1220; color:#d8e1f0; }
    .row { display:flex; flex-wrap:wrap; gap:16px; }
    .card { background:#111a2b; border:1px solid #1f2c45; border-radius:8px; padding:12px; flex:1; min-width:320px; }
    h1 { font-size: 20px; margin: 0 0 12px; }
    canvas { background:#0b1220; }
    .muted { color:#8aa0bf; font-size:12px }
  </style>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    const maxPoints = 180; // 3 minutes @1s
    const state = {
      last: {},
      series: {
        paddingBytesRate: [],
        pacingMicrosRate: [],
        directCopy: [],
        budgetHits: []
      },
      labels: []
    };

    function nowLabel(){
      const d = new Date();
      return d.toLocaleTimeString();
    }

    function pushPoint(arr, v){
      arr.push(v); if (arr.length>maxPoints) arr.shift();
    }

    function sumCounters(obj){ let s=0; for(const k in obj){ const v=obj[k]; for(const d in v){ for(const dir in v[d]){ s+= +v[d][dir]||0; } } } return s; }
    async function poll(){
      try{
        const res = await fetch('/debug/vars',{cache:'no-cache'});
        const j = await res.json();
        const x = {
          pad: +(j.xtls_padding_bytes_total||0),
          pace: +(j.xtls_pacing_micros_total||0),
          dc: +(j.xtls_direct_copy_engaged_total||0),
          budget: +(j.xtls_padding_budget_exhausted_total||0)
        };
        // bandwidth from stats
        let inTotal=0, outTotal=0;
        if (j.stats){
          if (j.stats.inbound) inTotal = sumCounters(j.stats.inbound);
          if (j.stats.outbound) outTotal = sumCounters(j.stats.outbound);
        }
        // observatory avg delay
        let avgDelayMs=0, cnt=0;
        if (j.observatory){
          for (const tag in j.observatory){ const s=j.observatory[tag]; if (s && s.Delay){ avgDelayMs += s.Delay; cnt++; } }
          if (cnt>0) avgDelayMs/=cnt;
        }
        // optional placeholders (0 if absent)
        let activeConns = +(j.active_connections||0);
        let dnsLatencyMs = +(j.dns_latency_ms||0);
        const l = state.last;
        const dt = 1; // seconds
        const padRate = (l.pad!=null)? Math.max(0, x.pad - l.pad) / dt : 0;
        const paceRate = (l.pace!=null)? Math.max(0, x.pace - l.pace) / dt : 0;
        const dcRate = (l.dc!=null)? Math.max(0, x.dc - l.dc) / dt : 0;
        const budgetRate = (l.budget!=null)? Math.max(0, x.budget - l.budget) / dt : 0;
        const inRate = (l.inTotal!=null)? Math.max(0, inTotal - l.inTotal) / dt : 0;
        const outRate = (l.outTotal!=null)? Math.max(0, outTotal - l.outTotal) / dt : 0;

        pushPoint(state.series.paddingBytesRate, padRate);
        pushPoint(state.series.pacingMicrosRate, paceRate);
        pushPoint(state.series.directCopy, dcRate);
        pushPoint(state.series.budgetHits, budgetRate);
        pushPoint(state.labels, nowLabel());

        chartBw.data.datasets[0].data.push(inRate); if (chartBw.data.datasets[0].data.length>maxPoints) chartBw.data.datasets[0].data.shift();
        chartBw.data.datasets[1].data.push(outRate); if (chartBw.data.datasets[1].data.length>maxPoints) chartBw.data.datasets[1].data.shift();
        chartLatency.data.datasets[0].data.push(avgDelayMs); if (chartLatency.data.datasets[0].data.length>maxPoints) chartLatency.data.datasets[0].data.shift();
        chartMisc.data.datasets[0].data.push(activeConns); if (chartMisc.data.datasets[0].data.length>maxPoints) chartMisc.data.datasets[0].data.shift();
        chartMisc.data.datasets[1].data.push(dnsLatencyMs); if (chartMisc.data.datasets[1].data.length>maxPoints) chartMisc.data.datasets[1].data.shift();

        state.last = Object.assign({}, x, {inTotal, outTotal});
        updateCharts();
      }catch(e){ console.warn(e); }
    }

    let chartXtls, chartBw, chartLatency, chartMisc;
    function setup(){
      const xtls = document.getElementById('chart_xtls').getContext('2d');
      chartXtls = new Chart(xtls, {
        type: 'line',
        data: {
          labels: state.labels,
          datasets: [
            { label: 'XTLS padding bytes/s', data: state.series.paddingBytesRate, borderColor:'#4cc9f0', backgroundColor:'rgba(76,201,240,0.15)', tension:0.25 },
            { label: 'pacing micros/s', data: state.series.pacingMicrosRate, borderColor:'#ffd166', backgroundColor:'rgba(255,209,102,0.15)', tension:0.25 },
            { label: 'direct-copy engages/s', data: state.series.directCopy, borderColor:'#06d6a0', backgroundColor:'rgba(6,214,160,0.15)', tension:0.25, yAxisID:'y2' },
            { label: 'padding budget hits/s', data: state.series.budgetHits, borderColor:'#ef476f', backgroundColor:'rgba(239,71,111,0.15)', tension:0.25, yAxisID:'y2' }
          ]
        },
        options: {
          responsive: true,
          animation: false,
          interaction: { intersect:false, mode:'nearest' },
          scales: {
            y: { beginAtZero:true, grid:{ color:'rgba(255,255,255,0.05)' }, ticks:{ color:'#8aa0bf' } },
            y2: { position:'right', beginAtZero:true, grid:{ display:false }, ticks:{ color:'#8aa0bf' } },
            x: { grid:{ color:'rgba(255,255,255,0.05)' }, ticks:{ color:'#8aa0bf', maxRotation:0 } }
          },
          plugins:{ legend:{ labels:{ color:'#d8e1f0' } } }
        }
      });
      // 传输吞吐/延迟/连接数（放在 setup 内创建，确保元素已存在）
      const bw = document.getElementById('chart_bw').getContext('2d');
      chartBw = new Chart(bw, { type:'line', data:{ labels: state.labels, datasets:[
        { label:'Inbound bytes/s', data:[], borderColor:'#a78bfa', backgroundColor:'rgba(167,139,250,0.15)', tension:0.25 },
        { label:'Outbound bytes/s', data:[], borderColor:'#60a5fa', backgroundColor:'rgba(96,165,250,0.15)', tension:0.25 }
      ]}, options:{ responsive:true, animation:false, plugins:{legend:{labels:{color:'#d8e1f0'}}}, scales:{x:{ticks:{color:'#8aa0bf'}},y:{beginAtZero:true,ticks:{color:'#8aa0bf'}}} });

      const lat = document.getElementById('chart_latency').getContext('2d');
      chartLatency = new Chart(lat, { type:'line', data:{ labels: state.labels, datasets:[
        { label:'Avg outbound delay (ms)', data:[], borderColor:'#34d399', backgroundColor:'rgba(52,211,153,0.15)', tension:0.25 }
      ]}, options:{ responsive:true, animation:false, plugins:{legend:{labels:{color:'#d8e1f0'}}}, scales:{x:{ticks:{color:'#8aa0bf'}},y:{beginAtZero:true,ticks:{color:'#8aa0bf'}}} });

      const misc = document.getElementById('chart_misc').getContext('2d');
      chartMisc = new Chart(misc, { type:'line', data:{ labels: state.labels, datasets:[
        { label:'Active connections', data:[], borderColor:'#f59e0b', backgroundColor:'rgba(245,158,11,0.15)', tension:0.25 },
        { label:'DNS latency (ms)', data:[], borderColor:'#f472b6', backgroundColor:'rgba(244,114,182,0.15)', tension:0.25, yAxisID:'y2' }
      ]}, options:{ responsive:true, animation:false, plugins:{legend:{labels:{color:'#d8e1f0'}}}, scales:{x:{ticks:{color:'#8aa0bf'}},y:{beginAtZero:true,ticks:{color:'#8aa0bf'}},y2:{position:'right',beginAtZero:true,ticks:{color:'#8aa0bf'}}} });

      setInterval(poll, 1000);
    }

    function updateCharts(){
      if (!chartXtls) return;
      chartXtls.data.labels = state.labels;
      chartXtls.update('none');
      chartBw.data.labels = state.labels; chartBw.update('none');
      chartLatency.data.labels = state.labels; chartLatency.update('none');
      chartMisc.data.labels = state.labels; chartMisc.update('none');
    }
  </script>
</head>
<body onload="setup()">
  <h1>Xray Metrics Dashboard <span class="muted">(expvar)</span></h1>
  <div class="row">
    <div class="card">
      <h1>XTLS 内核与数据面</h1>
      <canvas id="chart_xtls" height="260"></canvas>
      <div class="muted">来源: <code>/debug/vars</code>，每秒刷新；左轴字节/微秒速率，右轴事件速率</div>
    </div>
    <div class="card">
      <h1>传输吞吐（总）</h1>
      <canvas id="chart_bw" height="260"></canvas>
      <div class="muted">来源: <code>stats</code>（inbound/outbound 累计字节），每秒刷新</div>
    </div>
  </div>
  <div class="row">
    <div class="card">
      <h1>出站延迟（平均）</h1>
      <canvas id="chart_latency" height="260"></canvas>
      <div class="muted">来源: <code>observatory</code>（各出站 Delay 平均），每秒刷新</div>
    </div>
    <div class="card">
      <h1>连接数 / DNS 延迟</h1>
      <canvas id="chart_misc" height="260"></canvas>
      <div class="muted">连接数与 DNS 延迟如有相应 expvar 字段将显示，否则为 0</div>
    </div>
  </div>
</body>
</html>`)
	}
	http.HandleFunc("/debug/charts", charts)
	// 便捷别名：/charts 也可打开
	http.HandleFunc("/charts", charts)
}
