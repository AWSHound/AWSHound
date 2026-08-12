package progress

// Multi returns a Reporter that forwards every call to each of rs, in order. Nil
// reporters are dropped. Use it to drive the interactive display and a metrics
// accumulator (which also implements Reporter) from the same Stage/Advance/Stop
// calls, so neither the pipeline nor the collectors need to know both exist.
func Multi(rs ...Reporter) Reporter {
	kept := make(multi, 0, len(rs))
	for _, r := range rs {
		if r != nil {
			kept = append(kept, r)
		}
	}
	return kept
}

type multi []Reporter

func (m multi) Stage(name string, total int) {
	for _, r := range m {
		r.Stage(name, total)
	}
}

// SetStageLabel changes only the active display label on reporters that support
// it. Loggers and metrics deliberately keep the stable top-level stage name.
func (m multi) SetStageLabel(name string) {
	for _, r := range m {
		if labeler, ok := r.(interface{ SetStageLabel(string) }); ok {
			labeler.SetStageLabel(name)
		}
	}
}

func (m multi) AddTotal(n int) {
	for _, r := range m {
		r.AddTotal(n)
	}
}

func (m multi) Advance(n int) {
	for _, r := range m {
		r.Advance(n)
	}
}

func (m multi) Log(msg string) {
	for _, r := range m {
		r.Log(msg)
	}
}

// Detail forwards verbose details only to reporters that support them. In the
// usual display+metrics pair this reaches Logger, while Tracker and RunMetrics
// remain silent.
func (m multi) Detail(format string, args ...any) {
	for _, r := range m {
		if detailer, ok := r.(Detailer); ok {
			detailer.Detail(format, args...)
		}
	}
}

func (m multi) Stop() {
	for _, r := range m {
		r.Stop()
	}
}
