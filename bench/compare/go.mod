module github.com/lrweck/cloak/bench/compare

go 1.27.1

require (
	github.com/JAS0N-SMITH/redactlog v0.5.0
	github.com/alesr/redact v1.0.0
	github.com/lrweck/cloak v0.0.0
	github.com/m-mizutani/masq v0.2.3
	github.com/philiprehberger/go-slog-redact v0.4.0
	github.com/sudoki2015/sensitive v1.0.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	go.opentelemetry.io/otel v1.43.0 // indirect
)

replace github.com/lrweck/cloak => ../..
