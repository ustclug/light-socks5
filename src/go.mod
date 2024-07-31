module ganted

go 1.22.3

replace github.com/armon/go-socks5 => ./go-socks5

require (
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5
	github.com/kisom/netallow v0.0.0-20200609175051-08f6b004e41a
	github.com/klauspost/compress v1.17.9
	github.com/robfig/cron/v3 v3.0.1
	golang.org/x/net v0.25.0
	layeh.com/radius v0.0.0-20231213012653-1006025d24f8
)
