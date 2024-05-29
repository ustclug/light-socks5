module ganted

go 1.22.3

replace github.com/armon/go-socks5 => ./go-socks5

require (
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5
	github.com/kisom/netallow v0.0.0-20200609175051-08f6b004e41a
	layeh.com/radius v0.0.0-20231213012653-1006025d24f8
)

require golang.org/x/net v0.25.0 // indirect
