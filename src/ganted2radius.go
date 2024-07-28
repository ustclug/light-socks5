package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}

type RadiusAccountingCredentials struct {
	Server        string
	Secret        []byte
	NASIdentifier string
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: log_parser <logfile>")
		os.Exit(1)
	}

	radiusServer := getEnv("RADIUS_ACCOUNTING_SERVER", "127.0.0.1:1813")
	radiusSecret := getEnv("RADIUS_SECRET", "")
	nasIdentifier := getEnv("NAS_IDENTIFIER", "ganted")

	if radiusServer == "" || radiusSecret == "" {
		fmt.Println("RADIUS_SERVER and RADIUS_SECRET environment variables must be set")
		os.Exit(1)
	}

	logfile := os.Args[1]
	stats, err := parseLogFile(logfile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing log file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Parsed %d records from log file\n", len(stats))

	creds := RadiusAccountingCredentials{
		Server:        radiusServer,
		Secret:        []byte(radiusSecret),
		NASIdentifier: nasIdentifier,
	}

	for identity, bytes := range stats {
		err := sendAccountingData(creds, identity, bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error sending accounting data for identity %s: %v\n", identity, err)
		} else {
			fmt.Printf("Sent accounting data for identity %s\n", identity)
		}
	}
}

func parseLogFile(filename string) (map[string]int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats := make(map[string]int)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 8 {
			fmt.Printf("Skipping malformed line: %s\n", line)
			continue
		}

		identity := fields[3]
		bytesIn, _ := strconv.Atoi(fields[6])
		bytesOut, _ := strconv.Atoi(fields[7])
		totalBytes := bytesIn + bytesOut

		stats[identity] += totalBytes
	}

	return stats, scanner.Err()
}

func sendAccountingData(creds RadiusAccountingCredentials, identity string, bytes int) error {
        // send an CodeAccessRequest for test
	sessionID := strconv.FormatInt(time.Now().Unix(), 10)
	fmt.Printf("Sending accounting data for identity %s, session ID %s, bytes %d\n", identity, sessionID, bytes)

	// Send start accounting packet
	startPacket := radius.New(radius.CodeAccountingRequest, []byte(creds.Secret))
	rfc2865.UserName_SetString(startPacket, identity)
	// rfc2865.NASIdentifier_SetString(startPacket, creds.NASIdentifier)
	rfc2866.AcctSessionID_Set(startPacket, []byte(sessionID))
	rfc2866.AcctStatusType_Set(startPacket, rfc2866.AcctStatusType_Value_Start)
	fmt.Printf("Sending start packet\n")

	startReply, err := radius.Exchange(context.Background(), startPacket, creds.Server)
	if err != nil {
		return err
	}
	if startReply.Code != radius.CodeAccountingResponse {
		return fmt.Errorf("unexpected response from RADIUS server")
	}
	fmt.Printf("Received start reply\n")

	// Send stop accounting packet
	stopPacket := radius.New(radius.CodeAccountingRequest, []byte(creds.Secret))
	rfc2865.UserName_SetString(stopPacket, identity)
	rfc2865.NASIdentifier_SetString(stopPacket, creds.NASIdentifier)
	rfc2866.AcctSessionID_Set(stopPacket, []byte(sessionID))
	rfc2866.AcctStatusType_Set(stopPacket, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctOutputOctets_Set(stopPacket, rfc2866.AcctOutputOctets(bytes))
	fmt.Printf("Sending stop packet\n")

	stopReply, err := radius.Exchange(context.Background(), stopPacket, creds.Server)
	if err != nil {
		return err
	}
	if stopReply.Code != radius.CodeAccountingResponse {
		return fmt.Errorf("unexpected response from RADIUS server")
	}
	fmt.Printf("Received stop reply\n")

	return nil
}
