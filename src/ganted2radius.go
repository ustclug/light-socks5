package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/context"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

func archiveLog(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()
	// Copy the source file to the destination file
	_, err = io.Copy(dstFile, srcFile)
	if err != nil {
		return err
	}
	// Clear the source file
	err = os.Truncate(src, 0)
	if err != nil {
		return err
	}
	return nil
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

func (r *RadiusCredentials) sendAccountingData(identity string, bytes int) error {
	// send an CodeAccessRequest for test
	sessionID := strconv.FormatInt(time.Now().Unix(), 10)
	fmt.Printf("Sending accounting data for identity %s, session ID %s, bytes %d\n", identity, sessionID, bytes)

	// Send start accounting packet
	startPacket := radius.New(radius.CodeAccountingRequest, []byte(r.Secret))
	rfc2865.UserName_SetString(startPacket, identity)
	rfc2865.NASIdentifier_SetString(startPacket, r.NASIdentifier)
	rfc2866.AcctSessionID_Set(startPacket, []byte(sessionID))
	rfc2866.AcctStatusType_Set(startPacket, rfc2866.AcctStatusType_Value_Start)
	fmt.Printf("Sending start packet\n")

	startReply, err := radius.Exchange(context.Background(), startPacket, r.AccountingServer)
	if err != nil {
		return err
	}
	if startReply.Code != radius.CodeAccountingResponse {
		return fmt.Errorf("unexpected response from RADIUS server")
	}
	fmt.Printf("Received start reply\n")

	// Send stop accounting packet
	stopPacket := radius.New(radius.CodeAccountingRequest, r.Secret)
	rfc2865.UserName_SetString(stopPacket, identity)
	rfc2865.NASIdentifier_SetString(stopPacket, r.NASIdentifier)
	rfc2866.AcctSessionID_SetString(stopPacket, sessionID)
	rfc2866.AcctStatusType_Set(stopPacket, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctOutputOctets_Set(stopPacket, rfc2866.AcctOutputOctets(bytes))
	fmt.Printf("Sending stop packet\n")

	stopReply, err := radius.Exchange(context.Background(), stopPacket, r.AccountingServer)
	if err != nil {
		return err
	}
	if stopReply.Code != radius.CodeAccountingResponse {
		return fmt.Errorf("unexpected response from RADIUS server")
	}
	fmt.Printf("Received stop reply\n")

	return nil
}

func (r *RadiusCredentials) accounting(accessLogFile string, archiveLogFile string) error {
	if archiveLogFile == "" {
		archiveLogFile = filepath.Join(filepath.Dir(accessLogFile), "archive.log")
	}
	if err := archiveLog(accessLogFile, archiveLogFile); err != nil {
		return err
	}
	stats, err := parseLogFile(archiveLogFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing log file: %v\n", err)
		return err
	}

	for identity, bytes := range stats {
		err := r.sendAccountingData(identity, bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error sending accounting data for identity %s: %v\n", identity, err)
		} else {
			fmt.Printf("Sent accounting data for identity %s\n", identity)
		}
	}
	return nil
}
