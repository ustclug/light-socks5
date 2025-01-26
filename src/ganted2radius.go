package main

import (
	"bufio"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/context"
	"layeh.com/radius"
	"layeh.com/radius/rfc2865"
	"layeh.com/radius/rfc2866"
)

// compressFile compresses the given file using zstd compression.
// if the compressed file exists or any operation fails,
// it returns an error.
func compressFile(filepath string) error {
	// open the file
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	compressedFilepath := filepath + ".zst"
	// Check if the file already exists first
	if _, err := os.Stat(compressedFilepath); err == nil {
		return fmt.Errorf("file %s exists", compressedFilepath)
	} else if !os.IsNotExist(err) {
		// If the error is something other than "file does not exist", return it
		return err
	}
	// Create the file if it does not exist
	compressedFile, err := os.Create(compressedFilepath)
	if err != nil {
		return err
	}
	defer compressedFile.Close()
	// create the zstd writer
	zw, err := zstd.NewWriter(compressedFile)
	if err != nil {
		return err
	}
	// copy the file to the zstd writer
	_, err = io.Copy(zw, file)
	if err != nil {
		return err
	}
	// flush the zstd writer
	if err := zw.Close(); err != nil {
		return err
	}
	// remove the original file
	if err := os.Remove(filepath); err != nil {
		return err
	}
	return nil
}

func findLogs(logDir string, logPattern *regexp.Regexp) ([]string, error) {
	var logFiles []string
	err := filepath.WalkDir(logDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && logPattern.MatchString(d.Name()) {
			logFiles = append(logFiles, path)
		}
		return nil
	})
	return logFiles, err
}

func archiveLogs(logDir string, maxBackup int) error {
	logPattern := regexp.MustCompile(`^access-\d{14}\.log$`)
	logFiles, err := findLogs(logDir, logPattern)
	if err != nil {
		return err
	}
	if len(logFiles) >= maxBackup {
		sort.Strings(logFiles)
		// create archive log file with current date
		date := time.Now().Format("20060102")
		archiveFileName := fmt.Sprintf("archived-access-%s.log", date)
		archiveFilePath := filepath.Join(logDir, archiveFileName)
		// check if access-<date>.log.zst exists first
		if _, err := os.Stat(archiveFilePath + ".zst"); err == nil {
			return fmt.Errorf("file %s exists", archiveFileName+".zst")
		} else if !os.IsNotExist(err) {
			// If the error is something other than "file does not exist", return it
			return err
		}
		archiveFile, err := os.Create(archiveFilePath)
		if err != nil {
			return err
		}
		defer archiveFile.Close()
		// concatenate `maxBackup` access-<datetime>.log files to access-<date>.log
		for _, logFile := range logFiles {
			src, err := os.Open(logFile)
			if err != nil {
				return err
			}
			defer src.Close()
			_, err = io.Copy(archiveFile, src)
			if err != nil {
				return err
			}

		}
		// compress access-<date>.log
		if err := compressFile(archiveFilePath); err != nil {
			return err
		}
		// If the archiveFile exists, some error occur, and archiveFile need to delete
		// As the compressFile will remove the original archiveFile
		// Else, everything is ok, delete the original log files
		if _, err := os.Stat(archiveFilePath); !os.IsNotExist(err) {
			if err := os.Remove(archiveFilePath); err != nil {
				return fmt.Errorf("err when removing file %s", archiveFilePath)
			}
		} else if err == nil {
			for _, logFile := range logFiles {
				if err := os.Remove(logFile); err != nil {
					return fmt.Errorf("err when removing file %s", logFile)
				}
			}
		} else {
			return fmt.Errorf("Unknown err when clear original log file")
		}
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
		if len(fields) != 8 {
			log.Printf("Skipping malformed line: %s\n", line)
			continue
		}

		identity := fields[3]
		bytesIn, err := strconv.Atoi(fields[6])
		if err != nil {
			log.Printf("Error parsing bytes in: %v\n", err)
			continue
		}
		bytesOut, err := strconv.Atoi(fields[7])
		if err != nil {
			log.Printf("Error parsing bytes out: %v\n", err)
			continue
		}
		totalBytes := bytesIn + bytesOut

		stats[identity] += totalBytes
	}

	return stats, scanner.Err()
}

func (r *RadiusCredentials) sendAccountingData(identity string, bytes int) error {
	// send an CodeAccessRequest for test
	sessionID := strconv.FormatInt(time.Now().Unix(), 10)
	log.Printf("Sending accounting data for identity %s, session ID %s, bytes %d\n", identity, sessionID, bytes)

	// Send start accounting packet
	startPacket := radius.New(radius.CodeAccountingRequest, []byte(r.Secret))
	rfc2865.UserName_SetString(startPacket, identity)
	rfc2865.NASIdentifier_SetString(startPacket, r.NASIdentifier)
	rfc2866.AcctSessionID_Set(startPacket, []byte(sessionID))
	rfc2866.AcctStatusType_Set(startPacket, rfc2866.AcctStatusType_Value_Start)
	// log.Printf("Sending start packet\n")

	startReply, err := radius.Exchange(context.Background(), startPacket, r.AccountingServer)
	if err != nil {
		return err
	}
	if startReply.Code != radius.CodeAccountingResponse {
		return fmt.Errorf("unexpected response from RADIUS server")
	}
	// log.Printf("Received start reply\n")

	// Send stop accounting packet
	stopPacket := radius.New(radius.CodeAccountingRequest, r.Secret)
	rfc2865.UserName_SetString(stopPacket, identity)
	rfc2865.NASIdentifier_SetString(stopPacket, r.NASIdentifier)
	rfc2866.AcctSessionID_SetString(stopPacket, sessionID)
	rfc2866.AcctStatusType_Set(stopPacket, rfc2866.AcctStatusType_Value_Stop)
	rfc2866.AcctOutputOctets_Set(stopPacket, rfc2866.AcctOutputOctets(bytes))
	// log.Printf("Sending stop packet\n")

	stopReply, err := radius.Exchange(context.Background(), stopPacket, r.AccountingServer)
	if err != nil {
		return err
	}
	if stopReply.Code != radius.CodeAccountingResponse {
		return fmt.Errorf("unexpected response from RADIUS server")
	}
	// log.Printf("Received stop reply\n")

	return nil
}

func (r *RadiusCredentials) accounting(accessLogger *log.Logger) error {
	// Get the log directory
	accessLogFileHandler, ok := accessLogger.Writer().(*os.File)
	if !ok {
		return fmt.Errorf("access log file is not a file")
	}
	accessLogFile := accessLogFileHandler.Name()
	logDir := filepath.Dir(accessLogFile)
	// rename the access.log file to access-<datetime>.log
	now := time.Now()
	dotIndex := strings.LastIndex(accessLogFile, ".")
	accountingLogFile := accessLogFile[:dotIndex] + "-" + now.Format("20060102150405") + accessLogFile[dotIndex:]
	if err := os.Rename(accessLogFile, accountingLogFile); err != nil {
		return err
	}
	// ask accessLogger to reopen the access.log file
	if err := setFileLoggerOutput(accessLogger, accessLogFile); err != nil {
		return err
	}
	stats, err := parseLogFile(accountingLogFile)
	if err != nil {
		log.Printf("[ERR] Failed to parse log file %s: %v\n", accountingLogFile, err)
		return err
	}
	// Sending accounting data
	for identity, bytes := range stats {
		err := r.sendAccountingData(identity, bytes)
		if err != nil {
			log.Printf("[ERR] Failed to send accounting data for identity %s: %v\n", identity, err)
		} else {
			log.Printf("Sent accounting data for identity %s\n", identity)
		}
	}
	// Compress all access-<datetime>.log files in the log directory
	if err := archiveLogs(logDir, 24); err != nil {
		return err
	}
	return nil
}
