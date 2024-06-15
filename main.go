package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

type EmailRequest struct {
	Email string `json:"email"`
}

type EmailResponse struct {
	Valid       bool   `json:"valid"`
	Reason      string `json:"reason,omitempty"`
	HasMX       bool   `json:"hasMX"`
	HasSPF      bool   `json:"hasSPF"`
	SPFRecord   string `json:"spfRecord,omitempty"`
	HasDMARC    bool   `json:"hasDMARC"`
	DMARCRecord string `json:"dmarcRecord,omitempty"`
}

func main() {
	http.HandleFunc("/verify", verifyEmailHandler)
	fmt.Println("starting server at :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Error in starting the server:", err)
	}
}
func verifyEmailHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {

		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	var req EmailRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	email := req.Email
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}
	valid, reason, hasMX, hasSPF, spfRecord, hasDMARC, dmarcRecord := isValidEmail(email)
	response := EmailResponse{
		Valid:       valid,
		Reason:      reason,
		HasMX:       hasMX,
		HasSPF:      hasSPF,
		SPFRecord:   spfRecord,
		HasDMARC:    hasDMARC,
		DMARCRecord: dmarcRecord,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
func isValidEmail(email string) (bool, string, bool, bool, string, bool, string) {
	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !re.MatchString(email) {
		return false, "Invalid email format", false, false, "", false, ""
	}
	// extract the domain part
	parts := strings.Split(email, "@")
	domain := parts[1]
	// check MX Records
	mxRecords, err := net.LookupMX(domain)
	hasMX := err == nil && len(mxRecords) > 0
	// check spf records
	hasSPF, spfRecord := checkSPF(domain)
	// Check DMARC records
	hasDMARC, dmarcRecord := checkDMARC(domain)
	if !hasMX {
		return false, "Domain does not have valid MX records", hasMX, hasSPF, spfRecord, hasDMARC, dmarcRecord
	}

	return true, "", hasMX, hasSPF, spfRecord, hasDMARC, dmarcRecord
}
func checkSPF(domain string) (bool, string) {
	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		return false, ""
	}
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			return true, record
		}
	}
	return false, ""
}
func checkDMARC(domain string) (bool, string) {
	dmarcDomain := "_dmarc." + domain
	txtRecords, err := net.LookupTXT(dmarcDomain)
	if err != nil {
		return false, ""
	}
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=DMARC1") {
			return true, record
		}
	}
	return false, ""
}
