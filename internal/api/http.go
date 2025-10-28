package api

import (
	"encoding/json"
	"net/http"

	"github.com/gigvault/ca/internal/service"
	"github.com/gigvault/shared/pkg/logger"
	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

// HTTPHandler handles HTTP requests for the CA service
type HTTPHandler struct {
	service *service.CAService
	logger  *logger.Logger
}

// NewHTTPHandler creates a new HTTP handler
func NewHTTPHandler(service *service.CAService, logger *logger.Logger) *HTTPHandler {
	return &HTTPHandler{
		service: service,
		logger:  logger,
	}
}

// Routes returns the HTTP router
func (h *HTTPHandler) Routes() http.Handler {
	r := mux.NewRouter()

	// Health check
	r.HandleFunc("/health", h.Health).Methods("GET")
	r.HandleFunc("/ready", h.Ready).Methods("GET")

	// Certificate operations
	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/certificates", h.ListCertificates).Methods("GET")
	api.HandleFunc("/certificates/{serial}", h.GetCertificate).Methods("GET")
	api.HandleFunc("/certificates/sign", h.SignCertificate).Methods("POST")
	api.HandleFunc("/certificates/{serial}/revoke", h.RevokeCertificate).Methods("POST")

	// CSR operations
	api.HandleFunc("/csr", h.SubmitCSR).Methods("POST")
	api.HandleFunc("/csr/{id}", h.GetCSR).Methods("GET")

	return h.loggingMiddleware(r)
}

// Health returns the health status
func (h *HTTPHandler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// Ready returns the readiness status
func (h *HTTPHandler) Ready(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

// ListCertificates lists all certificates
func (h *HTTPHandler) ListCertificates(w http.ResponseWriter, r *http.Request) {
	certs, err := h.service.ListCertificates(r.Context())
	if err != nil {
		h.logger.Error("Failed to list certificates", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(certs)
}

// GetCertificate retrieves a certificate by serial number
func (h *HTTPHandler) GetCertificate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serial := vars["serial"]

	cert, err := h.service.GetCertificate(r.Context(), serial)
	if err != nil {
		h.logger.Error("Failed to get certificate", zap.String("serial", serial), zap.Error(err))
		http.Error(w, "Certificate not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cert)
}

// SignCertificate signs a CSR and issues a certificate
func (h *HTTPHandler) SignCertificate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSR          string `json:"csr"`
		ValidityDays int    `json:"validity_days"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	cert, err := h.service.SignCertificate(r.Context(), req.CSR, req.ValidityDays)
	if err != nil {
		h.logger.Error("Failed to sign certificate", zap.Error(err))
		http.Error(w, "Failed to sign certificate", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cert)
}

// RevokeCertificate revokes a certificate
func (h *HTTPHandler) RevokeCertificate(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	serial := vars["serial"]

	if err := h.service.RevokeCertificate(r.Context(), serial); err != nil {
		h.logger.Error("Failed to revoke certificate", zap.String("serial", serial), zap.Error(err))
		http.Error(w, "Failed to revoke certificate", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// SubmitCSR submits a new CSR
func (h *HTTPHandler) SubmitCSR(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CSR         string `json:"csr"`
		SubmittedBy string `json:"submitted_by"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	csr, err := h.service.SubmitCSR(r.Context(), req.CSR, req.SubmittedBy)
	if err != nil {
		h.logger.Error("Failed to submit CSR", zap.Error(err))
		http.Error(w, "Failed to submit CSR", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(csr)
}

// GetCSR retrieves a CSR by ID
func (h *HTTPHandler) GetCSR(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// TODO: Implement GetCSR
	h.logger.Info("GetCSR called", zap.String("id", id))
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// loggingMiddleware logs HTTP requests
func (h *HTTPHandler) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.logger.Info("HTTP request",
			zap.String("method", r.Method),
			zap.String("path", r.URL.Path),
			zap.String("remote_addr", r.RemoteAddr),
		)
		next.ServeHTTP(w, r)
	})
}
