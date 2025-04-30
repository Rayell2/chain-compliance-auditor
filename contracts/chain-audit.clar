;; chain-audit.clar
;; Chain Compliance Auditor - Central registry for smart contract auditing on the Stacks blockchain
;; This contract manages auditor registration, audit submissions, contract certifications, and 
;; provides transparency into the security status of registered contracts.

;; ========================================
;; Constants and Error Codes
;; ========================================

;; Error codes for function validation failures
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-AUDITOR (err u101))
(define-constant ERR-AUDITOR-EXISTS (err u102))
(define-constant ERR-AUDITOR-NOT-FOUND (err u103))
(define-constant ERR-CONTRACT-EXISTS (err u104))
(define-constant ERR-CONTRACT-NOT-FOUND (err u105))
(define-constant ERR-INVALID-RATING (err u106))
(define-constant ERR-AUDIT-EXISTS (err u107))
(define-constant ERR-AUDIT-NOT-FOUND (err u108))
(define-constant ERR-INVALID-VERSION (err u109))
(define-constant ERR-ALREADY-VOTED (err u110))
(define-constant ERR-INSUFFICIENT-REPUTATION (err u111))

;; Security rating boundaries
(define-constant MIN-SECURITY-RATING u1)
(define-constant MAX-SECURITY-RATING u10)

;; Minimum reputation required for certain governance actions
(define-constant MIN-GOVERNANCE-REPUTATION u50)

;; Audit status values
(define-constant STATUS-PENDING u1)
(define-constant STATUS-COMPLETED u2)
(define-constant STATUS-CERTIFIED u3)
(define-constant STATUS-REJECTED u4)

;; ========================================
;; Data Maps and Variables
;; ========================================

;; Manage the platform administrators
(define-data-var platform-admin principal tx-sender)

;; Auditor registry with credentials and reputation
(define-map auditors
  { id: principal }
  {
    name: (string-ascii 64),
    credentials: (string-utf8 256),
    reputation: uint,
    active: bool,
    registration-time: uint
  }
)

;; Contracts registered for auditing
(define-map registered-contracts
  { contract-id: (string-ascii 128) }
  {
    owner: principal,
    contract-principal: principal,
    description: (string-utf8 256),
    source-code-hash: (buff 32),
    registration-time: uint,
    version: (string-ascii 32),
    status: uint
  }
)

;; Store detailed audit reports
(define-map audit-reports
  { contract-id: (string-ascii 128), auditor: principal, version: (string-ascii 32) }
  {
    timestamp: uint,
    security-score: uint,
    code-quality-score: uint,
    performance-score: uint,
    overall-rating: uint,
    findings: (string-utf8 1024),
    recommendations: (string-utf8 1024),
    status: uint
  }
)

;; Track certifications awarded to contracts
(define-map certifications
  { contract-id: (string-ascii 128), version: (string-ascii 32) }
  {
    certification-time: uint,
    expiration-time: uint,
    certification-level: (string-ascii 32),
    certified-by: principal
  }
)

;; Track auditor votes for governance purposes
(define-map auditor-votes
  { proposal-id: (string-ascii 64), auditor: principal }
  { vote: bool, vote-time: uint }
)

;; Counter for total registered auditors
(define-data-var auditor-count uint u0)

;; ========================================
;; Private Functions
;; ========================================

;; Check if caller is the platform admin
(define-private (is-platform-admin)
  (is-eq tx-sender (var-get platform-admin))
)

;; Check if caller is a registered auditor
(define-private (is-registered-auditor (auditor principal))
  (default-to false (get active (map-get? auditors { id: auditor })))
)

;; Check if caller is the contract owner
(define-private (is-contract-owner (contract-id (string-ascii 128)))
  (let ((contract-data (map-get? registered-contracts { contract-id: contract-id })))
    (and 
      (is-some contract-data)
      (is-eq tx-sender (get owner (unwrap-panic contract-data)))
    )
  )
)

;; Calculate the average of multiple security ratings
(define-private (calculate-average (scores (list 3 uint)))
  (if (is-eq (len scores) u0)
    u0
    (/ (fold + scores u0) (len scores))
  )
)

;; Validate security rating is within allowed range
(define-private (validate-rating (rating uint))
  (and (>= rating MIN-SECURITY-RATING) (<= rating MAX-SECURITY-RATING))
)

;; ========================================
;; Read-Only Functions
;; ========================================

;; Get platform admin
(define-read-only (get-platform-admin)
  (var-get platform-admin)
)

;; Get auditor information
(define-read-only (get-auditor-info (auditor principal))
  (map-get? auditors { id: auditor })
)

;; Get contract information
(define-read-only (get-contract-info (contract-id (string-ascii 128)))
  (map-get? registered-contracts { contract-id: contract-id })
)

;; Get audit report details
(define-read-only (get-audit-report (contract-id (string-ascii 128)) (auditor principal) (version (string-ascii 32)))
  (map-get? audit-reports { contract-id: contract-id, auditor: auditor, version: version })
)

;; Get certification details for a contract
(define-read-only (get-certification (contract-id (string-ascii 128)) (version (string-ascii 32)))
  (map-get? certifications { contract-id: contract-id, version: version })
)

;; Check if a contract is certified
(define-read-only (is-contract-certified (contract-id (string-ascii 128)) (version (string-ascii 32)))
  (is-some (map-get? certifications { contract-id: contract-id, version: version }))
)

;; Get total number of registered auditors
(define-read-only (get-auditor-count)
  (var-get auditor-count)
)

;; ========================================
;; Public Functions
;; ========================================

;; Change platform administrator
(define-public (set-platform-admin (new-admin principal))
  (begin
    (asserts! (is-platform-admin) ERR-NOT-AUTHORIZED)
    (ok (var-set platform-admin new-admin))
  )
)

;; Register a new auditor
(define-public (register-auditor (name (string-ascii 64)) (credentials (string-utf8 256)))
  (let ((auditor tx-sender))
    (asserts! (not (is-registered-auditor auditor)) ERR-AUDITOR-EXISTS)
    
    (map-set auditors
      { id: auditor }
      {
        name: name,
        credentials: credentials,
        reputation: u10, ;; Starting reputation
        active: true,
        registration-time: block-height
      }
    )
    
    (var-set auditor-count (+ (var-get auditor-count) u1))
    (ok true)
  )
)

;; Allow platform admin to approve or deactivate an auditor
(define-public (update-auditor-status (auditor principal) (active bool))
  (begin
    (asserts! (is-platform-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? auditors { id: auditor })) ERR-AUDITOR-NOT-FOUND)
    
    (let ((current-data (unwrap-panic (map-get? auditors { id: auditor }))))
      (map-set auditors
        { id: auditor }
        (merge current-data { active: active })
      )
      (ok true)
    )
  )
)

;; Register a contract for auditing
(define-public (register-contract 
  (contract-id (string-ascii 128)) 
  (contract-principal principal) 
  (description (string-utf8 256)) 
  (source-code-hash (buff 32))
  (version (string-ascii 32)))
  (begin
    (asserts! (not (is-some (map-get? registered-contracts { contract-id: contract-id }))) ERR-CONTRACT-EXISTS)
    
    (map-set registered-contracts
      { contract-id: contract-id }
      {
        owner: tx-sender,
        contract-principal: contract-principal,
        description: description,
        source-code-hash: source-code-hash,
        registration-time: block-height,
        version: version,
        status: STATUS-PENDING
      }
    )
    (ok true)
  )
)

;; Update contract version or details
(define-public (update-contract 
  (contract-id (string-ascii 128)) 
  (description (string-utf8 256)) 
  (source-code-hash (buff 32))
  (version (string-ascii 32)))
  (begin
    (asserts! (is-contract-owner contract-id) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? registered-contracts { contract-id: contract-id })) ERR-CONTRACT-NOT-FOUND)
    
    (let ((current-data (unwrap-panic (map-get? registered-contracts { contract-id: contract-id }))))
      (map-set registered-contracts
        { contract-id: contract-id }
        (merge current-data {
          description: description,
          source-code-hash: source-code-hash,
          version: version,
          status: STATUS-PENDING
        })
      )
      (ok true)
    )
  )
)

;; Submit an audit report for a contract
(define-public (submit-audit 
  (contract-id (string-ascii 128)) 
  (version (string-ascii 32))
  (security-score uint) 
  (code-quality-score uint) 
  (performance-score uint)
  (findings (string-utf8 1024))
  (recommendations (string-utf8 1024)))
  (let (
    (auditor tx-sender)
    (overall-rating (calculate-average (list security-score code-quality-score performance-score)))
    (contract-data (map-get? registered-contracts { contract-id: contract-id }))
  )
    ;; Validate inputs
    (asserts! (is-registered-auditor auditor) ERR-INVALID-AUDITOR)
    (asserts! (is-some contract-data) ERR-CONTRACT-NOT-FOUND)
    (asserts! (is-eq version (get version (unwrap-panic contract-data))) ERR-INVALID-VERSION)
    (asserts! (validate-rating security-score) ERR-INVALID-RATING)
    (asserts! (validate-rating code-quality-score) ERR-INVALID-RATING)
    (asserts! (validate-rating performance-score) ERR-INVALID-RATING)
    
    ;; Check if this auditor already submitted a report for this version
    (asserts! (not (is-some (map-get? audit-reports 
      { contract-id: contract-id, auditor: auditor, version: version }))) 
      ERR-AUDIT-EXISTS)
    
    ;; Record the audit report
    (map-set audit-reports
      { contract-id: contract-id, auditor: auditor, version: version }
      {
        timestamp: block-height,
        security-score: security-score,
        code-quality-score: code-quality-score,
        performance-score: performance-score,
        overall-rating: overall-rating,
        findings: findings,
        recommendations: recommendations,
        status: STATUS-COMPLETED
      }
    )
    
    ;; Update contract status
    (map-set registered-contracts
      { contract-id: contract-id }
      (merge (unwrap-panic contract-data) { status: STATUS-COMPLETED })
    )
    
    (ok true)
  )
)

;; Issue a certification for a contract that passed auditing
(define-public (issue-certification 
  (contract-id (string-ascii 128)) 
  (version (string-ascii 32))
  (certification-level (string-ascii 32))
  (expiration-blocks uint))
  (begin
    (asserts! (is-platform-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? registered-contracts { contract-id: contract-id })) ERR-CONTRACT-NOT-FOUND)
    
    (let ((contract-data (unwrap-panic (map-get? registered-contracts { contract-id: contract-id }))))
      ;; Ensure contract version matches
      (asserts! (is-eq version (get version contract-data)) ERR-INVALID-VERSION)
      
      ;; Create certification
      (map-set certifications
        { contract-id: contract-id, version: version }
        {
          certification-time: block-height,
          expiration-time: (+ block-height expiration-blocks),
          certification-level: certification-level,
          certified-by: tx-sender
        }
      )
      
      ;; Update contract status to certified
      (map-set registered-contracts
        { contract-id: contract-id }
        (merge contract-data { status: STATUS-CERTIFIED })
      )
      
      (ok true)
    )
  )
)

;; Rate another auditor to affect their reputation
(define-public (rate-auditor (auditor principal) (increase bool))
  (let ((rater tx-sender))
    (asserts! (is-registered-auditor rater) ERR-INVALID-AUDITOR)
    (asserts! (is-registered-auditor auditor) ERR-AUDITOR-NOT-FOUND)
    (asserts! (not (is-eq rater auditor)) ERR-NOT-AUTHORIZED)
    
    (let ((current-data (unwrap-panic (map-get? auditors { id: auditor }))))
      (map-set auditors
        { id: auditor }
        (merge current-data {
          reputation: (if increase 
                        (+ (get reputation current-data) u1)
                        (if (> (get reputation current-data) u1)
                          (- (get reputation current-data) u1)
                          u1))
        })
      )
      (ok true)
    )
  )
)

;; Vote on governance proposals
(define-public (vote-on-proposal (proposal-id (string-ascii 64)) (vote bool))
  (let (
    (auditor tx-sender)
    (auditor-data (map-get? auditors { id: auditor }))
  )
    (asserts! (is-some auditor-data) ERR-INVALID-AUDITOR)
    (asserts! (>= (get reputation (unwrap-panic auditor-data)) MIN-GOVERNANCE-REPUTATION) 
      ERR-INSUFFICIENT-REPUTATION)
    (asserts! (not (is-some (map-get? auditor-votes { proposal-id: proposal-id, auditor: auditor })))
      ERR-ALREADY-VOTED)
    
    (map-set auditor-votes
      { proposal-id: proposal-id, auditor: auditor }
      { vote: vote, vote-time: block-height }
    )
    (ok true)
  )
)

;; Reject a contract audit (mark as failed)
(define-public (reject-audit (contract-id (string-ascii 128)) (version (string-ascii 32)) (reason (string-utf8 256)))
  (begin
    (asserts! (is-platform-admin) ERR-NOT-AUTHORIZED)
    (asserts! (is-some (map-get? registered-contracts { contract-id: contract-id })) ERR-CONTRACT-NOT-FOUND)
    
    (let ((contract-data (unwrap-panic (map-get? registered-contracts { contract-id: contract-id }))))
      ;; Ensure contract version matches
      (asserts! (is-eq version (get version contract-data)) ERR-INVALID-VERSION)
      
      ;; Update contract status to rejected
      (map-set registered-contracts
        { contract-id: contract-id }
        (merge contract-data { status: STATUS-REJECTED })
      )
      
      (ok true)
    )
  )
)