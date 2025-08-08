 
(define-constant ERR-NOT-AUTHORIZED u300)
(define-constant ERR-INVALID-EVENT u301)
(define-constant ERR-INVALID-SIGNATURE u302)
(define-constant ERR-INVALID-HASH u303)
(define-constant ERR-PAUSED u304)
(define-constant ERR-VERIFICATION-FAILED u305)
(define-constant ERR-INVALID-PRINCIPAL u306)

;; External contract references
(define-constant EVENT-LOGGER-CONTRACT .compliance-event-logger)
(define-constant ACCESS-CONTROL-CONTRACT .access-control-roles)

;; Contract state
(define-data-var admin principal tx-sender)
(define-data-var paused bool false)
(define-data-var verification-counter uint u0)

;; Verification status
(define-constant STATUS-PENDING u0)
(define-constant STATUS-VERIFIED u1)
(define-constant STATUS-REJECTED u2)

;; Maps
(define-map verifications 
  { event-id: uint }
  { 
    verifier: principal,
    status: uint,
    ipfs-hash: (string-ascii 64),
    signature: (string-ascii 130), ;; Mock 65-byte signature as hex string
    timestamp: uint,
    comment: (string-ascii 256)
  }
)

;; Event notification trait
(define-trait verification-notification-trait
  (
    (notify-verification (uint principal uint (string-ascii 64) (string-ascii 130) uint (string-ascii 256)) (response bool uint))
  )
)

(define-data-var notification-contract (optional principal) none)

;; Private helpers
(define-private (is-admin)
  (is-eq tx-sender (var-get admin))
)

(define-private (ensure-not-paused)
  (asserts! (not (var-get paused)) (err ERR-PAUSED))
)

(define-private (is-valid-principal (principal principal))
  (not (is-eq principal 'SP000000000000000000002Q6VF78))
)

(define-private (has-permission (principal principal) (permission-id uint))
  (let ((role-result (contract-call? ACCESS-CONTROL-CONTRACT get-role principal)))
    (if (is-ok role-result)
      (let ((role-id (get role-id (unwrap! role-result (err ERR-NOT-AUTHORIZED))))
            (perm-result (contract-call? ACCESS-CONTROL-CONTRACT has-permission role-id permission-id)))
        (if (is-ok perm-result)
          (get value perm-result)
          false
        )
      )
      false
    )
  )
)

(define-private (is-valid-ipfs-hash (hash (string-ascii 64)))
  (and (> (len hash) u0) (<= (len hash) u64))
)

(define-private (is-valid-signature (signature (string-ascii 130)))
  (is-eq (len signature) u130)
)

;; Admin functions
(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-valid-principal new-admin) (err ERR-INVALID-PRINCIPAL))
    (var-set admin new-admin)
    (ok true)
  )
)

(define-public (set-paused (pause bool))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (var-set paused pause)
    (ok true)
  )
)

(define-public (set-notification-contract (contract (optional principal)))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (var-set notification-contract contract)
    (ok true)
  )
)

;; Verification function
(define-public (verify-event 
  (event-id uint)
  (ipfs-hash (string-ascii 64))
  (signature (string-ascii 130))
  (comment (string-ascii 256)))
  (begin
    (asserts! (has-permission tx-sender u2) (err ERR-NOT-AUTHORIZED)) ;; PERMISSION-APPROVE-EVENT
    (asserts! (is-valid-ipfs-hash ipfs-hash) (err ERR-INVALID-HASH))
    (asserts! (is-valid-signature signature) (err ERR-INVALID-SIGNATURE))
    (ensure-not-paused)
    (let ((event-result (contract-call? EVENT-LOGGER-CONTRACT get-event event-id)))
      (asserts! (is-ok event-result) (err ERR-INVALID-EVENT))
      (let ((event (unwrap! event-result (err ERR-INVALID-EVENT)))
            (stored-hash (get ipfs-hash event))
            (stored-signature (get signature event))
            (verification-id (+ (var-get verification-counter) u1)))
        (asserts! (is-eq ipfs-hash stored-hash) (err ERR-VERIFICATION-FAILED))
        (asserts! (is-eq signature stored-signature) (err ERR-VERIFICATION-FAILED))
        (map-set verifications 
          { event-id: event-id }
          { 
            verifier: tx-sender,
            status: STATUS-VERIFIED,
            ipfs-hash: ipfs-hash,
            signature: signature,
            timestamp: block-height,
            comment: comment
          }
        )
        (var-set verification-counter verification-id)
        (match (var-get notification-contract)
          contract-principal
          (contract-call? 
            (unwrap! (contract-principal-to-principal contract-principal) (err ERR-NOT-AUTHORIZED))
            notify-verification 
            event-id 
            tx-sender 
            STATUS-VERIFIED 
            ipfs-hash 
            signature 
            block-height 
            comment
          )
          (ok true)
        )
        (ok verification-id)
      )
    )
  )
)

(define-public (reject-event 
  (event-id uint)
  (comment (string-ascii 256)))
  (begin
    (asserts! (has-permission tx-sender u2) (err ERR-NOT-AUTHORIZED)) ;; PERMISSION-APPROVE-EVENT
    (asserts! (is-ok (contract-call? EVENT-LOGGER-CONTRACT get-event event-id)) (err ERR-INVALID-EVENT))
    (ensure-not-paused)
    (let ((verification-id (+ (var-get verification-counter) u1)))
      (map-set verifications 
        { event-id: event-id }
        { 
          verifier: tx-sender,
          status: STATUS-REJECTED,
          ipfs-hash: "",
          signature: "",
          timestamp: block-height,
          comment: comment
        }
      )
      (var-set verification-counter verification-id)
      (match (var-get notification-contract)
        contract-principal
        (contract-call? 
          (unwrap! (contract-principal-to-principal contract-principal) (err ERR-NOT-AUTHORIZED))
          notify-verification 
          event-id 
          tx-sender 
          STATUS-REJECTED 
          "" 
          "" 
          block-height 
          comment
        )
        (ok true)
      )
      (ok verification-id)
    )
  )
)

;; Read-only functions
(define-read-only (get-verification (event-id uint))
  (match (map-get? verifications { event-id: event-id })
    verification (ok verification)
    (err ERR-INVALID-EVENT)
  )
)

(define-read-only (get-verification-count)
  (ok (var-get verification-counter))
)

(define-read-only (get-admin)
  (ok (var-get admin))
)

(define-read-only (is-paused)
  (ok (var-get paused))
)