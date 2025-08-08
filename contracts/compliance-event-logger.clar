(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-IPFS-HASH u101)
(define-constant ERR-EVENT-EXISTS u102)
(define-constant ERR-EVENT-NOT-FOUND u103)
(define-constant ERR-PAUSED u104)
(define-constant ERR-INVALID-TIMESTAMP u105)
(define-constant ERR-INVALID-EVENT-TYPE u106)
(define-constant ERR-INVALID-SIGNATURE u107)

;; Contract state
(define-data-var admin principal tx-sender)
(define-data-var paused bool false)
(define-data-var event-counter uint u0)

;; Role definitions
(define-constant ROLE-COMPANY u1)
(define-constant ROLE-AUDITOR u2)
(define-constant ROLE-REGULATOR u3)

;; Event types
(define-constant EVENT-TYPE-INSPECTION u1)
(define-constant EVENT-TYPE-CERTIFICATION u2)
(define-constant EVENT-TYPE-REPORT u3)

;; Maps
(define-map roles principal uint)
(define-map compliance-events 
  { event-id: uint }
  { 
    submitter: principal,
    event-type: uint,
    ipfs-hash: (string-ascii 64),
    timestamp: uint,
    signature: (buff 65),
    metadata: (string-ascii 256)
  }
)
(define-map event-permissions
  { event-id: uint, principal: principal }
  { can-view: bool, can-approve: bool }
)

;; Event notification trait
(define-trait event-notification-trait
  (
    (notify-event (uint principal uint (string-ascii 64) uint (buff 65) (string-ascii 256)) (response bool uint))
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

(define-private (is-valid-role (role uint))
  (or (is-eq role ROLE-COMPANY) 
      (is-eq role ROLE-AUDITOR) 
      (is-eq role ROLE-REGULATOR))
)

(define-private (is-valid-event-type (event-type uint))
  (or (is-eq event-type EVENT-TYPE-INSPECTION)
      (is-eq event-type EVENT-TYPE-CERTIFICATION)
      (is-eq event-type EVENT-TYPE-REPORT))
)

(define-private (is-valid-ipfs-hash (hash (string-ascii 64)))
  (and (> (len hash) u0) (<= (len hash) u64))
)

;; Admin functions
(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
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

;; Role management
(define-public (assign-role (user principal) (role uint))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-valid-role role) (err ERR-NOT-AUTHORIZED))
    (map-set roles user role)
    (ok true)
  )
)

(define-public (revoke-role (user principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (map-delete roles user)
    (ok true)
  )
)

;; Event submission
(define-public (submit-event 
  (event-type uint)
  (ipfs-hash (string-ascii 64))
  (signature (buff 65))
  (metadata (string-ascii 256)))
  (begin
    (ensure-not-paused)
    (asserts! (is-some (map-get? roles tx-sender)) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-valid-event-type event-type) (err ERR-INVALID-EVENT-TYPE))
    (asserts! (is-valid-ipfs-hash ipfs-hash) (err ERR-INVALID-IPFS-HASH))
    (asserts! (> block-height u0) (err ERR-INVALID-TIMESTAMP))
    (let ((event-id (+ (var-get event-counter) u1)))
      (asserts! (is-none (map-get? compliance-events { event-id: event-id })) (err ERR-EVENT-EXISTS))
      (map-set compliance-events 
        { event-id: event-id }
        { 
          submitter: tx-sender,
          event-type: event-type,
          ipfs-hash: ipfs-hash,
          timestamp: block-height,
          signature: signature,
          metadata: metadata
        }
      )
      (map-set event-permissions 
        { event-id: event-id, principal: tx-sender }
        { can-view: true, can-approve: false }
      )
      (var-set event-counter event-id)
      (match (var-get notification-contract)
        contract-principal
        (contract-call? 
          (unwrap! (contract-principal-to-principal contract-principal) (err ERR-NOT-AUTHORIZED))
          notify-event 
          event-id 
          tx-sender 
          event-type 
          ipfs-hash 
          block-height 
          signature 
          metadata
        )
        (ok true)
      )
      (ok event-id)
    )
  )
)

;; Event permission management
(define-public (grant-event-permission 
  (event-id uint)
  (principal principal)
  (can-view bool)
  (can-approve bool))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-some (map-get? compliance-events { event-id: event-id })) (err ERR-EVENT-NOT-FOUND))
    (map-set event-permissions 
      { event-id: event-id, principal: principal }
      { can-view: can-view, can-approve: can-approve }
    )
    (ok true)
  )
)

;; Read-only functions
(define-read-only (get-event (event-id uint))
  (let ((event (map-get? compliance-events { event-id: event-id })))
    (asserts! (is-some event) (err ERR-EVENT-NOT-FOUND))
    (asserts! (default-to false 
      (get can-view (map-get? event-permissions { event-id: event-id, principal: tx-sender }))) 
      (err ERR-NOT-AUTHORIZED))
    (ok (unwrap! event (err ERR-EVENT-NOT-FOUND)))
  )
)

(define-read-only (get-role (user principal))
  (ok (default-to u0 (map-get? roles user)))
)

(define-read-only (get-event-count)
  (ok (var-get event-counter))
)

(define-read-only (can-approve-event (event-id uint) (principal principal))
  (ok (default-to false 
    (get can-approve (map-get? event-permissions { event-id: event-id, principal: principal }))))
)