 
(define-constant ERR-NOT-AUTHORIZED u400)
(define-constant ERR-INVALID-EVENT u401)
(define-constant ERR-INVALID-APPROVAL u402)
(define-constant ERR-PAUSED u403)
(define-constant ERR-INVALID-PRINCIPAL u404)
(define-constant ERR-NOT-VERIFIED u405)

;; External contract references
(define-constant EVENT-LOGGER-CONTRACT .compliance-event-logger)
(define-constant ACCESS-CONTROL-CONTRACT .access-control-roles)
(define-constant PROOF-VERIFICATION-CONTRACT .proof-verification)

;; Contract state
(define-data-var admin principal tx-sender)
(define-data-var paused bool false)
(define-data-var approval-counter uint u0)

;; Approval status
(define-constant STATUS-PENDING u0)
(define-constant STATUS-APPROVED u1)
(define-constant STATUS-REJECTED u2)

;; Maps
(define-map approvals 
  { event-id: uint }
  { 
    approver: principal,
    status: uint,
    timestamp: uint,
    comment: (string-ascii 256)
  }
)

;; Event notification trait
(define-trait approval-notification-trait
  (
    (notify-approval (uint principal uint uint (string-ascii 256)) (response bool uint))
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

(define-private (is-event-verified (event-id uint))
  (let ((verification-result (contract-call? PROOF-VERIFICATION-CONTRACT get-verification event-id)))
    (if (is-ok verification-result)
      (is-eq (get status (unwrap! verification-result (err ERR-INVALID-EVENT))) u1)
      false
    )
  )
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

;; Approval functions
(define-public (approve-event 
  (event-id uint)
  (comment (string-ascii 256)))
  (begin
    (asserts! (has-permission tx-sender u2) (err ERR-NOT-AUTHORIZED)) ;; PERMISSION-APPROVE-EVENT
    (asserts! (is-ok (contract-call? EVENT-LOGGER-CONTRACT get-event event-id)) (err ERR-INVALID-EVENT))
    (asserts! (is-event-verified event-id) (err ERR-NOT-VERIFIED))
    (ensure-not-paused)
    (let ((approval-id (+ (var-get approval-counter) u1)))
      (asserts! (is-none (map-get? approvals { event-id: event-id })) (err ERR-INVALID-APPROVAL))
      (map-set approvals 
        { event-id: event-id }
        { 
          approver: tx-sender,
          status: STATUS-APPROVED,
          timestamp: block-height,
          comment: comment
        }
      )
      (var-set approval-counter approval-id)
      (match (var-get notification-contract)
        contract-principal
        (contract-call? 
          (unwrap! (contract-principal-to-principal contract-principal) (err ERR-NOT-AUTHORIZED))
          notify-approval 
          event-id 
          tx-sender 
          STATUS-APPROVED 
          block-height 
          comment
        )
        (ok true)
      )
      (ok approval-id)
    )
  )
)

(define-public (reject-event 
  (event-id uint)
  (comment (string-ascii 256)))
  (begin
    (asserts! (has-permission tx-sender u2) (err ERR-NOT-AUTHORIZED)) ;; PERMISSION-APPROVE-EVENT
    (asserts! (is-ok (contract-call? EVENT-LOGGER-CONTRACT get-event event-id)) (err ERR-INVALID-EVENT))
    (asserts! (is-event-verified event-id) (err ERR-NOT-VERIFIED))
    (ensure-not-paused)
    (let ((approval-id (+ (var-get approval-counter) u1)))
      (asserts! (is-none (map-get? approvals { event-id: event-id })) (err ERR-INVALID-APPROVAL))
      (map-set approvals 
        { event-id: event-id }
        { 
          approver: tx-sender,
          status: STATUS-REJECTED,
          timestamp: block-height,
          comment: comment
        }
      )
      (var-set approval-counter approval-id)
      (match (var-get notification-contract)
        contract-principal
        (contract-call? 
          (unwrap! (contract-principal-to-principal contract-principal) (err ERR-NOT-AUTHORIZED))
          notify-approval 
          event-id 
          tx-sender 
          STATUS-REJECTED 
          block-height 
          comment
        )
        (ok true)
      )
      (ok approval-id)
    )
  )
)

;; Read-only functions
(define-read-only (get-approval (event-id uint))
  (match (map-get? approvals { event-id: event-id })
    approval (ok approval)
    (err ERR-INVALID-EVENT)
  )
)

(define-read-only (get-approval-count)
  (ok (var-get approval-counter))
)

(define-read-only (get-admin)
  (ok (var-get admin))
)

(define-read-only (is-paused)
  (ok (var-get paused))
)