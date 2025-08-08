(define-constant ERR-NOT-AUTHORIZED u200)
(define-constant ERR-INVALID-ROLE u201)
(define-constant ERR-PAUSED u202)
(define-constant ERR-ALREADY-ASSIGNED u203)
(define-constant ERR-ROLE-NOT-FOUND u204)
(define-constant ERR-INVALID-PRINCIPAL u205)

;; Contract state
(define-data-var admin principal tx-sender)
(define-data-var paused bool false)
(define-data-var role-counter uint u0)

;; Role definitions
(define-constant ROLE-ADMIN u0)
(define-constant ROLE-COMPANY u1)
(define-constant ROLE-AUDITOR u2)
(define-constant ROLE-REGULATOR u3)

;; Permission levels
(define-constant PERMISSION-SUBMIT-EVENT u1)
(define-constant PERMISSION-APPROVE-EVENT u2)
(define-constant PERMISSION-VIEW-EVENT u3)
(define-constant PERMISSION-MANAGE-ROLES u4)

;; Maps
(define-map roles 
  { principal: principal }
  { role-id: uint, assigned-at: uint }
)
(define-map permissions 
  { role-id: uint, permission-id: uint }
  { allowed: bool }
)
(define-map role-descriptions 
  { role-id: uint }
  { description: (string-ascii 128) }
)

;; Event notification trait
(define-trait role-notification-trait
  (
    (notify-role-change (uint principal uint uint (string-ascii 128)) (response bool uint))
    (notify-permission-change (uint uint bool) (response bool uint))
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

(define-private (is-valid-role (role-id uint))
  (or 
    (is-eq role-id ROLE-ADMIN)
    (is-eq role-id ROLE-COMPANY)
    (is-eq role-id ROLE-AUDITOR)
    (is-eq role-id ROLE-REGULATOR)
  )
)

(define-private (is-valid-permission (permission-id uint))
  (or 
    (is-eq permission-id PERMISSION-SUBMIT-EVENT)
    (is-eq permission-id PERMISSION-APPROVE-EVENT)
    (is-eq permission-id PERMISSION-VIEW-EVENT)
    (is-eq permission-id PERMISSION-MANAGE-ROLES)
  )
)

(define-private (is-valid-principal (principal principal))
  (not (is-eq principal 'SP000000000000000000002Q6VF78))
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

;; Role management
(define-public (assign-role (user principal) (role-id uint) (description (string-ascii 128)))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-valid-principal user) (err ERR-INVALID-PRINCIPAL))
    (asserts! (is-valid-role role-id) (err ERR-INVALID-ROLE))
    (asserts! (is-none (map-get? roles { principal: user })) (err ERR-ALREADY-ASSIGNED))
    (ensure-not-paused)
    (let ((role-count (+ (var-get role-counter) u1)))
      (map-set roles 
        { principal: user }
        { role-id: role-id, assigned-at: block-height }
      )
      (map-set role-descriptions 
        { role-id: role-id }
        { description: description }
      )
      (var-set role-counter role-count)
      (match (var-get notification-contract)
        contract-principal
        (contract-call? 
          (unwrap! (contract-principal-to-principal contract-principal) (err ERR-NOT-AUTHORIZED))
          notify-role-change 
          role-count 
          user 
          role-id 
          block-height 
          description
        )
        (ok true)
      )
      (ok role-count)
    )
  )
)

(define-public (revoke-role (user principal))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-valid-principal user) (err ERR-INVALID-PRINCIPAL))
    (asserts! (is-some (map-get? roles { principal: user })) (err ERR-ROLE-NOT-FOUND))
    (ensure-not-paused)
    (map-delete roles { principal: user })
    (ok true)
  )
)

;; Permission management
(define-public (set-permission (role-id uint) (permission-id uint) (allowed bool))
  (begin
    (asserts! (is-admin) (err ERR-NOT-AUTHORIZED))
    (asserts! (is-valid-role role-id) (err ERR-INVALID-ROLE))
    (asserts! (is-valid-permission permission-id) (err ERR-INVALID-ROLE))
    (ensure-not-paused)
    (map-set permissions 
      { role-id: role-id, permission-id: permission-id }
      { allowed: allowed }
    )
    (match (var-get notification-contract)
      contract-principal
      (contract-call? 
        (unwrap! (contract-principal-to-principal contract-principal) (err ERR-NOT-AUTHORIZED))
        notify-permission-change 
        role-id 
        permission-id 
        allowed
      )
      (ok true)
    )
    (ok true)
  )
)

;; Read-only functions
(define-read-only (get-role (user principal))
  (match (map-get? roles { principal: user })
    role-data (ok role-data)
    (err ERR-ROLE-NOT-FOUND)
  )
)

(define-read-only (has-permission (role-id uint) (permission-id uint))
  (ok (default-to false 
    (get allowed (map-get? permissions { role-id: role-id, permission-id: permission-id })))
  )
)

(define-read-only (get-role-description (role-id uint))
  (match (map-get? role-descriptions { role-id: role-id })
    desc (ok desc)
    (err ERR-ROLE-NOT-FOUND)
  )
)

(define-read-only (get-admin)
  (ok (var-get admin))
)

(define-read-only (is-paused)
  (ok (var-get paused))
)

(define-read-only (get-role-count)
  (ok (var-get role-counter))
) 
