# AuditChain

A blockchain-powered compliance and audit trail platform that creates tamper-proof, transparent, and verifiable records for inspections, certifications, and regulatory reporting — all on-chain.

---

## Overview

AuditChain consists of five main smart contracts that work together to form a secure, decentralized, and transparent compliance logging system:

1. **Compliance Event Logger Contract** – Records and timestamps compliance-related events on-chain.  
2. **Access Control & Roles Contract** – Manages permissions for companies, auditors, and regulators.  
3. **Proof Verification Contract** – Validates event data integrity using cryptographic proofs and IPFS hashes.  
4. **Audit Approval Contract** – Allows authorized auditors to approve or reject compliance events.  
5. **Dispute Resolution Contract** – Handles disputes between companies and auditors with DAO-style voting.

---

## Features

- **Immutable compliance event logging** with timestamps and cryptographic hashes  
- **Role-based access control** for secure and regulated participation  
- **On-chain proof verification** for data authenticity  
- **Auditor approval workflows** for inspections and certifications  
- **Transparent dispute resolution** using decentralized voting mechanisms  
- **Off-chain storage integration** (IPFS/Arweave) for large documents  
- **Cross-border audit accessibility** for global compliance requirements  

---

## Smart Contracts

### Compliance Event Logger Contract
- Submit and record compliance events  
- Store IPFS/Arweave content hashes on-chain  
- Emit events for off-chain data indexing  

### Access Control & Roles Contract
- Assign roles to companies, auditors, and regulators  
- Role-based function execution restrictions  
- Dynamic granting and revoking of permissions  

### Proof Verification Contract
- Verify data integrity by matching IPFS hashes  
- Digital signature validation for authenticity  
- Public verification endpoints for third parties  

### Audit Approval Contract
- Approve or reject compliance events  
- Record auditor identity and decision reasoning  
- Immutable approval history for transparency  

### Dispute Resolution Contract
- Submit disputes related to audit outcomes  
- Allow evidence submissions via IPFS hashes  
- DAO-style voting among registered arbitrators  

---

## Installation

1. Install [Clarinet CLI](https://docs.hiro.so/clarinet/getting-started)  
2. Clone this repository:  
   ```bash
   git clone https://github.com/yourusername/auditchain.git
   ```
3. Run tests:
    ```bash
    npm test
    ```
4. Deploy contracts:
    ```bash
    clarinet deploy
    ```

---

## Usage

Each smart contract operates independently but integrates with others for a complete decentralized compliance system.
Refer to individual contract documentation for function calls, parameters, and usage examples.

---

## License

MIT License