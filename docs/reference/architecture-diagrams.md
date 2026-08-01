# EP-Governance Architecture Diagrams

**Status:** Draft visual companion to the architecture, deployment, operations, and database references.

---

## 1. System and trust boundaries

```mermaid
flowchart LR
    Agent[AI Agent] -->|Authenticated governance request| EP[EP Service]
    Human[Human Approver] -->|Authenticated approval| EP

    EP -->|Read/write governance state| GDB[(Governance PostgreSQL)]
    EP -->|Signed single-use token| Agent
    Agent -->|Token + exact payload| Proxy[Governed Proxy]

    Proxy -->|Verify and atomically claim| GDB
    Proxy -->|Approved operation only| TDB[(Target Database)]
    Proxy -->|Execution result| EP
    EP -->|Transition result + audit event| GDB

    subgraph No_Direct_Credentials[Credential boundaries]
        Agent -. no DB credentials .-> GDB
        Agent -. no target credentials .-> TDB
        EP -. no target credentials .-> TDB
    end
```

---

## 2. Authorization and execution sequence

```mermaid
sequenceDiagram
    participant A as Authenticated Agent
    participant E as EP Service
    participant G as Governance DB
    participant P as Governed Proxy
    participant T as Target DB

    A->>E: Propose tool + payload
    E->>G: Create transition
    E->>G: Evaluate active policy set
    alt denied
        E->>G: Mark denied + append audit
        E-->>A: Denied
    else approval required
        E->>G: Create approval request
        E-->>A: Pending approval
    else admissible
        E->>G: Mark authorized
        E->>G: Store authorization hash and expiry
        E-->>A: Signed single-use token
        A->>P: Token + exact payload
        P->>P: Verify signature, audience, expiry, payload hash
        P->>G: Revalidate policy set
        P->>G: Atomically claim unused authorization
        P->>G: Move transition to executing
        P->>T: Execute approved action
        T-->>P: Result
        P->>G: Record result
        P-->>E: Execution result
        E->>G: Commit graph node and audit event
        E-->>A: Governed result
    end
```

---

## 3. Transition lifecycle

```mermaid
stateDiagram-v2
    [*] --> proposed
    proposed --> pending_approval
    proposed --> authorized
    proposed --> denied
    proposed --> cancelled

    pending_approval --> authorized
    pending_approval --> denied
    pending_approval --> expired
    pending_approval --> cancelled

    authorized --> executing
    authorized --> expired
    authorized --> cancelled

    executing --> succeeded
    executing --> failed
    executing --> execution_uncertain

    execution_uncertain --> succeeded : reconcile
    execution_uncertain --> failed : reconcile

    succeeded --> [*]
    failed --> [*]
    denied --> [*]
    cancelled --> [*]
    expired --> [*]
```

---

## 4. Identity and role model

```mermaid
flowchart TD
    Principal[Principal]
    Human[Human]
    Agent[Agent]
    Service[Service]
    Proxy[Proxy]
    Binding[Role Binding]
    Role[Role]
    Project[Optional Project Scope]
    Credential[Credential Hash / Certificate Identity]

    Principal --> Human
    Principal --> Agent
    Principal --> Service
    Principal --> Proxy
    Principal --> Binding
    Binding --> Role
    Binding --> Project
    Principal --> Credential
```

---

## 5. Policy evaluation

```mermaid
flowchart TD
    Request[Authenticated action request] --> Classify[Classify tool and payload]
    Classify --> Load[Load effective policies]
    Load --> Match[Match scope, action, resource, conditions]
    Match --> Order[Order by priority and effect]
    Order --> Decision{Decision}

    Decision -->|deny| Denied[Denied]
    Decision -->|require approval| Pending[Pending approval]
    Decision -->|warn| Warned[Authorized with warning]
    Decision -->|allow| Allowed[Authorized]

    Load --> Hash[Compute policy-set hash]
    Hash --> Token[Bind hash into authorization token]
    Token --> Revalidate[Proxy revalidates before execution]
```

---

## 6. Signing-key flow

```mermaid
flowchart LR
    Private[Ed25519 Private Key<br/>EP service only] --> Sign[Sign authorization claims]
    Claims[Transition + payload hash + policy hash + audience + expiry] --> Sign
    Sign --> Token[Signed token]
    Token --> Proxy[Governed proxy]
    Public[Ed25519 Public Key<br/>proxy configuration] --> Verify[Verify signature]
    Proxy --> Verify
    Verify --> Claim[Atomically claim authorization]
    Claim --> Execute[Execute approved action]
```

The private key must never be available to the proxy or an agent.

---

## 7. Immediate key rotation

```mermaid
flowchart TD
    Start[Begin maintenance] --> StopIssue[Stop new authorization issuance]
    StopIssue --> Drain[Wait token TTL or expire outstanding authorizations]
    Drain --> StopEP[Stop EP service]
    StopEP --> Generate[Generate and install new private key]
    Generate --> Configure[Set matching public key on proxy]
    Configure --> RestartProxy[Restart proxy]
    RestartProxy --> RestartEP[Restart EP service]
    RestartEP --> Verify[Run full governed test]
    Verify --> Audit[Verify token reuse rejection and audit chain]
    Audit --> Done[Return to service]
```

---

## 8. Execution uncertainty and reconciliation

```mermaid
sequenceDiagram
    participant EP as EP Service
    participant Proxy
    participant Target
    participant DB as Governance DB
    participant Operator

    EP->>Proxy: Authorized execution
    Proxy->>DB: Claim and mark executing
    Proxy->>Target: Execute
    Note over Proxy,Target: Network loss, timeout, or proxy crash
    EP->>DB: Mark execution_uncertain
    Operator->>Target: Inspect actual side effects
    alt action succeeded
        Operator->>EP: Reconcile succeeded
        EP->>DB: Commit result and graph node
    else action failed
        Operator->>EP: Reconcile failed
        EP->>DB: Record terminal failure
    end
    EP->>DB: Append reconciliation audit event
```

---

## 9. Branch commit and optimistic concurrency

```mermaid
sequenceDiagram
    participant E as EP Service
    participant B as ep_branches
    participant N as ep_nodes
    participant G as ep_edges
    participant A as Audit log

    E->>B: Read head_node_id and version
    E->>E: Compare expected head/version
    alt stale
        E-->>E: Raise stale-head error
    else current
        E->>N: Insert committed node
        E->>G: Insert relationship edge
        E->>N: Supersede prior head
        E->>B: Update head and increment version
        E->>A: Append audit event
    end
```

---

## 10. Deployment topology

```mermaid
flowchart TB
    subgraph Agent_Zone[Agent zone]
        AgentRuntime[Agent runtime]
    end

    subgraph Governance_Zone[Governance zone]
        EPService[EP service]
        GovernanceDB[(Governance PostgreSQL)]
    end

    subgraph Execution_Zone[Execution zone]
        ProxyService[Governed proxy]
        TargetDB[(Target PostgreSQL)]
    end

    AgentRuntime -->|Authenticated MCP/API| EPService
    EPService --> GovernanceDB
    AgentRuntime -->|Signed token + payload| ProxyService
    ProxyService --> GovernanceDB
    ProxyService --> TargetDB

    EPService -. no target credential .-> TargetDB
    AgentRuntime -. no DB credential .-> GovernanceDB
    AgentRuntime -. no target credential .-> TargetDB
```

---

## 11. Documentation placement

Recommended links:

- `README.md` → system and trust-boundary diagram;
- `docs/architecture.md` → system, identity, policy, and branch diagrams;
- `docs/getting-started.md` → authorization sequence;
- `docs/deployment/enforced-mode.md` → deployment and key-flow diagrams;
- `docs/operations/runbooks.md` → key rotation and reconciliation diagrams;
- `docs/reference/database-schema.md` → ER and audit-chain diagrams.
