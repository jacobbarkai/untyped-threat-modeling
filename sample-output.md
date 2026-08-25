# Sample output

Real runs on `claude-opus-5`, reproduced verbatim so the behaviour can be judged
without spending tokens. Runs 1 to 3 use [`sample.tf`](sample.tf), six Terraform
resources. Run 4 uses [`sample-architecture.png`](sample-architecture.png), a
picture of an unrelated system, to exercise the vision path.

The input is deliberately bad architecture: an unauthenticated production API
reaching an administrator-privileged Lambda that reads a private patient database
and writes to a world-readable bucket, plus a BLE bedside monitor using Just Works
pairing. Almost everything in it is a genuine finding, which is why the positive
rate below is high. On a competently configured system it should be far lower, and
a high rate there would itself be a calibration signal.

---

## 1. Extraction only

Deterministic. No provider, no key, no SDK.

```
$ python untyped_threat_model.py --iac sample.tf --extract-only

6 vertices, 5 edges. Analysis skipped.

  0  aws_api_gateway_rest_api.public
     ['block=resource', 'type=aws_api_gateway_rest_api', 'label=public', 'name=patient-portal', 'authorization=NONE', 'stage=prod']
  1  aws_lambda_function.report_generator
     ['block=resource', 'type=aws_lambda_function', 'label=report_generator', 'function_name=report-generator', 'runtime=python3.11', 'role=aws_iam_role.lambda_exec.arn', 'vpc_config=none', 'trigger=aws_api_gateway_rest_api.public.id']
  2  aws_iam_role.lambda_exec
     ['block=resource', 'type=aws_iam_role', 'label=lambda_exec', 'name=lambda-exec', 'policy=AdministratorAccess']
  3  aws_db_instance.records
     ['block=resource', 'type=aws_db_instance', 'label=records', 'engine=postgres', 'publicly_accessible=false', 'subnet=private', 'accessed_by=aws_lambda_function.report_generator.arn']
  4  aws_s3_bucket.exports
     ['block=resource', 'type=aws_s3_bucket', 'label=exports', 'bucket=patient-exports', 'acl=public-read', 'versioning=false', 'written_by=aws_lambda_function.report_generator.arn']
  5  medical_device_ble_pairing.bedside_monitor
     ['block=resource', 'type=medical_device_ble_pairing', 'label=bedside_monitor', 'pairing_mode=just_works', 'firmware=2.1.0', 'uplink=aws_api_gateway_rest_api.public.id']
```

Vertex 5 is the point. `medical_device_ble_pairing` is not a real AWS resource type
and no provider defines it. It reaches analysis intact because the parser consults no
lookup table.

---

## 2. Default analysis

Boundaries, threats as paths, and a declared uninterpreted list.

Two findings are worth reading closely.

**The BLE chain** reasons from `pairing_mode=just_works` to man-in-the-middle
exposure using knowledge of the Bluetooth specifications, for a component type that
does not exist, and then follows it through the unauthenticated gateway into the
patient database.

**The MEDIUM finding** is the one a rule engine structurally cannot produce. It
notices that the database declares `subnet=private` while its own declared accessor
runs with `vpc_config=none`, and concludes the private-subnet attribute is
documentation rather than an enforced control. That requires holding two components'
strings in tension, not evaluating either one.

```
$ python untyped_threat_model.py --iac sample.tf
provider -> anthropic:claude-opus-5 via api.anthropic.com

6 vertices, 5 edges

  boundary  Public / unauthenticated internet edge: aws_api_gateway_rest_api.public, aws_s3_bucket.exports
            evidence: label=public, authorization=NONE, stage=prod, acl=public-read, bucket=patient-exports
  boundary  Compute outside VPC (no network isolation): aws_lambda_function.report_generator, aws_iam_role.lambda_exec
            evidence: vpc_config=none, role=aws_iam_role.lambda_exec.arn, policy=AdministratorAccess
  boundary  Private data subnet: aws_db_instance.records
            evidence: publicly_accessible=false, subnet=private, engine=postgres
  boundary  Clinical device / physical proximity zone: medical_device_ble_pairing.bedside_monitor
            evidence: type=medical_device_ble_pairing, label=bedside_monitor, pairing_mode=just_works, uplink=aws_api_gateway_rest_api.public.id
  boundary  Crossing: public API -> non-VPC compute -> private DB (0->1->3): aws_api_gateway_rest_api.public, aws_lambda_function.report_generator, aws_db_instance.records
            evidence: authorization=NONE, trigger=aws_api_gateway_rest_api.public.id, vpc_config=none, subnet=private, accessed_by=aws_lambda_function.report_generator.arn
  boundary  Crossing: private-data compute -> public bucket (1->4): aws_lambda_function.report_generator, aws_s3_bucket.exports
            evidence: written_by=aws_lambda_function.report_generator.arn, acl=public-read

  [CRITICAL] Unauthenticated public API reaches admin-privileged Lambda that reads private patient database
      path: aws_api_gateway_rest_api.public -> aws_lambda_function.report_generator -> aws_db_instance.records
      evidence: type=aws_api_gateway_rest_api, label=public, authorization=NONE, stage=prod, trigger=aws_api_gateway_rest_api.public.id, role=aws_iam_role.lambda_exec.arn, policy=AdministratorAccess, vpc_config=none, subnet=private, publicly_accessible=false, accessed_by=aws_lambda_function.report_generator.arn, engine=postgres
      The entry point requires no authorization in a production stage and directly triggers report-generator. That function assumes lambda_exec, which carries AdministratorAccess, so any input reaching it executes with unbounded account privilege. The database's publicly_accessible=false and subnet=private controls are irrelevant on this path because access is mediated by the Lambda's identity, not by the network perimeter, and the Lambda has vpc_config=none so it sits outside the private subnet entirely while still being named as the DB's accessor. One unauthenticated request is therefore a path to patient records.

  [CRITICAL] Patient data exfiltration via public-read export bucket written by the same unauthenticated path
      path: aws_api_gateway_rest_api.public -> aws_lambda_function.report_generator -> aws_s3_bucket.exports
      evidence: authorization=NONE, label=public, written_by=aws_lambda_function.report_generator.arn, bucket=patient-exports, acl=public-read, versioning=false, policy=AdministratorAccess
      An anonymous caller can invoke report-generator, which writes to patient-exports. That bucket is acl=public-read, so anything written becomes world-readable without any further compromise; the attacker does not even need to receive the API response. versioning=false removes recovery and tamper evidence, and AdministratorAccess means the function could also rewrite the bucket policy. Combining an unauthenticated trigger with a public sink turns a report feature into a self-service PHI export.

  [CRITICAL] Privilege escalation from internet-facing function through AdministratorAccess role
      path: aws_api_gateway_rest_api.public -> aws_lambda_function.report_generator -> aws_iam_role.lambda_exec
      evidence: authorization=NONE, role=aws_iam_role.lambda_exec.arn, name=lambda-exec, policy=AdministratorAccess, vpc_config=none
      The role attached to the internet-reachable function is granted AdministratorAccess rather than a scoped policy. Any code-injection, dependency, or deserialization flaw in the python3.11 handler converts directly into full account takeover: creating IAM users, disabling logging, reading every other resource. The graph edge 2->1 shows the privilege flows into the exact component that the unauthenticated gateway can reach, so there is no compensating layer between anonymous input and admin credentials. vpc_config=none also means no egress restriction on the exfiltration channel.

  [HIGH] Unauthenticated BLE bedside monitor injects telemetry into the same public API surface
      path: medical_device_ble_pairing.bedside_monitor -> aws_api_gateway_rest_api.public -> aws_lambda_function.report_generator -> aws_db_instance.records
      evidence: type=medical_device_ble_pairing, label=bedside_monitor, pairing_mode=just_works, firmware=2.1.0, uplink=aws_api_gateway_rest_api.public.id, authorization=NONE, policy=AdministratorAccess
      BLE 'just_works' pairing provides no man-in-the-middle protection or authenticated key exchange, so an attacker in radio range of a bedside monitor can impersonate or interpose on the device. The device's uplink is the same rest_api that has authorization=NONE, so spoofed clinical telemetry is accepted with no device identity check and is processed by the admin-privileged Lambda that touches the patient database. This chains a physical-proximity clinical-safety weakness to the cloud data plane; falsified vitals are also a patient-harm concern, not only a confidentiality one.

  [MEDIUM] Private-subnet control on the records database is not an effective boundary
      path: aws_lambda_function.report_generator -> aws_db_instance.records
      evidence: vpc_config=none, subnet=private, publicly_accessible=false, accessed_by=aws_lambda_function.report_generator.arn
      The database is declared private and not publicly accessible, yet its declared accessor runs with vpc_config=none, meaning the function has no interface in that private subnet. Either the connection actually traverses a public or otherwise widened path, or the isolation intent is not implemented as written. Reviewers should treat the private-subnet attribute here as documentation rather than an enforced control, since the trust boundary is crossed by identity-based access from outside the VPC.

  Uninterpreted (the honesty channel; a library tool reports these as
  nothing at all):
      medical_device_ble_pairing.bedside_monitor: Partially interpreted. 'pairing_mode=just_works' and the uplink reference are readable as an unauthenticated BLE pairing mode feeding the public API, but 'type=medical_device_ble_pairing' is not a recognized standard resource type and 'firmware=2.1.0' cannot be assessed for known vulnerabilities without a device model or advisory reference, so the severity of the device itself is unverifiable from these strings alone.
```

Note the uninterpreted entry. It did not return an empty list to look thorough. It
separated what it could read from what it could not, and said why.

---

## 3. Audit mode

Every vertex against every STRIDE category. **Negatives are the point** and are
reported with their reasoning, which is what a rule engine cannot do: a rule engine
reports the rules that fired and is silent about the rest of its own space.

The expected cell count is computed from the topology and checked against what came
back, so a short return is reported as an incomplete artifact rather than passed off
as a clean one.

The five negatives below fall into three distinct kinds, which is the behaviour that
makes this an audit artifact rather than a filtered finding list:

- **Data absent to decide.** IAM role x Spoofing: no trust policy string is present,
  so the question cannot be answered from what is here.
- **Genuinely inapplicable.** S3 x Spoofing: a public-read ACL grants anonymous reads
  but asserts no identity to impersonate, and no write access is opened.
- **Scoped to the vertex.** S3 and database x Elevation of privilege: no escalation is
  asserted *by this vertex itself*, correctly leaving the Lambda's escalation path,
  which the default analysis did find, to be reported where it belongs.

```
$ python untyped_threat_model.py --iac sample.tf --audit
provider -> anthropic:claude-opus-5 via api.anthropic.com

6 vertices x 6 categories = 36 evaluations, 36 returned, 31 positive

  aws_api_gateway_rest_api.public
    [APPLIES] Spoofing: With authorization=NONE on a public patient-portal API there is no caller identity check, so any party can present itself as a legitimate portal client or patient.
              evidence: type=aws_api_gateway_rest_api, authorization=NONE, label=public, name=patient-portal
    [APPLIES] Tampering: An unauthenticated production endpoint lets arbitrary callers submit requests that drive the downstream Lambda into writing to the database and export bucket, i.e. unauthorised data modification.
              evidence: authorization=NONE, stage=prod, trigger=aws_api_gateway_rest_api.public.id
    [APPLIES] Repudiation: No authorizer and no access-logging or execution-logging attributes mean requests carry no attributable principal, so a caller can deny having made a request.
              evidence: authorization=NONE, stage=prod
    [APPLIES] Information disclosure: An internet-facing patient portal API with no authorization exposes any data returned by its integration to unauthorised parties.
              evidence: label=public, name=patient-portal, authorization=NONE
    [APPLIES] Denial of service: A public, unauthenticated prod endpoint with no throttling, quota, or WAF attributes can be flooded to exhaust the backend and drive cost/availability failure.
              evidence: type=aws_api_gateway_rest_api, label=public, authorization=NONE, stage=prod
    [APPLIES] Elevation of privilege: An anonymous caller reaches a Lambda that runs with AdministratorAccess, converting zero granted privilege into full account capability.
              evidence: authorization=NONE, trigger=aws_api_gateway_rest_api.public.id, role=aws_iam_role.lambda_exec.arn, policy=AdministratorAccess

  aws_lambda_function.report_generator
    [APPLIES] Spoofing: Every anonymous invocation executes under the single lambda_exec identity, so downstream systems cannot distinguish a legitimate report request from an attacker wearing the function's identity.
              evidence: trigger=aws_api_gateway_rest_api.public.id, authorization=NONE, role=aws_iam_role.lambda_exec.arn
    [APPLIES] Tampering: The function holds administrator rights, so any injection through its unauthenticated trigger permits modification of its own code, the database rows, and bucket objects.
              evidence: role=aws_iam_role.lambda_exec.arn, policy=AdministratorAccess, written_by=aws_lambda_function.report_generator.arn
    [APPLIES] Repudiation: Actions are recorded only as the shared function role with no upstream caller identity and no logging configuration declared, so individual actions cannot be pinned to an actor.
              evidence: function_name=report-generator, trigger=aws_api_gateway_rest_api.public.id, authorization=NONE
    [APPLIES] Information disclosure: The function reads the patient records database and writes results into a public-read bucket, forming a direct path from private records to anonymous readers.
              evidence: accessed_by=aws_lambda_function.report_generator.arn, written_by=aws_lambda_function.report_generator.arn, acl=public-read, vpc_config=none
    [APPLIES] Denial of service: An unauthenticated public trigger with no reserved concurrency or timeout limits declared allows invocation floods that exhaust account concurrency and starve other functions.
              evidence: trigger=aws_api_gateway_rest_api.public.id, authorization=NONE, runtime=python3.11
    [APPLIES] Elevation of privilege: Compromise of this internet-triggered function yields AdministratorAccess, a maximal escalation far beyond generating reports.
              evidence: role=aws_iam_role.lambda_exec.arn, policy=AdministratorAccess, trigger=aws_api_gateway_rest_api.public.id

  aws_iam_role.lambda_exec
    [  ---  ] Spoofing: No assume_role_policy or trust-principal string is present, so there is nothing here asserting who may assume this role and no basis to judge impersonation.
              evidence: type=aws_iam_role, label=lambda_exec, name=lambda-exec
    [APPLIES] Tampering: AdministratorAccess grants unrestricted write to every resource in the account, so any holder of the role can modify arbitrary data and infrastructure code.
              evidence: policy=AdministratorAccess
    [APPLIES] Repudiation: Administrator rights include the ability to stop or delete audit trails and log groups, letting the actor erase the very evidence of its actions.
              evidence: policy=AdministratorAccess, name=lambda-exec
    [APPLIES] Information disclosure: The role can read every secret, database snapshot, and bucket in the account, vastly exceeding the read scope a report generator needs.
              evidence: policy=AdministratorAccess
    [APPLIES] Denial of service: Unlimited permissions include deletion of the database, bucket, and API, so misuse of this role can destroy availability outright.
              evidence: policy=AdministratorAccess
    [APPLIES] Elevation of privilege: Attaching AdministratorAccess to an execution role is itself the privilege violation: the workload receives every capability in the account instead of a scoped set.
              evidence: policy=AdministratorAccess, label=lambda_exec

  aws_db_instance.records
    [  ---  ] Spoofing: No authentication mechanism, IAM-auth flag, or credential handling is described, and network exposure is closed, so no impersonation claim can be decided from these strings.
              evidence: type=aws_db_instance, engine=postgres, publicly_accessible=false, subnet=private
    [APPLIES] Tampering: Its sole client is an administrator-privileged function reachable without authentication, so patient records can be altered by an unauthorised caller despite the private placement.
              evidence: accessed_by=aws_lambda_function.report_generator.arn, policy=AdministratorAccess, authorization=NONE
    [APPLIES] Repudiation: All access arrives through one shared function principal and no audit-log or pgaudit setting is declared, so individual record reads and writes cannot be attributed to a human actor.
              evidence: accessed_by=aws_lambda_function.report_generator.arn, engine=postgres
    [APPLIES] Information disclosure: The records database feeds a function that deposits output into a public-read bucket, so its contents can escape to unauthorised readers even though the instance itself is private.
              evidence: label=records, accessed_by=aws_lambda_function.report_generator.arn, acl=public-read
    [APPLIES] Denial of service: Unauthenticated request floods fan out into unbounded Lambda invocations that can exhaust Postgres connections, and no multi-AZ or backup attribute mitigates loss.
              evidence: accessed_by=aws_lambda_function.report_generator.arn, trigger=aws_api_gateway_rest_api.public.id, authorization=NONE
    [  ---  ] Elevation of privilege: The instance is network-isolated and no role, grant, or superuser configuration is asserted, so nothing here shows this resource conferring extra capability.
              evidence: publicly_accessible=false, subnet=private, engine=postgres

  aws_s3_bucket.exports
    [  ---  ] Spoofing: A public-read ACL grants anonymous reads but asserts no identity or credential that could be impersonated, and no write access is opened to the public.
              evidence: type=aws_s3_bucket, acl=public-read, bucket=patient-exports
    [APPLIES] Tampering: Objects are written by an administrator-privileged function and versioning is off, so any overwrite or deletion of export data is silent and irreversible.
              evidence: versioning=false, written_by=aws_lambda_function.report_generator.arn, policy=AdministratorAccess
    [APPLIES] Repudiation: With no versioning and no access-logging attribute, there is no record of who read, replaced, or removed an export object.
              evidence: versioning=false, acl=public-read
    [APPLIES] Information disclosure: A public-read ACL on a bucket named patient-exports publishes patient report data to any anonymous internet reader.
              evidence: acl=public-read, bucket=patient-exports
    [APPLIES] Denial of service: Loss of an export cannot be rolled back without versioning, and unrestricted anonymous reads permit unbounded egress that degrades availability and cost.
              evidence: versioning=false, acl=public-read
    [  ---  ] Elevation of privilege: The ACL grants only read to anonymous principals and no policy here confers additional AWS capability, so no escalation path is asserted by this vertex itself.
              evidence: acl=public-read, written_by=aws_lambda_function.report_generator.arn

  medical_device_ble_pairing.bedside_monitor
    [APPLIES] Spoofing: BLE Just Works pairing performs no authentication of either peer, so an attacker can pose as the bedside monitor or as the paired gateway, and the uplink API also checks no identity.
              evidence: pairing_mode=just_works, type=medical_device_ble_pairing, uplink=aws_api_gateway_rest_api.public.id
    [APPLIES] Tampering: Just Works offers no MITM resistance, so vitals in transit and commands to the device can be altered, and no firmware signing or integrity attribute is declared.
              evidence: pairing_mode=just_works, firmware=2.1.0, uplink=aws_api_gateway_rest_api.public.id
    [APPLIES] Repudiation: Unauthenticated pairing plus an unauthenticated uplink means telemetry cannot be proven to have come from a specific device, so injected or disputed readings are unattributable.
              evidence: pairing_mode=just_works, label=bedside_monitor, authorization=NONE
    [APPLIES] Information disclosure: Just Works pairing derives keys without authentication and is passively defeatable, exposing patient vital-sign traffic from the bedside monitor to eavesdroppers in radio range.
              evidence: pairing_mode=just_works, label=bedside_monitor
    [APPLIES] Denial of service: An attacker in range can force re-pairing or hijack the link to cut monitoring uplink for a life-safety device, and the shared public API is itself floodable.
              evidence: pairing_mode=just_works, type=medical_device_ble_pairing, uplink=aws_api_gateway_rest_api.public.id
    [APPLIES] Elevation of privilege: Any nearby party can complete pairing with no credential and thereby gain device-level access to a bedside monitor plus an injection path into the unauthenticated cloud API.
              evidence: pairing_mode=just_works, firmware=2.1.0, uplink=aws_api_gateway_rest_api.public.id, authorization=NONE
```

---

## 4. From an image

`--image` sends a picture to a vision model and asks for the same untyped graph.
Nothing about the pipeline changes: the extraction prompt forbids classifying nodes
into types, so what comes back is still integers and bags of strings.

[`sample-architecture.png`](sample-architecture.png) is deliberately unlike
`sample.tf`. Different domain, different stack, no Terraform, no AWS resource types,
and the annotations are drawn as text inside boxes rather than supplied as structured
data. The tiers are visual containers, not `subnet=private` strings.

Three things are worth checking in the output below.

**Boundaries came from the drawing.** DMZ, application tier, data tier and the
acquired estate were inferred from labelled rectangles in a picture, with no boundary
type existing anywhere in the representation.

**The AS400 bridge is the boundary-of-knowledge case**, and a more honest one than a
fabricated Terraform resource type: legacy mainframe integrations over FTP genuinely
are outside every component taxonomy in the field. It was reasoned about anyway.

**The structural finding is the third one.** The route through the acquired estate
reaches the database while bypassing both the DMZ proxy and the API's authentication.
That is a property of the topology, not of any component, and it is the same class of
finding as the private-subnet contradiction in run 2.

```
$ python untyped_threat_model.py --image sample-architecture.png
provider -> anthropic:claude-opus-5 via api.anthropic.com

7 vertices, 7 edges

  boundary  Untrusted public network (outside perimeter): Internet
            evidence: Internet
  boundary  DMZ / edge-facing tier: nginx reverse proxy
            evidence: DMZ, 0.0.0.0/0, nginx reverse proxy
  boundary  Application tier (internal compute): orders-api, settlement-worker
            evidence: Application tier, orders-api, settlement-worker
  boundary  Data tier (persistence, should be deepest zone): orders-db, nightly dump
            evidence: Data, orders-db, nightly dump
  boundary  Acquired estate - unmodelled/ungoverned zone outside the reviewed architecture: AS400 ledger bridge
            evidence: Acquired estate, unmodelled, AS400 ledger bridge, FTP poll

  [CRITICAL] Internet-reachable weak-TLS proxy fronts a basic-auth API that talks to an unencrypted database
      path: Internet -> nginx reverse proxy -> orders-api -> orders-db
      evidence: Internet, 0.0.0.0/0, TLS 1.0 enabled, basic auth, postgres 11, no TLS
      The entry point is open to the whole internet (0.0.0.0/0) and negotiates TLS 1.0, so credentials passed to the only authentication mechanism downstream (basic auth, which transmits a reusable password on every request) are exposed to downgrade/interception. Once an attacker holds those credentials there is no second factor and no authorization layer named anywhere on the path, and orders-api's session to orders-db is itself cleartext ('no TLS'), so the same passive position on the network yields both application credentials and raw record traffic. The severity comes from the chain, not from any single hop: weak edge crypto is survivable behind strong auth, and basic auth is survivable behind strong crypto; together with an unencrypted data leg they compose into an internet-to-database read.

  [CRITICAL] Data-tier compromise flows into an unencrypted public-cloud backup bucket, converting transient DB access into durable bulk exfiltration
      path: Internet -> nginx reverse proxy -> orders-api -> orders-db -> nightly dump
      evidence: 0.0.0.0/0, basic auth, no TLS, nightly dump, s3://acme-backups, unencrypted
      The database's contents are copied nightly to object storage with no encryption at rest and no access-control string of any kind on the vertex. This turns the reachable database into a permanent full-history dataset: an attacker who reaches vertex 5 by the path above, or who finds the bucket independently, gets every prior day's orders rather than a live query window. Absence of any credential, policy, or 'private' marker on the S3 vertex is itself the finding - nothing in the strings distinguishes this bucket from a publicly listable one, and it sits at the end of an internet-originating path.

  [CRITICAL] Unmodelled acquired-estate FTP bridge with plaintext credentials is given a write path into the production database
      path: orders-api -> settlement-worker -> AS400 ledger bridge -> orders-db
      evidence: Acquired estate, unmodelled, FTP poll, plaintext creds, cron every 5 min, AS400 ledger bridge, no TLS
      This is the most serious structural finding because it is a boundary crossing into and back out of a zone the organisation admits it has not modelled. settlement-worker fires every 5 minutes into a legacy AS400 bridge that authenticates over FTP with plaintext credentials, and that bridge has its own edge to orders-db. The graph therefore contains a route to the data tier that bypasses vertices 1 and 2 entirely - the DMZ proxy and the API's basic auth are not on it. Anyone who can sniff or replay the FTP credentials, or who already sits inside the acquired network, reaches production data directly, and the 5-minute cron guarantees a fresh credential exposure 288 times a day. 'Unmodelled' means no compensating control can be assumed to exist.

  [HIGH] Full internet-to-legacy-estate traversal: external entry pivots through the app tier into the ungoverned zone
      path: Internet -> nginx reverse proxy -> orders-api -> settlement-worker -> AS400 ledger bridge
      evidence: Internet, 0.0.0.0/0, TLS 1.0 enabled, basic auth, cron every 5 min, Acquired estate, unmodelled, plaintext creds
      Read in the outbound direction, the same edges let an attacker who compromises orders-api reach the acquired estate rather than merely the database. settlement-worker is an automated component with a standing FTP credential to a legacy mainframe bridge; harvesting that credential from the app tier gives lateral movement into a network segment with no documented controls, monitoring, or ownership. Legacy AS400 ledger systems are typically flat internally, so this hop is likely a privilege escalation as well as a lateral one.

  [HIGH] Unpatched runtime and end-of-life datastore on the sole internet-facing path
      path: Internet -> nginx reverse proxy -> orders-api -> orders-db
      evidence: TLS 1.0 enabled, Java 8, postgres 11, 0.0.0.0/0
      Every component on the externally reachable path carries an aged version marker: TLS 1.0 (deprecated, downgrade- and padding-attack prone), Java 8 as the application runtime, and PostgreSQL 11 which is past community end-of-life. Version staleness matters here specifically because it is stacked along a path that begins at 0.0.0.0/0 - remote code execution in the Java tier lands the attacker one unauthenticated, unencrypted hop from the database and two from the backup bucket. Rated high rather than critical because exploitability depends on the actual patch level, which the strings do not state.

  [MEDIUM] No egress or segmentation control between DMZ, app, data, and external estate
      path: nginx reverse proxy -> orders-api -> settlement-worker -> AS400 ledger bridge
      evidence: DMZ, Application tier, Acquired estate, unmodelled, FTP poll
      The vertices carry tier labels that imply a layered design, but the edge set shows each tier connecting freely to the next and the app tier reaching outward to a third-party network over FTP. No string anywhere in the graph mentions a firewall rule, security group, allow-list, mTLS, or private subnet. The labelled tiers are therefore descriptive rather than enforced, which is what allows the preceding findings to chain end to end instead of being contained at a boundary.

  Uninterpreted (the honesty channel; a library tool reports these as
  nothing at all):
      AS400 ledger bridge: Partially interpreted only. 'AS400 ledger bridge' and 'FTP poll' are legible as a legacy mainframe integration over an insecure file-transfer protocol, but 'Acquired estate, unmodelled' is an explicit admission that the artifact does not describe this zone. I cannot tell what else lives behind vertex 4, who owns it, whether its edge to orders-db is read or write, or what the FTP credentials authorise. Findings involving it are inferred from the missing information rather than from stated controls, and the real blast radius may be larger than modelled.
      nightly dump: Direction and access model are ambiguous. 'nightly dump' and the 5->6 edge suggest the database writes to the bucket, but nothing states whether the bucket is public, who else reads it, whether versioning or retention applies, or which principal holds the write credential. 'unencrypted' is clear; the exposure surface around it is not.
      settlement-worker: 'cron every 5 min' gives the cadence but not the identity or privilege of settlement-worker. Whether it runs as a shared service account, whether its FTP credential is also valid elsewhere, and whether it writes to orders-db directly are all unstated, so its role as the pivot into vertex 4 is inferred from edges alone.
```

The uninterpreted list is worth reading twice. It names three vertices, and for each it
separates what the picture stated from what was inferred from the edges alone. The last
line of the AS400 entry is the one that matters: *"the real blast radius may be larger
than modelled."* A method that under reports has to be able to say that about itself.

---

## What this does not show

These are single runs on one small graph with one model. They demonstrate that the
approach produces coherent output, not that it is complete, reproducible or better
than a rule engine. The four objections in [`ARTICLE.md`](ARTICLE.md) all still apply,
and the proposed measurement there, running both methods over the same artifact and
diffing the results, is the thing that would actually settle it.
