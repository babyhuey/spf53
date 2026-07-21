# spf53

**spf53 — reapply your SPF automatically.**

A small, open-source, self-hosted SPF flattener for Amazon Route53. It
resolves your providers' `include:` records, flattens them into `ip4`/`ip6`
mechanisms, and republishes them as a chain of TXT records on a schedule —
so your SPF record never silently drifts past the RFC 7208 10-DNS-lookup
limit.

## What and why

SPF records have a hard limit: mail receivers stop evaluating after 10 DNS
lookups (`include:`, `a`, `mx`, `ptr`, `exists:`, plus nested lookups inside
those). Once you add a handful of providers — Google Workspace, a marketing
platform, a transactional-email service, Salesforce — it's easy to blow past
that limit, and the failure mode is silent: some receivers just stop
validating your mail as authenticated.

The standard fix is "flattening": resolve every `include:` down to the
concrete IP ranges behind it, and publish those instead. The catch is that
providers' IP ranges *change*. A one-time flattened record goes stale the
moment a provider rotates infrastructure — this is exactly why
[dmarcian discontinued their SPF flattening product](https://dmarcian.com/):
static flattening without ongoing maintenance is a liability, not a fix.
Hosted flattening services solve the staleness problem, but they add a paid
third-party dependency sitting in your mail-authentication path.

spf53 is the middle ground: a small tool you run yourself, on a schedule,
that re-flattens automatically, refuses to publish a change that looks
dangerous, and tells you when something needs attention.

Every run (every hour by default): resolve providers → flatten to IPs →
diff against what's live in Route53 → guard-check the diff → apply as one
atomic change → notify over SNS. No diff, no writes, no noise.

## How it works

spf53 never touches your domain's apex TXT record — that's where site
verification records and other unrelated TXT data usually live, and it's
where *you* keep control of the top-level SPF policy. Instead, spf53 owns a
chain of records under `_spf53-1`, `_spf53-2`, … and you point your apex at
the first one, once, by hand:

```
example.com          TXT  "v=spf1 include:_spf53-1.example.com ~all"
                            ^ you set this once; spf53 never touches it

_spf53-1.example.com TXT  "v=spf1 exists:%{i}._spf.mta.salesforce.com
                            ip4:203.0.113.0/24 include:_spf53-2.example.com"

_spf53-2.example.com TXT  "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 ~all"
```

Passthrough mechanisms (things spf53 can't or shouldn't flatten, like
macro-based `exists:` rules) go verbatim at the front of the first chunk.
Every chunk after that is packed with `ip4`/`ip6` ranges up to the TXT
record size limit; every chunk except the last ends with
`include:_spf53-N+1.<domain>`, and the last ends with your policy (`~all`
or `-all`). If a provider shrinks and the chain gets shorter, the now-unused
trailing `_spf53-N` records are deleted in the same change batch — nothing
is left dangling.

`spf53 plan` always prints the apex record it expects to see and warns
(never errors) if your live apex doesn't reference `_spf53-1.<domain>`.

## Quickstart

```bash
pip install spf53
```

Write a config file:

```yaml
# spf53.yaml
sns_topic_arn: arn:aws:sns:us-east-1:123456789012:spf53-alerts  # optional
resolver_ips: ["1.1.1.1", "8.8.8.8"]                             # optional, defaults shown

domains:
  - name: example.com
    hosted_zone_id: Z123EXAMPLE
    policy: "~all"
    max_shrink_pct: 30
    passthrough:
      - "exists:%{i}._spf.mta.salesforce.com"
    includes:
      - _spf.google.com
      - amazonses.com
```

See what spf53 would publish, with no AWS changes:

```bash
spf53 plan -c spf53.yaml
```

Bootstrap the scheduled Lambda (SNS topic, SSM config, IAM role, Lambda
function, EventBridge schedule — all created or updated idempotently):

```bash
spf53 deploy -c spf53.yaml --create-topic spf53-alerts
```

From then on, spf53 runs itself every hour. To trigger a one-off run
against the config already deployed to SSM:

```bash
spf53 apply
```

## Config reference

The config is a single YAML document, either a local file (`-c/--config`)
or the value of an SSM parameter (`--ssm-param`, default `/spf53/config`).

| Key | Required | Default | Description |
|---|---|---|---|
| `domains` | yes | — | List of domain blocks (see below). Domain names must be unique (case-insensitive). |
| `sns_topic_arn` | no | none | Where alerts are published. No alerts if absent. |
| `resolver_ips` | no | `["1.1.1.1", "8.8.8.8"]` | DNS resolvers used for flattening, queried alternately with retries. |

Each entry in `domains`:

| Key | Required | Default | Description |
|---|---|---|---|
| `name` | yes | — | The domain whose SPF is being flattened. |
| `hosted_zone_id` | yes | — | Route53 hosted zone ID for this domain. No zone auto-discovery. |
| `includes` | yes | — | Provider `include:` targets to recursively resolve and flatten. |
| `passthrough` | no | `[]` | Mechanisms copied verbatim, never flattened, placed first in chunk 1. A bare `all` mechanism (any qualifier) is rejected — it would terminate SPF evaluation before the chunk chain. |
| `policy` | no | `"~all"` | SPF policy for the last chunk; must be `"~all"` or `"-all"`. |
| `max_shrink_pct` | no | `30` | Guard threshold — see below. |

## Safety guards

spf53 will refuse to publish (and sends an SNS alert instead) when:

- **The newly resolved set is empty.** An empty result almost always means
  a resolution problem, not a legitimate zero-IP provider.
- **The address count shrank by more than `max_shrink_pct`** compared to
  what's currently live. A shrink at or under the threshold is allowed
  through; anything larger is treated as a signal that something's wrong
  (a provider outage, a resolver problem) rather than an intended change.
  On the very first run, there's no live baseline, so this check passes as
  long as the new set is non-empty.
- **Resolution fails outright** (NXDOMAIN, timeout, missing SPF record, a
  nesting depth over 10 `include:`s deep) for a domain. That domain is
  skipped and alerted on; other domains in the same config still run.
- **The total SPF lookup cost exceeds the RFC 7208 hard limit of 10** —
  chain length, plus 1 for the apex `include:`, plus any DNS-querying
  passthrough mechanisms (`exists:`, `include:`, `a`, `mx`, `ptr`), including
  their own transitive lookups. Exceeding 10 means real mail receivers would
  PermError the whole domain, so spf53 refuses to publish rather than push a
  record they can't evaluate.

`spf53 apply --force` overrides a guard refusal for that run. Guard
refusals and resolution errors always trigger an SNS notification when a
topic is configured.

spf53 also warns (in `plan` output and in SNS messages, before it becomes a
hard refusal) once the total SPF lookup cost exceeds 9, since that's one
lookup away from the RFC 7208 limit above.

## CLI reference

| Command | Flags | Behavior |
|---|---|---|
| `spf53 plan` | `[-c FILE \| --ssm-param NAME]` | Prints the per-domain diff, lookup cost, and expected apex record. Exit `0` if nothing would change, `2` if changes are pending, `1` on error. |
| `spf53 apply` | `[-c FILE \| --ssm-param NAME] [--force]` | Applies the flattened records. Exit `0` on success (including no-op), `1` on error or guard refusal. |
| `spf53 deploy` | `-c FILE [--schedule "rate(1 hour)"] [--create-topic NAME] [--param-name NAME] [--function-name spf53] [--region REGION] [--dry-run]` | Idempotently bootstraps the SNS topic, SSM config, IAM role, Lambda function, and EventBridge schedule. `--dry-run` prints the planned actions without making any AWS calls. |

If neither `-c/--config` nor `--ssm-param` is given, `plan` and `apply`
read from SSM parameter `/spf53/config`.

## IAM permissions

Two separate sets of permissions are involved:

**The credentials you run `spf53 deploy` with** need enough access to
create/update the pieces spf53 manages:
`iam:CreateRole`, `iam:GetRole`, `iam:UpdateAssumeRolePolicy`,
`iam:PutRolePolicy`, `iam:PassRole` (for the `spf53-lambda` role),
`lambda:GetFunction`, `lambda:CreateFunction`, `lambda:UpdateFunctionCode`,
`lambda:UpdateFunctionConfiguration`, `lambda:AddPermission`,
`events:PutRule`, `events:PutTargets`, `ssm:PutParameter`,
`sns:CreateTopic` (only if using `--create-topic`), and
`sts:GetCallerIdentity`.

**The Lambda's own execution role** (`spf53-lambda`, created by `deploy`) is
scoped tightly to what the running tool actually needs — nothing more:

- `route53:ChangeResourceRecordSets` and `route53:ListResourceRecordSets`,
  scoped to the hosted zone(s) named in your config.
- `ssm:GetParameter`, scoped to the config parameter.
- `sns:Publish`, scoped to the configured alert topic (if any).
- `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` for its
  own CloudWatch log group.

## FAQ

**Why not just use SPF macros instead of flattening?**
Macros (`%{i}`, `exists:` tricks) aren't universally implemented by mail
receivers, and they don't solve the underlying problem: an `include:` still
costs a lookup no matter how it's expressed. spf53 supports macro-based
mechanisms you can't flatten (e.g. Salesforce's
`exists:%{i}._spf.mta.salesforce.com`) via `passthrough`, copied through
verbatim.

**Why isn't boto3 bundled in the Lambda deployment package?**
The Lambda Python runtime already ships boto3, so bundling it again would
just bloat the deployment zip for no benefit. `spf53 deploy` only packages
`dnspython`, `pyyaml`, and the spf53 package itself, pinned to the pure-Python
wheel versions installed in the environment you're deploying from — so the
zip matches what you tested, regardless of the Lambda runtime's own Python
version.

**How do I add or remove a provider?**
Edit the `includes` (or `passthrough`) list in your config and re-apply —
either `spf53 deploy -c spf53.yaml` again (which pushes the updated config
to SSM as part of its bootstrap) or push the file and run `spf53 apply -c`
directly. The next scheduled Lambda run will also pick up whatever is
currently in SSM.

**What happens when a provider changes its IPs?**
Nothing you have to do. On the next scheduled run, spf53 re-resolves the
provider's records, gets the new IPs, diffs them against what's live, and —
provided the change passes the safety guards — publishes the update and
sends an SNS notification. If the change looks like a problem (e.g. the
provider's records suddenly resolve to almost nothing), spf53 refuses and
alerts instead of publishing.

## Releasing

Releases publish to PyPI automatically via GitHub Actions
[Trusted Publishing](https://docs.pypi.org/trusted-publishers/) (OIDC —
no stored API tokens). To cut a release:

1. Bump `version` in `pyproject.toml` and commit.
2. Tag it (`git tag vX.Y.Z && git push origin vX.Y.Z`) and publish a
   [GitHub Release](https://github.com/babyhuey/spf53/releases) from that tag.
3. The `Release` workflow builds the sdist/wheel and publishes to PyPI —
   watch the [Actions tab](https://github.com/babyhuey/spf53/actions) for status.

## License

MIT — see [LICENSE](LICENSE).
