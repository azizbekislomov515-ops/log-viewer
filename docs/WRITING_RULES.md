# Writing explanation rule packs

LogLens explains log lines with rules. A rule is a regular expression and/or a set of
field conditions plus a few short templates. Rules live in YAML files called rule packs.
This guide covers everything a pack can contain, how LogLens loads and runs packs, and
how to test them.

The ground truth is the code: the JSON Schema in `src/loglens/explain/schema.py`, the
loader in `src/loglens/explain/rules.py` and the engine in
`src/loglens/explain/engine.py`. If this document and the code disagree, the code wins.
Please report the mismatch.

Contents:

1. [What a pack is and where packs are loaded from](#1-what-a-pack-is-and-where-packs-are-loaded-from)
2. [A minimal pack to copy](#2-a-minimal-pack-to-copy)
3. [Field reference](#3-field-reference)
4. [Examples and counter-examples](#4-examples-and-counter-examples)
5. [Overview metadata](#5-overview-metadata)
6. [Safety rules and limits](#6-safety-rules-and-limits)
7. [Workflow](#7-workflow)
8. [Common mistakes](#8-common-mistakes)

---

## 1. What a pack is and where packs are loaded from

A pack is one `*.yaml` file with a header (name, version, which sources it applies to)
and a list of rules. All rule ids in a pack start with the pack name: rules in pack
`squid` are called `squid.access.denied`, `squid.cache.starting` and so on.

When a log entry arrives, the engine tries every rule that applies to the entry's source
in order. **The first rule that matches explains the entry.** The other rules are not
tried. If no rule matches, the entry has no explanation. There is no LLM and no guessing:
the same line always gets the same explanation.

### Where packs come from

The GUI loads these directories, in this order:

| Order | Directory | Trusted | Notes |
|---|---|---|---|
| 1 | Built-in packs: `rules/` in a source checkout, `loglens/_data/rules/` in an installed package | yes | Shipped with LogLens. |
| 2 | `~/.config/loglens/rules/` (`$XDG_CONFIG_HOME/loglens/rules/`) | no | Loaded only if the directory exists. The in-app rule editor writes `user.yaml` here. |
| 3 | Each folder in **Settings → Extra rule pack folders** | no | Stored as `rule_dirs` in the `[rules]` section of `~/.config/loglens/config.toml`. `~` is expanded. |

```toml
# ~/.config/loglens/config.toml
[rules]
rule_dirs = ["~/loglens-rules", "/srv/shared/loglens-rules"]
```

In each directory, LogLens loads every file matching `*.yaml` or `*.yml`, sorted by
file name. `file_sources.yaml` is not a rule pack (it lists
well-known log files for discovery) and is always skipped.

So the global rule order is: directory order, then file name, then the order of rules in
the file. Two consequences:

- A built-in rule that matches a line wins over your own rule for the same line. Your
  rule never fires for that line.
- If two packs define the same rule id, the first one loaded wins. The later one is
  reported as `duplicate rule id` and skipped.

"Trusted" only matters for regex timeouts (see [section 6](#6-safety-rules-and-limits)).
A directory is trusted only if it is the built-in rules directory. Everything else,
including your user directory, is treated as untrusted input.

### Loading never stops the app

Problems are collected, not raised. Each problem has a file and a line number.

- Invalid YAML, or a bad pack header: the whole pack is skipped.
- A bad rule: only that rule is skipped. The rest of the pack loads.
- A bad `overview` block: the overview is dropped. The rules still load.
- A card whose `when.rules` names an unknown rule: only that card is skipped.

The GUI writes these problems to its log as warnings. Use `loglens-cli rules lint` to
see them (see [section 7](#7-workflow)).

---

## 2. A minimal pack to copy

This pack explains fail2ban "Ban" lines. It is complete: it passes `rules lint` and
`rules test`. Save it as `~/.config/loglens/rules/fail2ban.yaml` (or in any directory
you pass with `--rules`).

```yaml
pack: fail2ban
version: 1
description: fail2ban bans.
example_source: file:/var/log/fail2ban.log
applies_to:
  paths: ["/var/log/fail2ban.log*"]
  units: [fail2ban.service]

rules:
  - id: fail2ban.ban
    title: "fail2ban banned {{ ip }}"
    match:
      regex: '\[(?P<jail>[\w.-]+)\] Ban (?P<ip>[0-9A-Fa-f.:]+)$'
    template: >-
      fail2ban blocked {{ ip }} after too many failures in the {{ jail }} jail.
    cause: The address matched the jail's failure filter more than maxretry times within findtime.
    action: >-
      If {{ ip | shquote }} is a known address, unban it with
      "fail2ban-client set {{ jail | shquote }} unbanip {{ ip | shquote }}".
    category: security
    severity_override: notice
    tags: [ban]
    examples:
      - line: "2026-11-18 12:00:01,234 fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.7"
        expect:
          title: fail2ban banned 203.0.113.7
          text: fail2ban blocked 203.0.113.7 after too many failures in the sshd jail.
          action: >-
            If 203.0.113.7 is a known address, unban it with
            "fail2ban-client set sshd unbanip 203.0.113.7".
          severity: notice
          category: security
    counter_examples:
      - "2026-11-18 12:10:01,234 fail2ban.actions        [812]: NOTICE  [sshd] Unban 203.0.113.7"
```

What happens to the example line:

1. The source is `file:/var/log/fail2ban.log`. The pack's `applies_to.paths` selects it.
2. No service parser claims the line, so the generic `iso_text` parser takes the
   timestamp and level off. The message is
   `fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.7` and the fields are
   `{level: NOTICE, parser: iso_text}`.
3. The regex runs on the message. Its named groups `jail` and `ip` become template
   variables.
4. The templates are rendered. `action` quotes every value with `| shquote`, which the
   loader requires.

---

## 3. Field reference

Types used below: *text* is a non-empty string. *list of text* is a non-empty list of
non-empty strings. *scalar* is a string, an integer or a boolean.

### 3.1 Pack header

| Key | Type | Required | Meaning |
|---|---|---|---|
| `pack` | string matching `^[a-z0-9_]+$` | yes | Pack name. Every rule id must start with `<pack>.`. |
| `version` | the integer `1` | yes | Format version. Only `1` exists. |
| `example_source` | text (a source id) | yes | The source examples are parsed as when they do not set their own `source`. Also used by `loglens-cli explain --source <pack>`. Source ids look like `systemd:nginx.service`, `docker:web-1` or `file:/var/log/squid/access.log` (absolute path). |
| `description` | text | no | One line shown with the pack. |
| `applies_to` | selector ([3.2](#32-applies_to-selectors)) | no | Which sources the pack's rules apply to. Missing: every source. |
| `overview` | mapping ([section 5](#5-overview-metadata)) | no | Cards and thresholds for the Service Overview page. |
| `rules` | list of rules ([3.3](#33-rule-fields)) | yes | The rules, in evaluation order. |

No other keys are allowed in the header. A typo such as `example_sources:` makes the
whole pack fail with `Additional properties are not allowed`.

A real header, from `rules/squid.yaml`:

```yaml
pack: squid
version: 1
description: Squid access and cache log explanations.
example_source: file:/var/log/squid/access.log
applies_to:
  parsers: [squid]
  units: [squid.service, squid3.service]
  paths: ["/var/log/squid/*", "/var/log/squid3/*"]
  images: ["*squid*"]
  services: ["*squid*"]
```

### 3.2 `applies_to` selectors

A selector decides which sources a rule can see. It can appear on the pack, on a single
rule, and in `overview`.

| Key | Type | Matches | How |
|---|---|---|---|
| `units` | list of text | systemd unit name (`nginx.service`) | glob |
| `paths` | list of text | file path (`/var/log/nginx/access.log`) | glob |
| `images` | list of text | Docker image name | glob |
| `services` | list of text | Compose service name **or** container name | glob |
| `parsers` | list of text | name of the parser that parsed the entry | exact |
| `programs` | list of text | the entry's `program` field, or journald's `SYSLOG_IDENTIFIER` | exact |

Rules:

- The criteria are ORed: one matching criterion selects the source.
- A selector must have at least one key. An empty selector (`applies_to: {}`) is a
  schema error. To apply to every source, leave `applies_to` out.
- Globs use `fnmatch` and are **case-sensitive**: `*`, `?` and `[...]` work, and `*`
  also matches `/`.
- A rule's own `applies_to` **replaces** the pack's selector for that rule. It is not
  merged with it.
- Parser names in this version: `squid`, `clamav`, `nginx`, `sshd`, `dockerd` (service
  parsers) and `json`, `logfmt`, `syslog`, `iso_text` (generic parsers).
- `services: ["*"]` selects every Docker container. The Docker pack uses it on its
  lifecycle rules because Docker's events appear in each container's own stream.

### 3.3 Rule fields

| Key | Type | Required | Meaning |
|---|---|---|---|
| `id` | string matching `^[a-z0-9_]+(\.[a-z0-9_]+)+$` | yes | Unique id, `<pack>.<more>`, e.g. `squid.access.denied`. Lower case, digits and `_`, at least one dot. |
| `title` | text (template) | yes | Short headline, one line. |
| `template` | text (template) | yes | The explanation: one or two plain sentences that name the concrete IP, domain, container or file from the line. |
| `category` | `security`, `performance`, `availability`, `configuration`, `info` | yes | What kind of event this is. |
| `match` | mapping ([3.4](#34-match)) | yes | When the rule fires. |
| `examples` | list, at least 1 ([section 4](#4-examples-and-counter-examples)) | yes | Lines this rule must explain, with the expected output. |
| `counter_examples` | list, at least 1 ([section 4](#4-examples-and-counter-examples)) | yes | Similar lines this rule must not explain. |
| `cause` | text (template) | no | Probable cause. Shown as "Probable cause". Stored as the explanation's `probable_cause`. |
| `action` | text (template) | no | Suggested next step. Shown as "Next step". Stored as `suggested_action`. Every value must end in `\| shquote` ([3.7](#37-action-and-shquote)). |
| `severity_override` | `trace`, `debug`, `info`, `notice`, `warning`, `error`, `critical` | no | The severity of the explanation. Missing: the entry's own severity is kept. |
| `confidence` | number 0 to 1 | no | How sure the rule is about the *cause*. Default `0.9`. What the line says is matched deterministically; use a lower value when the cause is a guess (the Squid pack uses `0.6` for "could not reach this site"). |
| `references` | list of text | no | Links or man pages, e.g. `"man:squid(8)"` or a URL. Shown as "See". |
| `tags` | list of text | no | Labels used by overview cards, health and notifications ([3.8](#38-category-severity-tags)). |
| `applies_to` | selector ([3.2](#32-applies_to-selectors)) | no | Replaces the pack's selector for this rule. |
| `extract` | list of names | no | Values the templates need. If one is missing, the rule does not fire ([3.5](#35-extract-and-optional)). |
| `optional` | list of names | no | Values the templates can use if present; missing ones are `None` ([3.5](#35-extract-and-optional)). |

Names in `extract` and `optional` must match `^[A-Za-z_]\w*$`. No other keys are
allowed in a rule.

### 3.4 `match`

`match` must contain `regex`, `fields`, or both. Allowed keys:

| Key | Type | Meaning |
|---|---|---|
| `fields` | mapping of field name to a scalar or a non-empty list of scalars | Every listed field must exist and equal one of the given values. |
| `regex` | text | A regular expression searched in the message (or in `field`). Named groups become template variables. |
| `field` | text | What `regex` runs on. Default `message`. `raw` is the line exactly as collected, before any parser removed a prefix. Any other name is a parsed or collector field. |

The checks run in this order, cheapest first. The first one that fails ends the rule.

1. **`fields`**: each field must be present, and its value, converted to text, must
   equal one of the listed values converted to text. `status: 407` matches the integer
   `407` and the string `"407"`. Booleans compare as `true` / `false`. A list means "any
   of these": `fields: {event: [db_loaded, db_reloaded]}`.
2. **`regex`**: `search` (not a full match), so use `^` and `$` to anchor. It looks at
   the first 4096 characters of the target only (`MAX_MATCH_CHARS`). If `field` names a
   field the entry does not have, the rule does not fire.
3. **`extract`**: see below.

Syntax is Python `re` syntax. Built-in packs are compiled with `re`; untrusted packs are
compiled with the `regex` module, which accepts the same syntax and supports timeouts.

Match on parsed fields when a parser provides them. It is faster and more precise than
a regex. From `rules/squid.yaml`, using only field conditions:

```yaml
  - id: squid.access.denied_connect
    title: "Blocked HTTPS site: {{ domain }}"
    match:
      fields: {cache_result: TCP_DENIED, status: 403, method: CONNECT}
    extract: [client_ip, domain]
    optional: [user]
    template: >-
      Squid blocked {{ client_ip }}{% if user %} (user {{ user }}){% endif %} from opening a
      secure connection to {{ domain }}.
```

Field conditions and a regex on a field, combined (`rules/squid.yaml`, excerpt):

```yaml
  - id: squid.access.miss
    title: "Fetched: {{ domain or url }}"
    match:
      fields: {cache_result: TCP_MISS}
      field: status
      regex: ^[23]\d\d$
```

A regex on the raw line, because the message no longer contains the part the rule needs
(`rules/clamav.yaml`, excerpt):

```yaml
  - id: clamav.scan.stream_found
    title: "Malware sent by {{ client }}"
    match:
      field: raw
      regex: 'instream\((?P<client>[^@)]+)@\d+\): (?P<signature>\S+) FOUND'
    template: ClamAV found malware ({{ signature }}) in a file that {{ client }} sent for scanning.
```

To see the message and fields a parser produces for your lines, run
`uv run loglens-cli tail <source-id> -n 20 --fields`, for example
`uv run loglens-cli tail file:/var/log/fail2ban.log -n 20 --fields`. It hides journald's
own upper-case and `_`-prefixed fields. The comment at the top of each built-in pack
lists the fields its parser sets.

### 3.5 `extract` and `optional`

Templates may use:

- the built-in variables `source` (the source's display name) and `message` (the
  entry's message);
- every named group of the regex;
- every name listed in `extract` or `optional`.

Using any other name is a load error: `template uses addr: add to 'extract' or the regex
groups`.

For each name in `extract` and `optional`, the value is the regex group of that name if
it matched, otherwise the entry's field of that name.

- `extract`: if the value is missing or an empty string, **the rule does not fire**.
  This way an explanation never says "None".
- `optional`: if the value is missing or empty, it is `None` in the template. Test it
  with `{% if name %}` or use `{{ name or "fallback" }}`.

A named group that did not take part in the match (inside `(...)?`) and is **not**
listed in `optional` is also `None`, and `{{ name }}` prints the word `None`. List such
groups in `optional`.

Every value is cut to 200 characters (`MAX_VALUE_CHARS`, the last one becomes `…`)
before it reaches a template. The values (except `source` and `message`) are stored
with the explanation as `extracted`, and overview cards read them.

Types: regex groups are always strings. Parser fields keep their type (the Squid
parser's `status` and `elapsed_ms` are integers). Convert groups before arithmetic:
`{{ (ms | int) / 1000 }}`, not `{{ ms / 1000 }}`.

### 3.6 Templates

`title`, `template`, `cause` and `action` are Jinja2 templates. They run in a restricted
sandbox (details in [section 6](#6-safety-rules-and-limits)). In short:

- Output: `{{ name }}`, `{{ name or "the server" }}`, `{{ a ~ b }}`, arithmetic,
  comparisons, `x[0]`, `x[:10]`.
- Conditions: `{% if %}`, `{% elif %}`, `{% else %}`, and inline `a if cond else b`.
  Tests such as `is none` work.
- Not allowed: `{% for %}`, `{% set %}`, macros, includes, method calls
  (`name.upper()`), attribute access (`name.attr`), `**`.
- Filters: only those in this table.

| Filter | Effect |
|---|---|
| `shquote` | Quotes for a POSIX shell (`shlex.quote`): `x; rm -rf ~` becomes `'x; rm -rf ~'`. Required in `action`. |
| `thousands` | `8708530` becomes `8,708,530`. Non-numbers are unchanged. |
| `int`, `float`, `round`, `abs` | Numbers. `round(1)` keeps one decimal. |
| `filesizeformat` | `48213` becomes `48.2 kB`. |
| `lower`, `upper`, `capitalize`, `title`, `trim` | Text. |
| `default` | `{{ name \| default("unknown") }}`. |
| `length` | Length of a string or list. |

Rendering details:

- Missing variables are an error (`StrictUndefined`). The loader already rejects
  unknown names, so this only happens with odd expressions.
- Whitespace in the result is collapsed to single spaces. YAML folded blocks (`>-`) and
  `{% if %}` blocks spread over several lines read cleanly.
- The result is cut at 8000 characters (`MAX_OUTPUT_CHARS`).
- If `template` renders to an empty string, the rule does not fire.
- An error while rendering (for example dividing a string) skips the rule for that line
  and logs `rule failed to render` once per rule. The next rule gets a chance.

From `rules/squid.yaml`, filters and arithmetic on parser fields (integers):

```yaml
    template: >-
      {{ client_ip }} opened an encrypted connection to {{ domain }} through the proxy. It lasted
      {{ (elapsed_ms / 1000) | round(1) }} s and carried {{ bytes | filesizeformat }}; Squid
      cannot see or cache what was inside.
```

`{% if %}` in `cause` (`rules/squid.yaml`):

```yaml
    cause: >-
      {% if status == 502 %}The web server sent a broken reply or closed the connection
      early.{% elif status == 503 %}The web server is overloaded or down for
      maintenance.{% else %}The web server hit an internal error.{% endif %}
```

`thousands` (`rules/clamav.yaml`):

```yaml
    template: clamd loaded its virus database ({{ signatures | thousands }} signatures) and is ready to scan.
```

### 3.7 `action` and `shquote`

`action` often contains commands an admin will copy and paste into a shell. The values
in it come from log text, which an attacker can control. So the loader requires that
**every `{{ ... }}` in `action` is either a literal or ends with `| shquote`**.
Otherwise the rule fails to load with:

```text
every value in 'action' must end with '| shquote': actions hold commands admins copy-paste, and log text is untrusted
```

| In `action` | Allowed |
|---|---|
| `{{ ip \| shquote }}` | yes |
| `{{ (domain or url) \| shquote }}` | yes |
| `{{ "literal" }}` | yes |
| `{% if domain %}{{ domain \| shquote }}{% else %}the same site{% endif %}` | yes (`{% if %}` is fine, every printed value is quoted) |
| `{{ ip }}` | no |
| `{{ ip \| shquote \| upper }}` | no (`shquote` must be the last filter) |

Quote even when the value goes into prose rather than a command. Do not add your own
quotes around a quoted value: `'{{ x | shquote }}'` breaks for values that need
quoting.

From `rules/squid.yaml`:

```yaml
    action: >-
      Nothing to do if {{ domain | shquote }} is meant to be blocked. Otherwise find the acl that lists
      {{ domain | shquote }} (grep -nF {{ domain | shquote }} /etc/squid/squid.conf /etc/squid/*.acl) and adjust it.
```

`title`, `template` and `cause` do not need `shquote`. They are plain text, and the GUI
escapes them before display.

### 3.8 Category, severity, tags

**`category`** (required) is one of `security`, `performance`, `availability`,
`configuration`, `info`.

**`severity_override`** is one of `trace`, `debug`, `info`, `notice`, `warning`,
`error`, `critical` (least to most severe). It sets the explanation's severity. Without
it, the explanation keeps the severity the parser gave the entry. Use it when the line's
own level is misleading: a Squid "Terminated abnormally" line is `critical`, a 404 is
`info`.

**`tags`** are free-form labels. Overview cards select entries by tag. Some tags have a
meaning elsewhere in the app:

| Tag | Used by |
|---|---|
| `restart` | Restart counts and "last restart" in summaries, Service Overview health, Compose service tiles; restart-loop notifications (3 restarts in 5 minutes). |
| `restart_loop` | Service Overview health becomes "failing"; the "restart loop" desktop notification. |
| `detection` | The "malware or security detection" desktop notification. |
| `dependency` | Compose service tiles show the explanation as a dependency hint. |

Reuse existing tags where they fit (`denial`, `upstream`, `exit`, `oom`, `failure`,
`login_failure`, ...), so cards and filters in other packs pick your entries up.

---

## 4. Examples and counter-examples

Both are **mandatory**: every rule needs at least one example and at least one
counter-example. They are the rule's tests. `loglens-cli rules test` runs them, and so
does the test suite and the in-app editor before it saves.

### Example

| Key | Type | Required | Meaning |
|---|---|---|---|
| `line` | text | yes | A log line exactly as the collector delivers it (for files: the whole line, timestamp included). |
| `expect` | mapping | yes | Expected output. Only the keys you list are compared. |
| `source` | text (source id) | no | The source the line comes from. Default: the pack's `example_source`. |
| `fields` | mapping of field name to scalar | no | Collector fields the line arrives with, e.g. `{stream: events}`. |

`expect` keys:

| Key | Type | Required | Compared with |
|---|---|---|---|
| `text` | text | yes | rendered `template` |
| `title` | text | no | rendered `title` |
| `cause` | text | no | rendered `cause` |
| `action` | text | no | rendered `action` |
| `severity` | severity name | no | the explanation's severity (`severity_override`, or the parsed severity) |
| `category` | category name | no | `category` |

Comparison is exact, after the whitespace collapsing described in
[3.6](#36-templates). So a folded YAML block (`>-`) in `expect.text` works the same way
as one long line.

### Counter-example

Either a plain string (the line), or a mapping:

| Key | Type | Required | Meaning |
|---|---|---|---|
| `line` | text | yes | The line. |
| `source` | text (source id) | no | Default: the pack's `example_source`. |
| `fields` | mapping of field name to scalar | no | Collector fields. |

A good counter-example is a *similar* line that must get a different explanation: the
`Unban` line for a `Ban` rule, a 407 for a 403 rule, the same text arriving on `stdout`
instead of from Docker's event stream.

### How they are run

Each line goes through the real pipeline: `source` is turned into a source, the line is
parsed by the normal parsers with the example's `fields` as collector fields, and the
whole engine (all loaded packs, in order) explains it. The collector time is fixed at
2026-11-18 12:00 UTC, so lines without a year parse the same way every time.

- An example passes only if **this rule** explains it, and every key in `expect`
  matches. "Explained by some rule" is not enough: if an earlier rule wins, the failure
  is `example explained by <other rule> instead`. This is how shadowing is caught.
- A counter-example passes if this rule does **not** explain it. Another rule may.

The example's source must be one that the rule's selector selects. If a rule has its own
`applies_to` that the pack's `example_source` does not match, give each example a
`source` that does. From `rules/docker.yaml`, with collector fields:

```yaml
  - id: docker.container.exit_0
    title: "{{ name }} finished (exit 0)"
    applies_to:  # only containers' own streams carry Docker's lifecycle events
      services: ["*"]
    match:
      fields: {stream: events}
      regex: ^container die \S+ (?=.*[(,] ?exitCode=(?P<code>0)[,)])(?=.*[(,] ?name=(?P<name>[^,)]+))
    template: Container {{ name }} stopped normally (exit code 0); its main program finished its work.
    action: Nothing to do for one-off jobs. If {{ name | shquote }} is a long-running service, check why its program exited (docker logs {{ name | shquote }}).
    category: availability
    tags: [exit]
    severity_override: info
    examples:
      - line: "2026-11-18T20:10:00.123456789+05:00 container die 4f1e2d3c4b5a (exitCode=0, image=alpine, name=backup-job)"
        source: docker:web-1
        fields: {stream: events}
        expect:
          title: backup-job finished (exit 0)
          text: Container backup-job stopped normally (exit code 0); its main program finished its work.
    counter_examples:
      - line: "2026-11-18T20:10:00.123456789+05:00 container die 4f1e2d3c4b5a (exitCode=0, image=alpine, name=backup-job)"  # printed on stdout: not Docker
        source: docker:web-1
        fields: {stream: stdout}
      - "2026-11-18T20:10:00.123456789+05:00 container die 4f1e2d3c4b5a (exitCode=1, image=alpine, name=backup-job)"
```

---

## 5. Overview metadata

The optional `overview` block feeds the Service Overview page: the "What is happening"
paragraph, the health header, and cards. LogLens has no per-service overview code; all
of it comes from packs.

| Key | Type | Required | Meaning |
|---|---|---|---|
| `applies_to` | selector | no | Sources that show this pack's cards. Default: the pack's own `applies_to`. |
| `key_fields` | mapping of field name to label (text), at least one | no | Fields the summary names as "top" values, e.g. `{client_ip: client}`. |
| `thresholds` | mapping | no | See below. |
| `cards` | list of cards, at least one | no | See below. |

No other keys are allowed.

**When a pack's overview is used.** For a source (or a group of sources), a pack's
overview applies when the pack's own non-empty `applies_to` selects the source, when one
of its rules explained an entry in the period, or when `overview.applies_to` selects the
source. Cards appear in that order: the service's own pack first, packs whose rules
fired next, broad packs (such as Docker's lifecycle cards for every container) last.
`key_fields` of all applicable packs are merged. Without any, the defaults are
`client_ip`, `src_ip`, `domain`, `status` and `user`.

**`thresholds`** (all optional):

| Key | Type | Default | Meaning |
|---|---|---|---|
| `error_rate` | number, more than 0, at most 1 | `0.05` | Share of error-or-worse entries in the last 5 minutes that makes the service "degraded". Twice this makes it "failing". |
| `spike_z` | number, more than 0 | `3.0` | z-score of a bucket's error count against earlier buckets that counts as a spike. |
| `spike_min_errors` | integer, at least 1 | `5` | A bucket needs at least this many errors to be a spike. |

When several applicable packs set a threshold, the first pack in the order above wins.

**Cards**:

| Key | Type | Required | Meaning |
|---|---|---|---|
| `title` | text | yes | Card heading. |
| `kind` | `top`, `count`, `recent` | yes | `top`: most frequent values of `field`. `count`: how many entries. `recent`: the newest entries. |
| `field` | text | for `top` | The value to count. Read from the rule's extracted values first, then from the entry's fields. |
| `columns` | list of text | no | `recent` only: extra columns after time and title, read like `field`. |
| `limit` | integer 1 to 50 | no | Rows shown. Default 5. |
| `warn_at` | integer, at least 1 | no | Highlight the card when at least this many entries are selected. |
| `empty` | text | no | Shown when nothing is selected. Default "Nothing in this period." |
| `when` | mapping, at least one key | no | Which entries feed the card. Without it: every entry. |

`when` keys:

| Key | Type | Meaning |
|---|---|---|
| `rules` | list of rule ids | Entries explained by one of these rules. The ids must exist in the same pack. |
| `tags` | list of text | Entries whose explanation has one of these tags. |
| `min_severity` | severity name | Entries at least this severe (explanation severity, or the entry's own if unexplained). |

`rules` and `tags` are ORed. `min_severity` is an additional condition (AND).

From `rules/squid.yaml`:

```yaml
overview:
  key_fields: {client_ip: client, domain: domain}
  thresholds: {error_rate: 0.10}
  cards:
    - {title: Top clients, kind: top, field: client_ip}
    - {title: Top domains, kind: top, field: domain}
    - {title: Blocked sites, kind: top, field: domain, when: {tags: [denial]}, empty: Nothing was blocked.}
    - {title: Sites that failed, kind: top, field: domain, when: {tags: [upstream]}, empty: Every site answered.}
    - {title: Served from cache, kind: count, when: {tags: [cache_hit]}}
    - {title: Proxy errors, kind: recent, when: {min_severity: error}, limit: 5, empty: No errors.}
```

A pack whose rules apply to a narrow set of sources but whose cards should show more
widely sets `overview.applies_to` (`rules/docker.yaml`, excerpt):

```yaml
overview:
  # Container lifecycle events appear in each container's own stream.
  applies_to: {services: ["*"], units: [docker.service, containerd.service]}
```

---

## 6. Safety rules and limits

Packs are treated as untrusted input (only the built-in directory is trusted), and log
text is always untrusted. These limits are enforced by the loader and engine. You
cannot turn them off from a pack.

| Limit | Value | Effect |
|---|---|---|
| `MAX_MATCH_CHARS` | 4096 | A regex only sees the first 4096 characters of its target. |
| `MAX_VALUE_CHARS` | 200 | Each value is cut to 200 characters before it reaches a template. |
| `MAX_OUTPUT_CHARS` | 8000 | Each rendered template is cut to 8000 characters. |
| `MAX_REPEAT` | 10 000 | `"ab" * n` may not build a string longer than this; repeating lists is not allowed; a filter argument may not be a constant above it. |
| `RULE_TIMEOUT_S` | 0.02 s | Untrusted packs only: a regex that runs longer than 20 ms on one line gives up. The rule does not match that line; later rules still get the line. |
| `MAX_RULE_TIMEOUTS` / `RULE_COOLDOWN_S` | 3 / 60 s | A rule that times out 3 times within 60 s is suspended for 60 s, then tried again. Never permanently: log text must not be able to switch a detection off for good. |

**Template sandbox.** Templates run in Jinja2's immutable sandbox, plus a check at load
time that the template uses only the allowed node types (`ALLOWED_NODES`: output,
names, constants, filters, tests, `if` / inline `if`, comparisons, `and` / `or` /
`not`, indexing and slicing, `+ - * / // %`, unary `-` / `+`, `~`, tuples and lists)
and the filters in `ALLOWED_FILTERS` (the table in [3.6](#36-templates)). Loops can hang
the app even in a sandbox, method calls and attribute access can reach internals, and
filters like `replace`, `center`, `indent`, `join` or `wordwrap` can multiply a value's
size; all of them are rejected at load time. Log text is passed in as data and never
evaluated: a line containing `{{ 7*191 }}` is shown as that text.

**`shquote` in `action`.** See [3.7](#37-action-and-shquote).

**Regex timeouts, trusted and untrusted.** Built-in packs use Python's `re` (fast, no
timeout). Their regexes are checked in CI against crafted 4 KB lines
(`tests/test_explain_bench.py::test_no_rule_regex_backtracks_quadratically`, limit 5 ms
per regex and line). Packs from any other directory use the `regex` module with the
20 ms timeout. Rules that keep timing out show up in the log as
`rule suspended for 60 s: its regex keeps timing out`. A timeout during
`rules test` looks like a plain non-match (`example not explained by any rule`).

**Fields log text cannot set.** Rules can trust some fields because only LogLens itself
sets them. If a parser extracts a field with one of these names from a line, the
normalizer drops it; the collector's and the normalizer's values always win:

| Field | Set by | Meaning |
|---|---|---|
| `stream` | Docker collector | `stdout`, `stderr`, or `events` for Docker's own lifecycle events. |
| `parser` | normalizer | Name of the parser that parsed the line. |
| `truncated` | collector / normalizer / multiline assembler | The line was cut (too long, or a file was truncated). |
| `lines` | multiline assembler | Number of physical lines in an assembled event (stack traces). |
| `timestamp_source` | normalizer | `ingest` when no timestamp was found and the arrival time was used. |
| `redacted` | redactor | Number of secrets removed from the line. |

This is why the Docker lifecycle rules require `fields: {stream: events}`. A container
can print `container die ... (exitCode=137, ...)` on its stdout, but that line gets
`stream: stdout`, so it cannot fake an OOM kill or a restart. Use these fields in
`match.fields` whenever a rule must only fire for events LogLens observed itself. In
examples and counter-examples, set them with `fields:`.

Other fields come from parsers, that is from log text. `program` (the syslog tag) is one
of them, so a `programs:` selector says where a line claims to come from, not where it
came from. journald's own trusted fields (`_SYSTEMD_UNIT`, `_PID`, ...) are collector
fields and do win over parsed ones.

---

## 7. Workflow

All commands run from the repository root with `uv run`. `--rules` takes **one**
directory; without it, the built-in packs are used.

### 1. Write

Start from the minimal pack in [section 2](#2-a-minimal-pack-to-copy), or from the
built-in pack closest to your service. Collect a few real lines first, and look at how
they parse:

```sh
uv run loglens-cli tail file:/var/log/fail2ban.log -n 20 --fields
```

Put specific rules before general ones.

### 2. Lint

```sh
uv run loglens-cli rules lint --rules ~/.config/loglens/rules
```

`rules lint` loads every pack in the directory and prints each problem as
`file:line: [rule id] message`, then a count. For the minimal pack with `{{ jail }}` mistyped as `{{ addr }}`:

```text
/home/me/.config/loglens/rules/fail2ban.yaml:14: [fail2ban.ban] template uses addr: add to 'extract' or the regex groups
1 packs, 0 rules, 1 problems
```

Exit status 1 if there is any problem.

### 3. Test

```sh
uv run loglens-cli rules test --rules ~/.config/loglens/rules
uv run loglens-cli rules test --rules ~/.config/loglens/rules --pack fail2ban
```

`rules test` runs every example and counter-example. `--pack` (repeatable) limits the
run to those packs, but all packs in the directory are still loaded, so shadowing
between them still shows. Failures look like this:

```text
/home/me/.config/loglens/rules/demo.yaml:5: [demo.ban] output differs
    text:
      expected 'banned 1.2.3.4 in sshd'
      got      'banned 1.2.3.4 in None'
    line: 'Ban 1.2.3.4'
1 rules, 2 examples, 1 failures
```

Exit status 1 on any failure, any load problem, or when no rule was tested.

`--rules` loads only that directory. In the app, built-in packs come first and can
shadow your rules. To test your pack the way the app runs it, with the built-in packs
loaded first:

```sh
uv run python -c "
from pathlib import Path
from loglens.explain import DEFAULT_RULES_DIR, ExplanationEngine, load_rules
from loglens.explain.examples import run_examples
engine = ExplanationEngine(load_rules([DEFAULT_RULES_DIR, Path('~/.config/loglens/rules').expanduser()]))
print(*engine.issues, sep='\n')
report = run_examples(engine, ['fail2ban'])
print(*report.failures, sep='\n')
print(report.rules, 'rules,', report.examples, 'examples,', len(report.failures), 'failures')
"
```

### 4. Try it on a real file

```sh
uv run loglens-cli explain --file /var/log/fail2ban.log --source fail2ban --rules ~/.config/loglens/rules
```

`--source` takes either a pack name or a source id:

- A **pack name** loads only that pack and parses the lines as if they came from the
  pack's `example_source`. Use this for a copy of a log in another place, because path
  selectors would not match the copy's path.
- A **source id** (`systemd:nginx.service`, `docker:web-1`, `file:/var/log/x.log`)
  loads all packs in the rules directory and parses the lines as that source.
- Without `--source`, the file is its own source (`file:<absolute path>`).

`explain` prints each entry with its explanation (or `(no explanation available)`),
then how many entries were explained and a short summary. Use it to find lines your
pack misses. Note that `explain` reads plain lines, so rules that require collector
fields such as `stream: events` never fire there; cover those with examples.

With the fuller fail2ban pack below, a four-line log gives (the final summary line is
left out):

```text
2026-11-18 12:00:00 INFO     fail2ban.server         [812]: INFO    Starting Fail2ban v1.0.2
    (no explanation available)

2026-11-18 12:00:00 INFO     fail2ban.filter         [812]: INFO    [sshd] Found 203.0.113.7 - 2026-11-18 12:00:00
    => Failure counted for 203.0.113.7  [info, security]
       fail2ban counted a failure from 203.0.113.7 in the sshd jail (logged at 2026-11-18 12:00:00). Enough of these in a row lead to a ban.

2026-11-18 12:00:01 NOTICE   fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.7
    => fail2ban banned 203.0.113.7  [notice, security]
       fail2ban blocked 203.0.113.7 after too many failures in the sshd jail.
       Probable cause: The address matched the jail's failure filter more than maxretry times within findtime.
       Next step: If 203.0.113.7 is a known address, unban it with "fail2ban-client set sshd unbanip 203.0.113.7".

2026-11-18 12:10:01 NOTICE   fail2ban.actions        [812]: NOTICE  [sshd] Unban 203.0.113.7
    => fail2ban lifted the ban on 203.0.113.7  [info, security]
       The sshd jail's ban on 203.0.113.7 expired or was lifted by hand; it can connect again.


3 of 4 entries explained.
```

### 5. Load it in the app

Put the file in `~/.config/loglens/rules/` or in a folder listed under **Settings →
Extra rule pack folders**. The app reloads rules when you save a rule in the editor or
change the folder list. After editing a pack file by hand, restart the app.

### The in-app rule editor

For an unexplained line, **Create rule from this line…** (in the explanation panel and
the log view's context menu) opens the rule editor. It:

- suggests an id (`user.<first words>`), a title, and a regex built from the line with
  IPv4 addresses captured as `ip`, `ip2`, ... and numbers and hex ids generalized;
- scopes the rule to the line's own service (`units`, `services` or `paths`); untick
  **Scope** to apply it to every source;
- matches on `message` or `raw` only;
- requires a counter-example, and pre-fills a nearby line with a different message;
- shows a live preview made with the real loader and sandbox, with the regex groups and
  the rendered explanation.

**Save** adds the rule to (or replaces it by id in) `~/.config/loglens/rules/user.yaml`,
pack `user`, with the line as its example and the rendered text as `expect.text`. Before
writing, it loads the whole `user` pack in a temporary directory and runs its examples;
if anything fails, nothing is written. The file is owner-only (mode 600).

The editor rewrites `user.yaml` with a YAML dumper, so comments and formatting you add
there by hand are lost on the next save. Keep hand-written rules in a separate file in
the same directory, e.g. `~/.config/loglens/rules/mysite.yaml`.

### A fuller example pack

The minimal pack from [section 2](#2-a-minimal-pack-to-copy), extended with an overview,
an `optional` group, and a `fields` condition on the `level` field set by the
`iso_text` parser. It passes `rules lint` and `rules test`, and produced the `explain`
output above.

```yaml
# fail2ban: bans, unbans, counted failures and configuration errors.
# Lines go through the generic iso_text parser: the message starts after the timestamp
# ("fail2ban.actions [812]: NOTICE  [sshd] Ban 203.0.113.7") and `level` is set.
pack: fail2ban
version: 1
description: fail2ban bans, unbans and configuration errors.
example_source: file:/var/log/fail2ban.log
applies_to:
  paths: ["/var/log/fail2ban.log*"]
  units: [fail2ban.service]

overview:
  key_fields: {ip: address, jail: jail}
  thresholds: {error_rate: 0.2, spike_min_errors: 3}
  cards:
    - {title: Banned addresses, kind: top, field: ip, when: {tags: [ban]}, empty: Nobody was banned.}
    - {title: Failures counted, kind: count, when: {tags: [failure]}, warn_at: 100}
    - {title: Recent bans, kind: recent, when: {rules: [fail2ban.ban]}, columns: [jail, ip], limit: 8}
    - {title: Errors, kind: recent, when: {min_severity: error}, empty: No errors.}

rules:
  - id: fail2ban.ban
    title: "fail2ban banned {{ ip }}"
    match:
      regex: '\[(?P<jail>[\w.-]+)\] Ban (?P<ip>[0-9A-Fa-f.:]+)$'
    template: >-
      fail2ban blocked {{ ip }} after too many failures in the {{ jail }} jail.
    cause: The address matched the jail's failure filter more than maxretry times within findtime.
    action: >-
      If {{ ip | shquote }} is a known address, unban it with
      "fail2ban-client set {{ jail | shquote }} unbanip {{ ip | shquote }}".
    category: security
    severity_override: notice
    tags: [ban]
    examples:
      - line: "2026-11-18 12:00:01,234 fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.7"
        expect:
          title: fail2ban banned 203.0.113.7
          text: fail2ban blocked 203.0.113.7 after too many failures in the sshd jail.
          severity: notice
    counter_examples:
      - "2026-11-18 12:10:01,234 fail2ban.actions        [812]: NOTICE  [sshd] Unban 203.0.113.7"

  - id: fail2ban.unban
    title: "fail2ban lifted the ban on {{ ip }}"
    match:
      regex: '\[(?P<jail>[\w.-]+)\] Unban (?P<ip>[0-9A-Fa-f.:]+)$'
    template: The {{ jail }} jail's ban on {{ ip }} expired or was lifted by hand; it can connect again.
    category: security
    severity_override: info
    examples:
      - line: "2026-11-18 12:10:01,234 fail2ban.actions        [812]: NOTICE  [sshd] Unban 203.0.113.7"
        expect:
          text: The sshd jail's ban on 203.0.113.7 expired or was lifted by hand; it can connect again.
          severity: info
    counter_examples:
      - "2026-11-18 12:00:01,234 fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.7"

  - id: fail2ban.found
    title: "Failure counted for {{ ip }}"
    match:
      regex: '\[(?P<jail>[\w.-]+)\] Found (?P<ip>[0-9A-Fa-f.:]+)(?: - (?P<when>\S+ \S+))?$'
    optional: [when]
    template: >-
      fail2ban counted a failure from {{ ip }} in the {{ jail }} jail{% if when %} (logged at
      {{ when }}){% endif %}. Enough of these in a row lead to a ban.
    category: security
    tags: [failure]
    examples:
      - line: "2026-11-18 12:00:00,100 fail2ban.filter         [812]: INFO    [sshd] Found 203.0.113.7 - 2026-11-18 12:00:00"
        expect:
          text: >-
            fail2ban counted a failure from 203.0.113.7 in the sshd jail (logged at 2026-11-18
            12:00:00). Enough of these in a row lead to a ban.
          severity: info
      - line: "2026-11-18 12:00:00,100 fail2ban.filter         [812]: INFO    [sshd] Found 203.0.113.7"
        expect:
          text: >-
            fail2ban counted a failure from 203.0.113.7 in the sshd jail. Enough of these in a
            row lead to a ban.
    counter_examples:
      - "2026-11-18 12:00:01,234 fail2ban.actions        [812]: NOTICE  [sshd] Ban 203.0.113.7"

  - id: fail2ban.config_error
    title: fail2ban configuration error
    match:
      fields: {level: ERROR}
      regex: 'Failed during configuration: (?P<reason>.+)$'
    template: "fail2ban could not load its configuration: {{ reason }}."
    cause: A jail points at a log file or backend that does not exist, or jail.local has a typo.
    action: Run "fail2ban-client -t" to test the configuration, fix the jail it names, then "systemctl restart fail2ban".
    category: configuration
    severity_override: error
    examples:
      - line: "2026-11-18 12:00:00,000 fail2ban                [812]: ERROR   Failed during configuration: Have not found any log file for sshd jail"
        expect:
          text: "fail2ban could not load its configuration: Have not found any log file for sshd jail."
          severity: error
          category: configuration
    counter_examples:
      - "2026-11-18 12:00:00,000 fail2ban                [812]: INFO    Failed during configuration: Have not found any log file for sshd jail"
```

### Contributing a built-in pack

Built-in packs live in `rules/`. Besides `rules lint` and `rules test` (no `--rules`
needed), run the regex speed check, because built-in regexes run without a timeout:

```sh
uv run pytest tests/test_explain_bench.py -k backtracks
```

---

## 8. Common mistakes

### `: ` inside an unquoted regex

In YAML, `: ` (colon followed by a space) inside a plain value starts a mapping.

```yaml
    match:
      regex: NOTICE: Ban (?P<ip>\S+)$
```

```text
demo.yaml:14: invalid YAML: mapping values are not allowed in this context
```

The whole pack fails to load. Quote regexes. **Single quotes** are the safest: a
backslash is just a backslash, and a literal `'` is written `''`.

```yaml
    match:
      regex: 'NOTICE: Ban (?P<ip>\S+)$'
```

### Backslashes in double quotes

In double-quoted YAML strings, `\` starts an escape sequence. `"\d"`, `"\S"`, `"\["` are
invalid YAML (`found unknown escape character`), and some sequences (`"\b"`, `"\t"`)
are valid YAML but turn into a different character. Use single quotes, or double every
backslash as `rules/systemd.yaml` does: `"^(?P<unit>\\S+): ..."`.

A value starting with `{`, `[`, `*`, `&`, `!`, `%`, `@`, `` ` ``, `|` or `>`, or
containing ` #`, also needs quotes. Templates starting with `{{` must be quoted for the
same reason: `template: "{{ domain }} told ..."`.

### `on`, `yes`, `no` parse as booleans

LogLens reads YAML 1.1, where unquoted `on`, `off`, `yes`, `no`, `true`, `false` (any
case) are booleans.

- As a key: `on: message` in `match` becomes the key `True`, and the rule fails with
  `match: Additional properties are not allowed (True was unexpected)`. The key that
  selects what the regex runs on is `field`, not `on`.
- As a value: `fields: {flag: on}` compares the field with `true`, not with `on`, so a
  field with the text `on` never matches. In `tags` or other text lists, `[on]` is a
  schema error because a boolean is not a string. Quote such values: `"on"`, `"no"`.

### Catastrophic backtracking

Nested or overlapping quantifiers such as `(a+)+`, `(\w+\s?)+$`, `(a|aa)+` or
`(.*,)*` can take exponential time on a line that almost matches. Log lines are attacker
input. In your packs such a rule times out after 20 ms per line and is suspended after
3 timeouts within 60 s, so it silently explains nothing for long stretches. In a
built-in pack it would stall the app, which is why CI rejects it.

- Anchor with `^` where you can, and use `\S+`, `[^,)]+` or `[^"]*` instead of `.*`
  between delimiters.
- Never put a quantified group inside another quantifier when both can match the same
  text.
- Prefer `match.fields` when the parser already split the line.

### First match wins: rule order

Rules are tried in order and the first match explains the line. A general rule placed
before a specific one hides it:

```yaml
  - id: demo.any_ban
    match:
      regex: '(?i)ban (?P<ip>\S+)$'   # also matches "Unban 1.2.3.4"
  - id: demo.unban
    match:
      regex: 'Unban (?P<ip>\S+)$'     # never reached for unban lines
```

`rules test` reports this as
`[demo.unban] example explained by demo.any_ban instead`. Put specific rules first, or
make the general one stricter. Across packs, the order is directory, then file name;
built-in packs always come before yours.

### Other mistakes

| Mistake | What you see | Fix |
|---|---|---|
| Value in `action` without `\| shquote` | `every value in 'action' must end with '\| shquote' ...` | Add `\| shquote` as the last filter of every value. |
| Template uses a name not in the regex groups, `extract` or `optional` | `template uses addr: add to 'extract' or the regex groups` | Fix the name or list it. |
| Optional regex group not listed in `optional` | The text says `None` | Add it to `optional`, use `{% if %}`. |
| Arithmetic on a regex group | `rule failed to render` in the log; in tests, `example not explained by any rule` | Groups are strings: `(ms \| int) / 1000`. |
| Rule id without the pack prefix | `rule id must start with 'demo.'` | Rename. |
| Rule id without a dot or with capitals | `id: 'demo_ban' does not match '^[a-z0-9_]+(\\.[a-z0-9_]+)+$'` | `demo.ban`. |
| No counter-example | `'counter_examples' is a required property` | Add a similar line the rule must not explain. |
| `{% for %}`, `{% set %}`, `name.upper()` | `'For' is not allowed in rule templates`, `'Call' is not allowed ...` | Use `{% if %}` and filters. |
| A filter outside the list (`replace`, `join`, ...) | `filter 'replace' is not allowed in rule templates` | Use an allowed filter, or capture the part you need with a regex group. |
| Example source not selected by the rule | `example not explained by any rule` | Give the example a `source` the rule's `applies_to` selects. |
| A rule for collector events tested without the field | `example not explained by any rule` | Add `fields: {stream: events}` to the example. |
| Testing a path-scoped pack on a copied file with `explain` | Nothing is explained | Use `--source <pack name>`. |
