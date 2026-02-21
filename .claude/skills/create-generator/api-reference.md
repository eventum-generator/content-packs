# Eventum Template API Reference

## Variables available in templates

| Variable | Type | Description |
|----------|------|-------------|
| `timestamp` | `datetime` | Timezone-aware datetime from input plugin |
| `tags` | `tuple[str, ...]` | Tags from input plugin |
| `params` | `dict` | User-defined params from `generator.yml` event.template.params |
| `samples` | object | Sample data — access as `samples.<name>` |
| `module` | object | Data generation modules (see below) |
| `shared` | object | State shared across templates in the same generator |
| `globals` | object | State shared across ALL generators |
| `locals` | object | State local to this specific template |
| `subprocess` | object | Run shell commands (avoid in hot paths) |

## `module.rand` functions

```
module.rand.choice(items)                          → random item from sequence
module.rand.choices(items, n)                      → n random items
module.rand.weighted_choice(items, weights)         → weighted random (two separate lists)
module.rand.weighted_choices(items, weights, n)     → n weighted random items
module.rand.chance(probability)                     → True with given probability (0.0-1.0)

module.rand.number.integer(a, b)                   → random int in [a, b]
module.rand.number.floating(a, b)                  → random float in [a, b]

module.rand.string.hex(size)                       → random hex string
module.rand.string.digits(size)                    → random digit string
module.rand.string.letters(size)                   → random letter string

module.rand.network.ip_v4()                        → random IPv4
module.rand.network.ip_v4_private_a/b/c()          → random private IPv4
module.rand.network.ip_v4_public()                 → random public IPv4

module.rand.crypto.uuid4()                         → random UUID v4
```

## Faker and Mimesis modules

For generating realistic contextual data beyond what `module.rand.*` offers:

```
module.faker.locale.en_US.name()              → realistic full name
module.faker.locale.en_US.ipv4()              → random IPv4
module.faker.locale.en_US.user_agent()        → browser User-Agent string
module.faker.locale.en_US.uri_path()          → random URI path
module.faker.locale.en_US.file_path()         → random file path
module.faker.locale.en_US.sentence()          → random sentence
module.faker.locale.<locale>.*                → any Faker provider in any locale

module.mimesis.locale.en.person.full_name()   → realistic name
module.mimesis.locale.en.internet.ip_v4()     → random IPv4
module.mimesis.locale.en.internet.url()       → random URL
module.mimesis.locale.en.file.file_name()     → random filename
module.mimesis.locale.<locale>.*              → any Mimesis provider in any locale
```

Use `module.faker.*` / `module.mimesis.*` when you need realistic contextual data (names, emails, user agents, URLs, file paths, sentences). Prefer `module.rand.*` on hot paths for performance — Faker/Mimesis are slower but produce more natural-looking data.

## Other modules

Any installed Python package is accessible via `module.<package>.*`. Examples:

```
module.json.dumps(data)                        → serialize to JSON string
module.json.loads(string)                      → parse JSON string
module.math.ceil(value)                        → ceiling
module.math.log(value)                         → natural log
module.hashlib.md5(b'data').hexdigest()        → MD5 hash
module.base64.b64encode(b'data').decode()      → Base64 encode
module.datetime.datetime.now()                 → current datetime
module.ipaddress.ip_network('10.0.0.0/8')     → IP network object
module.urllib.parse.quote(string)              → URL-encode a string
```

This means you can use any Python stdlib or third-party package installed in the Eventum environment — just prefix with `module.`.

## `shared` / `locals` / `globals` state

```
shared.get('key', default)    → get value or default
shared.set('key', value)      → set value
shared.delete('key')          → delete key
```

## Samples access

- CSV with `header: true`: `(samples.<name> | random).column_name`
- JSON array: `samples.<name> | random` → dict entry
- `| tojson` to serialize for JSON output

## Jinja2 essentials

- `{%- ... -%}` — whitespace-stripping tags (use on setup logic to keep output clean)
- `{% do list.append(item) %}` — mutate lists in-place
- `{{ value | tojson }}`, `{{ value | upper }}`, `{{ list | length }}`, `{{ list | random }}`
