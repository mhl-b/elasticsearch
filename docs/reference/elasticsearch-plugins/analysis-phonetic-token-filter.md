---
mapped_pages:
  - https://www.elastic.co/guide/en/elasticsearch/plugins/current/analysis-phonetic-token-filter.html
---

# phonetic token filter [analysis-phonetic-token-filter]

The `phonetic` token filter takes the following settings:

`encoder`
:   Which phonetic encoder to use. Accepts `metaphone` (default), `double_metaphone`, `soundex`, `refined_soundex`, `caverphone1`, `caverphone2`, `cologne`, `nysiis`, `koelnerphonetik`, `haasephonetik`, `beider_morse`, `daitch_mokotoff`.

`replace`
:   Whether or not the original token should be replaced by the phonetic token. Accepts `true` (default) and `false`. Not supported by `beider_morse` encoding.

```console
PUT phonetic_sample
{
  "settings": {
    "index": {
      "analysis": {
        "analyzer": {
          "my_analyzer": {
            "tokenizer": "standard",
            "filter": [
              "lowercase",
              "my_metaphone"
            ]
          }
        },
        "filter": {
          "my_metaphone": {
            "type": "phonetic",
            "encoder": "metaphone",
            "replace": false
          }
        }
      }
    }
  }
}

GET phonetic_sample/_analyze
{
  "analyzer": "my_analyzer",
  "text": "Joe Bloggs" <1>
}
```

1. Returns: `J`, `joe`, `BLKS`, `bloggs`


It is important to note that `"replace": false` can lead to unexpected behavior since the original and the phonetically analyzed version are both kept at the same token position. Some queries handle these stacked tokens in special ways. For example, the fuzzy `match` query does not apply [fuzziness](/reference/elasticsearch/rest-apis/common-options.md#fuzziness) to stacked synonym tokens. This can lead to issues that are difficult to diagnose and reason about. For this reason, it is often beneficial to use separate fields for analysis with and without phonetic filtering. That way searches can be run against both fields with differing boosts and trade-offs (e.g. only run a fuzzy `match` query on the original text field, but not on the phonetic version).


## Double metaphone settings [_double_metaphone_settings]

If the `double_metaphone` encoder is used, then this additional setting is supported:

`max_code_len`
:   The maximum length of the emitted metaphone token. Defaults to `4`.


## Beider Morse settings [_beider_morse_settings]

If the `beider_morse` encoder is used, then these additional settings are supported:

`rule_type`
:   Whether matching should be `exact` or `approx` (default).

`name_type`
:   Whether names are `ashkenazi`, `sephardic`, or `generic` (default).

`languageset`
:   An array of languages to check. If not specified, then the language will be guessed. Accepts: `any`, `common`, `cyrillic`, `english`, `french`, `german`, `hebrew`, `hungarian`, `polish`, `romanian`, `russian`, `spanish`.

