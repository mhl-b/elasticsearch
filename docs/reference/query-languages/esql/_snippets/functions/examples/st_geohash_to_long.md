% This is generated by ESQL's AbstractFunctionTestCase. Do not edit it. See ../README.md for how to regenerate it.

**Example**

```esql
ROW geohash = "u3bu"
| EVAL geohashLong = ST_GEOHASH_TO_LONG(geohash)
```

| geohash:keyword | geohashLong:long |
| --- | --- |
| u3bu | 13686180 |


